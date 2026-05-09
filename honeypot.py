"""
honeypot.py — Delilah Honeypot
Fake Elasticsearch / Kibana surface that logs, classifies, and blocks attackers.

DevSecOps additions
-------------------
* IP blocklist integration (auto-block after threshold, persist to DB)
* Per-IP rate limiting enforced before any handler logic
* Prometheus /metrics endpoint (request counters, event-type histogram, blocked count)
* Structured JSON log lines alongside human-readable output
* Request fingerprinting — stores a SHA-256 of headers for attacker correlation
* X-Forwarded-For / X-Real-IP awareness (proxy-aware IP extraction)
* Graceful shutdown (SIGTERM → drain pool)
"""

import asyncio
import datetime
import hashlib
import json
import logging
import os
import signal
import time
from collections import defaultdict

import aiosmtplib
import asyncpg
import tornado.httpclient
import tornado.httpserver
import tornado.ioloop
import tornado.web
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import blocklist as bl

# ── Environment ──────────────────────────────────────────────────────────────
load_dotenv()

SMTP_SERVER     = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT       = int(os.getenv("SMTP_PORT", 587))
EMAIL           = os.getenv("ALERT_EMAIL")
PASSWORD        = os.getenv("ALERT_PASSWORD")
RECIPIENT       = os.getenv("ALERT_RECIPIENT")
ALERT_COOLDOWN  = int(os.getenv("ALERT_COOLDOWN_SECONDS", 600))
HONEYPOT_PORT   = int(os.getenv("PORT", 9200))
LOG_LEVEL       = os.getenv("LOG_LEVEL", "INFO")
DATABASE_URL    = os.getenv("DATABASE_URL", "postgresql://delilah:delilah@localhost:5432/honeypot")
TRUSTED_PROXIES = set(os.getenv("TRUSTED_PROXIES", "").split(",")) - {""}

# ── Logging (human + JSON) ────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({
            "ts":    self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "name":  record.name,
            "msg":   record.getMessage(),
        })

_json_h = logging.FileHandler("logs/honeypot.jsonl", mode="a")
_json_h.setFormatter(_JsonFormatter())

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/honeypot.log", mode="a"),
        _json_h,
    ],
)
logger = logging.getLogger(__name__)

# ── Global state ──────────────────────────────────────────────────────────────
_alert_last_sent: dict[str, float] = {}
GEO_CACHE: dict[str, tuple]        = {}
GEO_CACHE_TTL                      = 3600
db_pool: asyncpg.Pool | None       = None

# ── Prometheus counters ───────────────────────────────────────────────────────
_prom: dict = {
    "requests_total":    defaultdict(int),
    "blocked_requests":  0,
    "credentials_total": 0,
    "alerts_sent":       0,
    "db_errors":         0,
}

def _prom_inc(key: str, label: str | None = None) -> None:
    if label is not None:
        _prom[key][label] += 1
    else:
        _prom[key] += 1


# ── DB init ───────────────────────────────────────────────────────────────────

async def init_db() -> None:
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    async with db_pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id              BIGSERIAL PRIMARY KEY,
                timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                source_ip       TEXT,
                event_type      TEXT,
                request_uri     TEXT,
                method          TEXT DEFAULT 'GET',
                post_body       TEXT,
                user_agent      TEXT,
                req_fingerprint TEXT,
                country         TEXT,
                region          TEXT,
                city            TEXT,
                isp             TEXT,
                org             TEXT,
                lat             DOUBLE PRECISION,
                lon             DOUBLE PRECISION
            )
        """)
        await conn.execute(
            "ALTER TABLE events ADD COLUMN IF NOT EXISTS req_fingerprint TEXT"
        )
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS harvested_credentials (
                id          BIGSERIAL PRIMARY KEY,
                timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                source_ip   TEXT,
                username    TEXT,
                password    TEXT,
                endpoint    TEXT,
                user_agent  TEXT,
                country     TEXT,
                city        TEXT
            )
        """)
        for ddl in [
            "CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_events_ip      ON events(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_events_type    ON events(event_type)",
            "CREATE INDEX IF NOT EXISTS idx_events_country ON events(country)",
            "CREATE INDEX IF NOT EXISTS idx_events_fp      ON events(req_fingerprint)",
            "CREATE INDEX IF NOT EXISTS idx_cred_ts        ON harvested_credentials(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_cred_ip        ON harvested_credentials(source_ip)",
        ]:
            await conn.execute(ddl)
    await bl.init_blocklist(db_pool)
    logger.info("✅ PostgreSQL pool ready")


# ── IP resolution (proxy-aware) ───────────────────────────────────────────────

def resolve_ip(request) -> str:
    peer = request.remote_ip or "0.0.0.0"
    if peer in TRUSTED_PROXIES:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        real = request.headers.get("X-Real-IP", "")
        if real:
            return real.strip()
    return peer


# ── Request fingerprinting ─────────────────────────────────────────────────────

def fingerprint(request) -> str:
    parts = [
        request.headers.get("User-Agent", ""),
        request.headers.get("Accept", ""),
        request.headers.get("Accept-Encoding", ""),
        request.headers.get("Accept-Language", ""),
        request.headers.get("Connection", ""),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


# ── Geo ────────────────────────────────────────────────────────────────────────

async def geolocate_ip(ip: str) -> dict | None:
    if ip in GEO_CACHE:
        data, ts = GEO_CACHE[ip]
        if (datetime.datetime.now() - ts).seconds < GEO_CACHE_TTL:
            return data
    try:
        client = tornado.httpclient.AsyncHTTPClient()
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,regionName,city,lat,lon,isp,org"
        )
        resp = await client.fetch(
            url, raise_error=False, connect_timeout=3.0, request_timeout=5.0
        )
        d = json.loads(resp.body)
        if d.get("status") == "success":
            result = {
                "country": d.get("country"),
                "region":  d.get("regionName"),
                "city":    d.get("city"),
                "isp":     d.get("isp"),
                "org":     d.get("org"),
                "lat":     d.get("lat"),
                "lon":     d.get("lon"),
            }
            GEO_CACHE[ip] = (result, datetime.datetime.now())
            return result
    except Exception as e:
        logger.warning(f"[GEO FAILED] {ip}: {e}")
    return None


# ── Alert throttle ─────────────────────────────────────────────────────────────

def should_send_alert(ip: str) -> bool:
    now = time.time()
    if now - _alert_last_sent.get(ip, 0) >= ALERT_COOLDOWN:
        _alert_last_sent[ip] = now
        return True
    return False


# ── Event logging ──────────────────────────────────────────────────────────────

async def log_event(
    source_ip: str, event_type: str, request_uri: str, user_agent: str,
    method: str = "GET", post_body: str | None = None,
    req_fingerprint: str | None = None,
) -> dict | None:
    geo = await geolocate_ip(source_ip)
    try:
        async with db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO events
                (source_ip, event_type, request_uri, method, post_body,
                 user_agent, req_fingerprint,
                 country, region, city, isp, org, lat, lon)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
            """,
                source_ip, event_type, request_uri, method, post_body,
                user_agent, req_fingerprint,
                geo.get("country") if geo else None,
                geo.get("region")  if geo else None,
                geo.get("city")    if geo else None,
                geo.get("isp")     if geo else None,
                geo.get("org")     if geo else None,
                geo.get("lat")     if geo else None,
                geo.get("lon")     if geo else None,
            )
    except Exception as e:
        _prom_inc("db_errors")
        logger.error(f"[DB] log_event failed: {e}")

    _prom_inc("requests_total", event_type)
    logger.debug(f"[EVENT] {event_type} from {source_ip} | {request_uri}")
    return geo


# ── Attack summary ─────────────────────────────────────────────────────────────

async def get_attack_summary() -> dict:
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT
                COUNT(*)                              AS total_attacks,
                STRING_AGG(DISTINCT event_type, ', ') AS attack_types,
                COUNT(*) / 24.0                       AS attack_frequency
            FROM events
            WHERE timestamp > NOW() - INTERVAL '24 hours'
              AND event_type LIKE '%Attack%'
        """)
        recent = await conn.fetch("""
            SELECT timestamp, source_ip, event_type FROM events
            WHERE event_type LIKE '%Attack%'
            ORDER BY timestamp DESC LIMIT 5
        """)
    recent_str = "\n".join(
        f"{r['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} | {r['source_ip']} | {r['event_type']}"
        for r in recent
    ) or "No attacks yet"
    return {
        "total_attacks":    row["total_attacks"] or 0,
        "attack_types":     (row["attack_types"] or "").split(", "),
        "attack_frequency": round(float(row["attack_frequency"] or 0), 1),
        "recent_attacks":   recent_str,
    }


# ── Email alert ────────────────────────────────────────────────────────────────

async def send_alert(
    source_ip: str, request_uri: str, user_agent: str, geo: dict | None,
    method: str = "GET", post_body: str | None = None,
) -> None:
    if not EMAIL or not PASSWORD:
        logger.warning("[ALERT] Email credentials not configured")
        return
    summary = await get_attack_summary()
    geo_str = ""
    if geo:
        geo_str = (
            f"\nLocation: {geo.get('city','')}, {geo.get('region','')}, "
            f"{geo.get('country','')}\nISP: {geo.get('isp','Unknown')}"
        )
    body = f"""
⚠️  NEW ATTACK DETECTED
--------------------------
Source IP:   {source_ip}{geo_str}
Method:      {method}
Time:        {datetime.datetime.utcnow().isoformat()}Z
Target URI:  {request_uri}
User Agent:  {user_agent}
{("POST Body:   " + str(post_body)) if post_body else ""}

📊 ATTACK SUMMARY (Last 24h)
--------------------------
Total Attacks:     {summary['total_attacks']}
Attack Types:      {', '.join(summary['attack_types'])}
Attack Frequency:  {summary['attack_frequency']}/hour
Recent Attacks:
{summary['recent_attacks']}
"""
    msg = MIMEMultipart("alternative")
    msg["From"]    = EMAIL
    msg["To"]      = RECIPIENT
    msg["Subject"] = f"🚨 Honeypot Alert: Attack from {source_ip}"
    msg.attach(MIMEText(body, "plain"))
    try:
        await aiosmtplib.send(
            msg,
            hostname=SMTP_SERVER,
            port=SMTP_PORT,
            username=EMAIL,
            password=PASSWORD,
            start_tls=True,
        )
        _prom_inc("alerts_sent")
        logger.info(f"📧 Alert sent for {source_ip}")
    except Exception as e:
        logger.error(f"❌ Email alert failed: {e}")


# ── Attack classifier ──────────────────────────────────────────────────────────

def classify_attack(uri: str, user_agent: str, post_body: str = "") -> str:
    payload = (uri + " " + post_body).lower()
    ua = user_agent.lower()

    if any(s in ua for s in [
        "shodan", "masscan", "nmap", "zgrab", "censys", "python-requests",
        "go-http-client", "curl/", "libwww-perl", "nikto", "sqlmap",
        "dirbuster", "nuclei", "metasploit",
    ]):
        return "Automated Scanner Detected"

    if any(p in payload for p in [
        "${jndi:", "${${lower:j}ndi:", "jndi:ldap", "jndi:rmi",
        "() {", "() { :;};", "class.module.classloader",
        "heartbeat", "eval-stdin.php", "thinkphp", "%{#context",
    ]):
        return "CVE Exploit Probe"

    if any(p in payload for p in [
        "' or '", "' or 1=1", "union select", "drop table",
        "insert into", "delete from", "'; --", "%27",
        "information_schema", "sleep(", "benchmark(",
        "xp_cmdshell", "or 1=1", "' and '",
    ]):
        return "SQL Injection Attempt"

    if any(p in payload for p in [
        "<script", "javascript:", "onerror=", "onload=", "alert(",
        "document.cookie", "eval(", "<img src=", "svg/onload", "%3cscript",
    ]):
        return "XSS Attempt"

    if any(p in payload for p in [
        "../", "..\\", "%2e%2e%2f", "/etc/passwd", "/etc/shadow",
        "boot.ini", "win.ini", "/windows/system32", "../../../../",
    ]):
        return "Path Traversal / LFI Attempt"

    if any(c in payload for c in [
        "wget", "curl", "bash", " sh ", "nc", "chmod",
        ";ls", ";id", ";whoami", "|id", "|whoami",
        "&&id", "&&cat /etc", "cmd.exe", "powershell",
    ]):
        return "Command Injection Attempt"

    if any(p in uri for p in [
        "/_search", "/_cat", "/_cluster", "/_nodes",
        "/_bulk", "/_stats", "/_mapping", "/_aliases", "/_template",
    ]):
        return "Reconnaissance Attack"

    if any(p in payload for p in [
        "/admin", "/administrator", "/wp-admin", "/wp-login",
        "/phpmyadmin", "/manager/html", "/console", "/login",
        "/.env", "/config", "/.git", "/actuator",
    ]):
        return "Admin Panel Probe"

    return "Suspicious Request"


# ── Prometheus metrics ─────────────────────────────────────────────────────────

async def _render_metrics() -> str:
    blocked_now = 0
    try:
        async with db_pool.acquire() as conn:
            blocked_now = await conn.fetchval(
                "SELECT COUNT(*) FROM blocked_ips WHERE expires_at IS NULL OR expires_at > NOW()"
            )
    except Exception:
        pass

    lines = [
        "# HELP delilah_requests_total Events logged by type",
        "# TYPE delilah_requests_total counter",
    ]
    for label, count in _prom["requests_total"].items():
        safe = label.replace(" ", "_").replace("/", "_").lower()
        lines.append(f'delilah_requests_total{{event_type="{safe}"}} {count}')

    lines += [
        "",
        "# HELP delilah_blocked_requests_total Requests rejected by blocklist",
        "# TYPE delilah_blocked_requests_total counter",
        f"delilah_blocked_requests_total {_prom['blocked_requests']}",
        "",
        "# HELP delilah_credentials_total Credentials harvested from fake login",
        "# TYPE delilah_credentials_total counter",
        f"delilah_credentials_total {_prom['credentials_total']}",
        "",
        "# HELP delilah_alerts_sent_total Email alerts dispatched",
        "# TYPE delilah_alerts_sent_total counter",
        f"delilah_alerts_sent_total {_prom['alerts_sent']}",
        "",
        "# HELP delilah_db_errors_total Database write errors",
        "# TYPE delilah_db_errors_total counter",
        f"delilah_db_errors_total {_prom['db_errors']}",
        "",
        "# HELP delilah_blocked_ips_active Currently active IP blocks",
        "# TYPE delilah_blocked_ips_active gauge",
        f"delilah_blocked_ips_active {blocked_now}",
    ]
    return "\n".join(lines) + "\n"


# ── Handlers ───────────────────────────────────────────────────────────────────

class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self) -> None:
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "*")
        self.set_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.set_header("X-elastic-product", "Elasticsearch")  # deceive scanners

    async def handle_request(self) -> str | None:
        ip     = resolve_ip(self.request)
        uri    = self.request.uri
        ua     = self.request.headers.get("User-Agent", "Unknown")
        method = self.request.method
        fp     = fingerprint(self.request)

        if bl.is_blocked(ip):
            _prom_inc("blocked_requests")
            self.set_status(403)
            self.write(json.dumps({"error": "Forbidden"}))
            return None

        post_body: str | None = None
        if method == "POST":
            try:
                post_body = self.request.body.decode("utf-8", errors="replace")[:2000]
            except Exception:
                post_body = "<binary>"

        event = classify_attack(uri, ua, post_body or "")
        tornado.ioloop.IOLoop.current().add_callback(
            bl.maybe_auto_block, db_pool, ip, event
        )
        geo = await log_event(ip, event, uri, ua, method, post_body, fp)
        if should_send_alert(ip):
            tornado.ioloop.IOLoop.current().add_callback(
                send_alert, ip, uri, ua, geo, method, post_body
            )
        return event

    async def get(self) -> None:
        raise NotImplementedError

    async def post(self) -> None:
        raise NotImplementedError


class AttackHandler(BaseHandler):
    async def get(self) -> None:
        event = await self.handle_request()
        if event is None:
            return
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"status": "ok", "type": event}))

    async def post(self) -> None:
        await self.get()


class FakeElasticsearchHandler(BaseHandler):
    async def get(self) -> None:
        ip  = resolve_ip(self.request)
        uri = self.request.uri
        ua  = self.request.headers.get("User-Agent", "Unknown")
        fp  = fingerprint(self.request)

        if bl.is_blocked(ip):
            _prom_inc("blocked_requests")
            self.set_status(403)
            self.write(json.dumps({"error": "Forbidden"}))
            return

        event = classify_attack(uri, ua)
        if event == "Suspicious Request":
            event = "Recon"

        tornado.ioloop.IOLoop.current().add_callback(
            bl.maybe_auto_block, db_pool, ip, event
        )
        geo = await log_event(ip, event, uri, ua, "GET", req_fingerprint=fp)
        if should_send_alert(ip):
            tornado.ioloop.IOLoop.current().add_callback(send_alert, ip, uri, ua, geo)

        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({
            "name":         "elastic-prod-node-1",
            "cluster_name": "production-es-cluster",
            "cluster_uuid": "kJ8d9slPQr2xYz",
            "version": {
                "number":       "7.10.0",
                "build_flavor": "default",
                "build_type":   "docker",
            },
            "tagline": "You Know, for Search",
        }))

    async def post(self) -> None:
        await self.get()


class FakeLoginHandler(tornado.web.RequestHandler):
    def set_default_headers(self) -> None:
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "*")
        self.set_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")

    def get(self) -> None:
        ip = resolve_ip(self.request)
        ua = self.request.headers.get("User-Agent", "Unknown")
        fp = fingerprint(self.request)
        if bl.is_blocked(ip):
            _prom_inc("blocked_requests")
            self.set_status(403)
            self.finish()
            return
        tornado.ioloop.IOLoop.current().add_callback(
            log_event, ip, "Admin Panel Probe", self.request.uri, ua, "GET", None, fp,
        )
        self.set_header("Content-Type", "text/html")
        self.write(FAKE_LOGIN_HTML)

    async def post(self) -> None:
        ip = resolve_ip(self.request)
        ua = self.request.headers.get("User-Agent", "Unknown")
        fp = fingerprint(self.request)

        if bl.is_blocked(ip):
            _prom_inc("blocked_requests")
            self.set_status(403)
            self.finish()
            return

        username = (
            self.get_body_argument("username", None)
            or self.get_body_argument("user", None)
            or self.get_body_argument("email", None)
            or "<not provided>"
        )
        password = (
            self.get_body_argument("password", None)
            or self.get_body_argument("pass", None)
            or self.get_body_argument("passwd", None)
            or "<not provided>"
        )

        geo = await geolocate_ip(ip)
        try:
            async with db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO harvested_credentials
                    (source_ip, username, password, endpoint, user_agent, country, city)
                    VALUES ($1,$2,$3,$4,$5,$6,$7)
                """, ip, username, password, self.request.uri, ua,
                    geo.get("country") if geo else None,
                    geo.get("city")    if geo else None,
                )
            _prom_inc("credentials_total")
        except Exception as e:
            _prom_inc("db_errors")
            logger.error(f"[DB] credential insert failed: {e}")

        await log_event(
            ip, "Credential Submission", self.request.uri, ua, "POST",
            f"user={username}", fp,
        )
        tornado.ioloop.IOLoop.current().add_callback(
            bl.maybe_auto_block, db_pool, ip, "Credential Submission"
        )
        logger.info(f"🔑 Credentials harvested: {username} / {'*' * len(password)} from {ip}")
        if should_send_alert(ip):
            tornado.ioloop.IOLoop.current().add_callback(
                send_alert, ip, self.request.uri, ua, geo, "POST",
                f"username={username}&password={password}",
            )
        self.set_header("Content-Type", "text/html")
        self.write(FAKE_LOGIN_HTML.replace(
            "<!--ERROR-->",
            '<div style="color:#ff4136;margin-bottom:12px;">Invalid username or password.</div>',
        ))


FAKE_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Kibana — Log in</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #1a1a2e; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #16213e; border: 1px solid #0f3460; border-radius: 8px;
            padding: 40px 36px; width: 360px; box-shadow: 0 8px 32px rgba(0,0,0,0.5); }
    .logo { text-align: center; margin-bottom: 28px; }
    .logo svg { width: 48px; height: 48px; }
    .logo h1 { color: #00b5d8; font-size: 22px; margin-top: 10px; letter-spacing: 1px; }
    label { display: block; color: #a0aec0; font-size: 12px; margin-bottom: 6px;
            text-transform: uppercase; letter-spacing: 1px; }
    input { width: 100%; background: #0f3460; border: 1px solid #2d4a7a; color: #e2e8f0;
            padding: 10px 14px; border-radius: 4px; font-size: 14px; margin-bottom: 18px; outline: none; }
    input:focus { border-color: #00b5d8; }
    button { width: 100%; background: #00b5d8; color: #fff; border: none;
             padding: 12px; border-radius: 4px; font-size: 15px; font-weight: 600;
             cursor: pointer; letter-spacing: 0.5px; }
    button:hover { background: #0097b5; }
    .footer { text-align: center; color: #4a5568; font-size: 11px; margin-top: 24px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="16" cy="16" r="15" stroke="#00b5d8" stroke-width="2"/>
        <path d="M8 16 Q16 8 24 16 Q16 24 8 16Z" fill="#00b5d8" opacity="0.6"/>
      </svg>
      <h1>Kibana</h1>
    </div>
    <!--ERROR-->
    <form method="POST">
      <label>Username</label>
      <input type="text" name="username" placeholder="elastic" autocomplete="off"/>
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••"/>
      <button type="submit">Log in</button>
    </form>
    <div class="footer">Elastic Stack 7.10.0 &nbsp;·&nbsp; Kibana</div>
  </div>
</body>
</html>"""


class MetricsHandler(tornado.web.RequestHandler):
    """Prometheus /metrics scrape endpoint."""
    async def get(self) -> None:
        self.set_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.write(await _render_metrics())


class HealthHandler(tornado.web.RequestHandler):
    async def get(self) -> None:
        try:
            async with db_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            self.write({
                "status":  "ok",
                "service": "honeypot",
                "db":      "connected",
                "blocked": len(bl._blocked),
            })
        except Exception as e:
            self.set_status(503)
            self.write({"status": "degraded", "db": str(e)})


def make_app() -> tornado.web.Application:
    return tornado.web.Application([
        (r"/health",          HealthHandler),
        (r"/metrics",         MetricsHandler),
        (r"/",                FakeElasticsearchHandler),
        (r"/_cat/indices",    FakeElasticsearchHandler),
        (r"/_cluster/health", FakeElasticsearchHandler),
        (r"/_nodes",          FakeElasticsearchHandler),
        (r"/_mapping",        FakeElasticsearchHandler),
        (r"/_search",         AttackHandler),
        (r"/login",           FakeLoginHandler),
        (r"/kibana",          FakeLoginHandler),
        (r"/kibana/login",    FakeLoginHandler),
        (r"/app/kibana",      FakeLoginHandler),
        (r"/.*",              AttackHandler),
    ])


# ── Graceful shutdown ──────────────────────────────────────────────────────────

async def _shutdown(server: tornado.httpserver.HTTPServer) -> None:
    logger.info("🛑 Shutting down honeypot…")
    server.stop()
    await asyncio.sleep(1)
    if db_pool:
        await db_pool.close()
    asyncio.get_event_loop().stop()


async def main() -> None:
    await init_db()
    app    = make_app()
    server = tornado.httpserver.HTTPServer(app)
    server.listen(HONEYPOT_PORT)

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(_shutdown(server)))

    asyncio.create_task(bl.start_expiry_loop(db_pool))

    logger.info(f"🍯 Delilah Honeypot on :{HONEYPOT_PORT}")
    logger.info(f"🚫 Block threshold: {bl.BLOCK_THRESHOLD} hits/{bl.BLOCK_WINDOW}s")
    logger.info(f"📈 Prometheus metrics at /metrics")
    logger.info(f"⚠️  Email alerts: {'enabled' if EMAIL else 'disabled'}")

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())