import asyncio
import csv
import io
import json
import logging
import os

import asyncpg
import tornado.ioloop
import tornado.web
from dotenv import load_dotenv

load_dotenv()

MONITOR_PORT = int(os.getenv("PORT", 8080))
LOG_LEVEL    = os.getenv("LOG_LEVEL", "INFO")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://delilah:delilah@localhost:5432/honeypot")

# ===== Logging =====
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/monitor.log", mode="a"),
    ],
)
logger = logging.getLogger(__name__)

db_pool: asyncpg.Pool | None = None


async def init_db():
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    logger.info("✅ Monitor connected to PostgreSQL")


# ───────────────────────────────────────────
#  CSV Export
# ───────────────────────────────────────────

class ExportHandler(tornado.web.RequestHandler):
    async def get(self):
        async with db_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, timestamp, source_ip, event_type, method,
                       request_uri, user_agent, country, region, city, isp
                FROM events ORDER BY timestamp DESC LIMIT 1000
            """)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID","Timestamp","Source IP","Event Type","Method",
                         "URI","User Agent","Country","Region","City","ISP"])
        for r in rows:
            writer.writerow([
                r["id"],
                r["timestamp"].isoformat() if r["timestamp"] else "",
                r["source_ip"], r["event_type"], r["method"],
                r["request_uri"], r["user_agent"],
                r["country"], r["region"], r["city"], r["isp"],
            ])
        self.set_header("Content-Type", "text/csv")
        self.set_header("Content-Disposition", "attachment; filename=honeypot_events.csv")
        self.write(output.getvalue())
        logger.info(f"📥 CSV export: {len(rows)} events")


# ───────────────────────────────────────────
#  Live Stats API
# ───────────────────────────────────────────

class StatsHandler(tornado.web.RequestHandler):
    async def get(self):
        try:
            async with db_pool.acquire() as conn:
                total_events  = await conn.fetchval("SELECT COUNT(*) FROM events")
                total_attacks = await conn.fetchval(
                    "SELECT COUNT(*) FROM events WHERE event_type LIKE '%Attack%'"
                )
                top_ip_row = await conn.fetchrow(
                    "SELECT source_ip, COUNT(*) c FROM events GROUP BY source_ip ORDER BY c DESC LIMIT 1"
                )
                top_ep_row = await conn.fetchrow(
                    "SELECT request_uri, COUNT(*) c FROM events GROUP BY request_uri ORDER BY c DESC LIMIT 1"
                )
                cred_count = await conn.fetchval("SELECT COUNT(*) FROM harvested_credentials")

                hourly = await conn.fetch("""
                    SELECT TO_CHAR(timestamp AT TIME ZONE 'UTC', 'HH24') AS hour,
                           COUNT(*) AS count
                    FROM events
                    WHERE timestamp > NOW() - INTERVAL '24 hours'
                    GROUP BY hour ORDER BY hour
                """)
                types = await conn.fetch("""
                    SELECT event_type, COUNT(*) AS count
                    FROM events GROUP BY event_type ORDER BY count DESC LIMIT 8
                """)
                timeline = await conn.fetch("""
                    SELECT TO_CHAR(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS day,
                           COUNT(*) AS count
                    FROM events
                    WHERE timestamp > NOW() - INTERVAL '7 days'
                    GROUP BY day ORDER BY day
                """)
                countries = await conn.fetch("""
                    SELECT country, COUNT(*) AS count
                    FROM events WHERE country IS NOT NULL
                    GROUP BY country ORDER BY count DESC LIMIT 10
                """)
                geo_points = await conn.fetch("""
                    SELECT lat, lon, source_ip, event_type, country
                    FROM events WHERE lat IS NOT NULL AND lon IS NOT NULL
                """)

            self.set_header("Content-Type", "application/json")
            self.write(json.dumps({
                "total_events":  total_events,
                "total_attacks": total_attacks,
                "top_ip":        top_ip_row["source_ip"] if top_ip_row else "N/A",
                "top_endpoint":  top_ep_row["request_uri"] if top_ep_row else "N/A",
                "cred_count":    cred_count,
                "hourly":        [{"hour": r["hour"], "count": r["count"]} for r in hourly],
                "types":         [{"type": r["event_type"], "count": r["count"]} for r in types],
                "timeline":      [{"day": r["day"], "count": r["count"]} for r in timeline],
                "countries":     [{"country": r["country"], "count": r["count"]} for r in countries],
                "geo_points":    [
                    {"lat": r["lat"], "lon": r["lon"], "ip": r["source_ip"],
                     "type": r["event_type"], "country": r["country"]}
                    for r in geo_points
                ],
            }))
        except Exception as e:
            logger.error(f"Stats query failed: {e}")
            self.set_status(500)
            self.write({"error": str(e)})


# ───────────────────────────────────────────
#  Dashboard
# ───────────────────────────────────────────

class DashboardHandler(tornado.web.RequestHandler):
    async def get(self):
        try:
            async with db_pool.acquire() as conn:
                logs = await conn.fetch("""
                    SELECT id, timestamp, source_ip, event_type, method,
                           request_uri, user_agent, country, region, city, isp
                    FROM events ORDER BY timestamp DESC LIMIT 1000
                """)
                total_events  = await conn.fetchval("SELECT COUNT(*) FROM events")
                total_attacks = await conn.fetchval(
                    "SELECT COUNT(*) FROM events WHERE event_type LIKE '%Attack%'"
                )
                top_ip_row = await conn.fetchrow(
                    "SELECT source_ip FROM events GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 1"
                )
                top_ep_row = await conn.fetchrow(
                    "SELECT request_uri FROM events GROUP BY request_uri ORDER BY COUNT(*) DESC LIMIT 1"
                )
                cred_count = await conn.fetchval("SELECT COUNT(*) FROM harvested_credentials")
                creds = await conn.fetch("""
                    SELECT id, timestamp, source_ip, username, password, endpoint, country, city
                    FROM harvested_credentials ORDER BY timestamp DESC LIMIT 200
                """)

            top_ip       = top_ip_row["source_ip"] if top_ip_row else "N/A"
            top_endpoint = top_ep_row["request_uri"] if top_ep_row else "N/A"

            # ── Build credential rows ──
            cred_rows_html = ""
            if creds:
                for c in creds:
                    ts = c["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if c["timestamp"] else ""
                    cred_rows_html += f"""
                    <tr class="log-row">
                      <td><span class="id-badge">#{c['id']}</span></td>
                      <td><span class="ts">{ts}</span></td>
                      <td><span class="ip-chip">{c['source_ip']}</span></td>
                      <td><span class="cred-val">{c['username']}</span></td>
                      <td><span class="cred-val pwd">{c['password']}</span></td>
                      <td><code class="uri-code">{c['endpoint']}</code></td>
                      <td><span class="loc-text">📍 {c['city'] or '?'}, {c['country'] or '?'}</span></td>
                    </tr>"""
            else:
                cred_rows_html = '<tr><td colspan="7" style="color:var(--muted);padding:20px;text-align:center">No credentials harvested yet</td></tr>'

            # ── Build event rows ──
            event_color_map = {
                "Command Injection Attempt":    ("#ff4757", "💉"),
                "Reconnaissance Attack":        ("#ffa502", "🔍"),
                "Suspicious Request":           ("#1e90ff", "⚠️"),
                "Recon":                        ("#eccc68", "👁"),
                "SQL Injection Attempt":        ("#ff6b81", "🗄️"),
                "XSS Attempt":                  ("#ff6348", "📜"),
                "Path Traversal / LFI Attempt": ("#ff4757", "📂"),
                "CVE Exploit Probe":            ("#e84393", "💣"),
                "Admin Panel Probe":            ("#a29bfe", "🔑"),
                "Automated Scanner Detected":   ("#00d2d3", "🤖"),
                "Credential Submission":        ("#2ed573", "🔐"),
            }
            rows_html = ""
            for log in logs:
                eid      = log["id"]
                ts       = log["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if log["timestamp"] else ""
                src_ip   = log["source_ip"]
                etype    = log["event_type"]
                method   = log["method"]
                uri      = log["request_uri"] or ""
                ua       = log["user_agent"] or ""
                country  = log["country"] or "?"
                city     = log["city"] or "?"
                isp      = log["isp"] or "—"
                color, icon  = event_color_map.get(etype, ("#2ed573", "❓"))
                ua_display   = (ua[:44] + "…") if len(ua) > 44 else ua
                uri_display  = (uri[:32] + "…") if len(uri) > 32 else uri
                method_color = "#ff4757" if method == "POST" else "#4a5d78"
                rows_html += f"""
                  <tr class="log-row" data-type="{etype}" data-ip="{src_ip}" data-country="{country}">
                    <td><span class="id-badge">#{eid}</span></td>
                    <td><span class="ts">{ts}</span></td>
                    <td><span class="ip-chip">{src_ip}</span></td>
                    <td><span class="method-badge" style="color:{method_color}">{method}</span></td>
                    <td><span class="loc-text">📍 {city}, {country}</span></td>
                    <td><span class="event-badge" style="color:{color};border-color:{color}30;background:{color}12">{icon} {etype}</span></td>
                    <td><code class="uri-code">{uri_display}</code></td>
                    <td><span class="ua-text" title="{ua}">{ua_display}</span></td>
                    <td><span class="isp-text">{isp}</span></td>
                  </tr>"""

            self.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Delilah Honeypot — Monitor</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css"/>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
  <style>
    :root {{
      --bg:#06080d; --surface:#0d111a; --surface2:#121824;
      --border:#1c2537; --border2:#253044; --text:#b8cce0; --muted:#4a5d78;
      --red:#ff4757; --orange:#ffa502; --blue:#1e90ff; --cyan:#00d2d3;
      --green:#2ed573; --pink:#e84393; --purple:#a29bfe; --glow:rgba(255,71,87,0.18);
    }}
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;min-height:100vh;overflow-x:hidden}}
    body::after{{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.04) 2px,rgba(0,0,0,0.04) 4px);pointer-events:none;z-index:9999}}
    body::before{{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(255,71,87,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(255,71,87,0.03) 1px,transparent 1px);background-size:48px 48px;pointer-events:none}}
    header{{display:flex;align-items:center;justify-content:space-between;padding:0 32px;height:60px;background:rgba(6,8,13,0.97);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:200;backdrop-filter:blur(10px)}}
    .header-left{{display:flex;align-items:center;gap:14px}}
    .hex-logo{{width:34px;height:34px;background:var(--red);clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);display:flex;align-items:center;justify-content:center;font-size:15px;animation:pulse-glow 2s ease-in-out infinite}}
    @keyframes pulse-glow{{0%,100%{{box-shadow:0 0 20px var(--glow)}}50%{{box-shadow:0 0 40px rgba(255,71,87,0.4)}}}}
    .brand{{font-size:20px;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:#fff}}
    .brand span{{color:var(--red)}}
    .live-badge{{display:flex;align-items:center;gap:6px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--green);background:rgba(46,213,115,0.08);border:1px solid rgba(46,213,115,0.2);padding:4px 10px;border-radius:4px;letter-spacing:1px}}
    .live-dot{{width:7px;height:7px;background:var(--green);border-radius:50%;animation:blink 1.2s ease-in-out infinite}}
    @keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:0.2}}}}
    .header-right{{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);letter-spacing:1px;display:flex;align-items:center;gap:16px}}
    .refresh-timer{{color:var(--cyan)}}
    main{{padding:24px 32px;max-width:1900px;margin:0 auto}}
    .tab-nav{{display:flex;gap:4px;margin-bottom:22px;border-bottom:1px solid var(--border);padding-bottom:0}}
    .tab-btn{{padding:9px 20px;border:none;background:transparent;color:var(--muted);font-family:'Rajdhani',sans-serif;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase;cursor:pointer;border-bottom:2px solid transparent;transition:0.2s;margin-bottom:-1px}}
    .tab-btn.active{{color:var(--red);border-bottom-color:var(--red)}}
    .tab-btn:hover:not(.active){{color:var(--text)}}
    .tab-panel{{display:none}}.tab-panel.active{{display:block}}
    .stats-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:22px}}
    .stat-card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;position:relative;overflow:hidden;transition:border-color 0.2s,transform 0.2s}}
    .stat-card:hover{{border-color:var(--border2);transform:translateY(-2px)}}
    .stat-card::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px}}
    .stat-card.red::before{{background:linear-gradient(90deg,transparent,var(--red),transparent)}}
    .stat-card.orange::before{{background:linear-gradient(90deg,transparent,var(--orange),transparent)}}
    .stat-card.blue::before{{background:linear-gradient(90deg,transparent,var(--blue),transparent)}}
    .stat-card.cyan::before{{background:linear-gradient(90deg,transparent,var(--cyan),transparent)}}
    .stat-card.green::before{{background:linear-gradient(90deg,transparent,var(--green),transparent)}}
    .stat-label{{font-size:10px;font-weight:600;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;font-family:'IBM Plex Mono',monospace}}
    .stat-value{{font-size:32px;font-weight:700;line-height:1;color:#fff}}
    .stat-card.red .stat-value{{color:var(--red);text-shadow:0 0 30px rgba(255,71,87,0.4)}}
    .stat-card.orange .stat-value{{color:var(--orange);text-shadow:0 0 30px rgba(255,165,2,0.3)}}
    .stat-card.green .stat-value{{color:var(--green);text-shadow:0 0 20px rgba(46,213,115,0.3)}}
    .stat-sub{{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
    .stat-icon{{position:absolute;right:16px;top:50%;transform:translateY(-50%);font-size:32px;opacity:0.06}}
    .charts-grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:22px}}
    .panel{{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}}
    .panel-header{{display:flex;align-items:center;justify-content:space-between;padding:11px 18px;border-bottom:1px solid var(--border);background:var(--surface2)}}
    .panel-title{{font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--text);display:flex;align-items:center;gap:8px}}
    .panel-title::before{{content:'';display:inline-block;width:3px;height:14px;background:var(--red);border-radius:2px}}
    .panel-body{{padding:16px}}
    #attackMap{{height:300px}}
    .leaflet-tile-pane{{filter:invert(1) hue-rotate(180deg) brightness(0.85) contrast(1.1)}}
    .controls-bar{{display:flex;align-items:center;gap:12px;padding:12px 18px;background:var(--surface2);border-bottom:1px solid var(--border);flex-wrap:wrap}}
    .search-input{{flex:1;min-width:180px;background:var(--bg);border:1px solid var(--border2);color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:12px;padding:7px 12px;border-radius:6px;outline:none;transition:border-color 0.2s}}
    .search-input::placeholder{{color:var(--muted)}}
    .search-input:focus{{border-color:var(--red)}}
    .filter-select{{background:var(--bg);border:1px solid var(--border2);color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:11px;padding:7px 10px;border-radius:6px;outline:none;cursor:pointer}}
    .filter-select option{{background:var(--surface2)}}
    .btn{{display:flex;align-items:center;gap:6px;padding:7px 14px;border-radius:6px;border:none;cursor:pointer;font-family:'Rajdhani',sans-serif;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase;transition:0.2s}}
    .btn-export{{background:rgba(46,213,115,0.1);color:var(--green);border:1px solid rgba(46,213,115,0.25)}}
    .btn-export:hover{{background:rgba(46,213,115,0.2)}}
    .btn-clear{{background:rgba(255,71,87,0.08);color:var(--red);border:1px solid rgba(255,71,87,0.2)}}
    .btn-clear:hover{{background:rgba(255,71,87,0.15)}}
    .result-count{{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-left:auto}}
    .table-wrap{{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}}
    table{{width:100%;border-collapse:collapse}}
    thead tr{{background:var(--surface2);border-bottom:1px solid var(--border)}}
    th{{padding:10px 14px;font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);font-weight:600;text-align:left;white-space:nowrap}}
    .log-row{{border-bottom:1px solid rgba(28,37,55,0.6);transition:background 0.15s}}
    .log-row:last-child{{border-bottom:none}}
    .log-row:hover{{background:rgba(255,71,87,0.04)}}
    .log-row.hidden{{display:none}}
    td{{padding:8px 14px;vertical-align:middle}}
    .id-badge{{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted)}}
    .ts{{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);white-space:nowrap}}
    .ip-chip{{font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--cyan);background:rgba(0,210,211,0.07);padding:2px 8px;border-radius:4px;border:1px solid rgba(0,210,211,0.15);white-space:nowrap}}
    .method-badge{{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600}}
    .loc-text{{font-size:12px;color:var(--text);white-space:nowrap}}
    .event-badge{{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px;border:1px solid;white-space:nowrap}}
    .uri-code{{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--orange);background:rgba(255,165,2,0.06);padding:2px 6px;border-radius:3px}}
    .ua-text{{font-size:11px;color:var(--muted);font-family:'IBM Plex Mono',monospace}}
    .isp-text{{font-size:11px;color:var(--muted)}}
    .cred-val{{font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--green)}}
    .cred-val.pwd{{color:var(--orange)}}
    .table-footer{{padding:10px 18px;background:var(--surface2);border-top:1px solid var(--border);font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);display:flex;justify-content:space-between;align-items:center}}
    ::-webkit-scrollbar{{width:6px;height:6px}}
    ::-webkit-scrollbar-track{{background:var(--bg)}}
    ::-webkit-scrollbar-thumb{{background:var(--border2);border-radius:3px}}
    ::-webkit-scrollbar-thumb:hover{{background:var(--muted)}}
    @keyframes fadeUp{{from{{opacity:0;transform:translateY(10px)}}to{{opacity:1;transform:translateY(0)}}}}
    .stats-grid{{animation:fadeUp 0.4s ease both}}
    .tab-panel.active{{animation:fadeUp 0.35s ease both}}
  </style>
</head>
<body>

<header>
  <div class="header-left">
    <div class="hex-logo">🛡</div>
    <div class="brand">DELI<span>LAH</span></div>
    <div class="live-badge"><div class="live-dot"></div>LIVE</div>
  </div>
  <div class="header-right">
    <span>PORT {MONITOR_PORT}</span>
    <span class="refresh-timer" id="refreshTimer">⟳ refreshing in 30s</span>
  </div>
</header>

<main>

  <!-- STAT CARDS -->
  <div class="stats-grid">
    <div class="stat-card red">
      <div class="stat-label">Total Attacks</div>
      <div class="stat-value" id="s-attacks">{total_attacks}</div>
      <div class="stat-sub">classified malicious events</div>
      <div class="stat-icon">💥</div>
    </div>
    <div class="stat-card orange">
      <div class="stat-label">Total Events</div>
      <div class="stat-value" id="s-events">{total_events}</div>
      <div class="stat-sub">all logged requests</div>
      <div class="stat-icon">📡</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-label">Top Attacker</div>
      <div class="stat-value" id="s-ip" style="font-size:15px;color:#1e90ff;font-family:'IBM Plex Mono',monospace;padding-top:4px">{top_ip}</div>
      <div class="stat-sub">highest frequency source IP</div>
      <div class="stat-icon">🎯</div>
    </div>
    <div class="stat-card cyan">
      <div class="stat-label">Hot Endpoint</div>
      <div class="stat-value" id="s-ep" style="font-size:15px;color:#00d2d3;font-family:'IBM Plex Mono',monospace;padding-top:4px">{top_endpoint}</div>
      <div class="stat-sub">most targeted URI</div>
      <div class="stat-icon">🔥</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">Harvested Creds</div>
      <div class="stat-value" id="s-creds">{cred_count}</div>
      <div class="stat-sub">credentials submitted</div>
      <div class="stat-icon">🔑</div>
    </div>
  </div>

  <!-- TABS -->
  <div class="tab-nav">
    <button class="tab-btn active" onclick="switchTab('events')">📋 Event Log</button>
    <button class="tab-btn" onclick="switchTab('analytics')">📊 Analytics</button>
    <button class="tab-btn" onclick="switchTab('map')">🗺 World Map</button>
    <button class="tab-btn" onclick="switchTab('creds')">🔑 Harvested Credentials</button>
  </div>

  <!-- TAB: EVENTS -->
  <div class="tab-panel active" id="tab-events">
    <div class="table-wrap">
      <div class="controls-bar">
        <input class="search-input" id="searchInput" type="text" placeholder="🔍  Search IP, country, type, URI…"/>
        <select class="filter-select" id="typeFilter">
          <option value="">All event types</option>
          <option>Command Injection Attempt</option>
          <option>Reconnaissance Attack</option>
          <option>SQL Injection Attempt</option>
          <option>XSS Attempt</option>
          <option>Path Traversal / LFI Attempt</option>
          <option>CVE Exploit Probe</option>
          <option>Admin Panel Probe</option>
          <option>Automated Scanner Detected</option>
          <option>Credential Submission</option>
          <option>Suspicious Request</option>
          <option>Recon</option>
        </select>
        <select class="filter-select" id="methodFilter">
          <option value="">All methods</option>
          <option>GET</option>
          <option>POST</option>
        </select>
        <button class="btn btn-export" onclick="window.location='/export'">⬇ Export CSV</button>
        <button class="btn btn-clear" onclick="clearFilters()">✕ Clear</button>
        <span class="result-count" id="resultCount"></span>
      </div>
      <table>
        <thead><tr>
          <th>ID</th><th>Timestamp</th><th>Source IP</th><th>Method</th>
          <th>Location</th><th>Event Type</th><th>URI</th><th>User Agent</th><th>ISP</th>
        </tr></thead>
        <tbody id="logTable">{rows_html}</tbody>
      </table>
      <div class="table-footer">
        <span>⚡ DELILAH · LAST 1000 EVENTS</span>
        <span id="lastUpdated" style="color:var(--cyan)"></span>
      </div>
    </div>
  </div>

  <!-- TAB: ANALYTICS -->
  <div class="tab-panel" id="tab-analytics">
    <div class="charts-grid">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">Attacks Per Hour (Last 24h)</div></div>
        <div class="panel-body"><canvas id="hourlyChart" height="140"></canvas></div>
      </div>
      <div class="panel">
        <div class="panel-header"><div class="panel-title">Attack Type Breakdown</div></div>
        <div class="panel-body" style="display:flex;align-items:center;justify-content:center">
          <canvas id="typeChart" height="140" style="max-width:320px"></canvas>
        </div>
      </div>
    </div>
    <div class="charts-grid">
      <div class="panel">
        <div class="panel-header"><div class="panel-title">7-Day Attack Timeline</div></div>
        <div class="panel-body"><canvas id="timelineChart" height="140"></canvas></div>
      </div>
      <div class="panel">
        <div class="panel-header"><div class="panel-title">Top Attacker Countries</div></div>
        <div class="panel-body"><canvas id="countryChart" height="140"></canvas></div>
      </div>
    </div>
  </div>

  <!-- TAB: MAP -->
  <div class="tab-panel" id="tab-map">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Global Attack Origin Map</div>
        <span style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)">geo-located IPs only</span>
      </div>
      <div id="attackMap"></div>
    </div>
  </div>

  <!-- TAB: CREDENTIALS -->
  <div class="tab-panel" id="tab-creds">
    <div class="table-wrap">
      <div class="controls-bar">
        <span style="font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--orange)">
          ⚠️ These are credentials submitted by attackers to the fake Kibana login page
        </span>
      </div>
      <table>
        <thead><tr>
          <th>ID</th><th>Timestamp</th><th>Source IP</th>
          <th>Username</th><th>Password</th><th>Endpoint</th><th>Location</th>
        </tr></thead>
        <tbody>{cred_rows_html}</tbody>
      </table>
      <div class="table-footer">
        <span>🔑 HARVESTED CREDENTIALS — FAKE LOGIN PAGE</span>
      </div>
    </div>
  </div>

</main>

<script>
function switchTab(name) {{
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'analytics') initCharts(window._lastStats || {{}});
  if (name === 'map') setTimeout(() => map.invalidateSize(), 100);
}}

Chart.defaults.color       = '#4a5d78';
Chart.defaults.borderColor = '#1c2537';
Chart.defaults.font.family = "'IBM Plex Mono', monospace";
Chart.defaults.font.size   = 10;
let hourlyChart, typeChart, timelineChart, countryChart;

function initCharts(data) {{
  const hours   = Array.from({{length:24}}, (_,i) => String(i).padStart(2,'0'));
  const hourMap = {{}};
  (data.hourly || []).forEach(h => hourMap[h.hour] = h.count);
  const hCounts = hours.map(h => hourMap[h] || 0);
  if (hourlyChart) hourlyChart.destroy();
  hourlyChart = new Chart(document.getElementById('hourlyChart'), {{
    type:'bar', data:{{ labels:hours, datasets:[{{ label:'Attacks', data:hCounts,
      backgroundColor:'rgba(255,71,87,0.5)', borderColor:'#ff4757', borderWidth:1, borderRadius:3 }}] }},
    options:{{ responsive:true, maintainAspectRatio:true,
      plugins:{{ legend:{{display:false}} }},
      scales:{{ x:{{ grid:{{color:'rgba(255,255,255,0.03)'}} }}, y:{{ grid:{{color:'rgba(255,255,255,0.05)'}} }} }}
    }}
  }});

  const typeLabels = (data.types || []).map(t => t.type);
  const typeCounts = (data.types || []).map(t => t.count);
  const palette    = ['#ff4757','#ffa502','#1e90ff','#e84393','#00d2d3','#a29bfe','#2ed573','#eccc68'];
  if (typeChart) typeChart.destroy();
  typeChart = new Chart(document.getElementById('typeChart'), {{
    type:'doughnut', data:{{ labels:typeLabels,
      datasets:[{{ data:typeCounts, backgroundColor:palette.map(c=>c+'cc'),
                   borderColor:palette, borderWidth:1.5, hoverOffset:6 }}] }},
    options:{{ responsive:true, maintainAspectRatio:true, cutout:'62%',
      plugins:{{ legend:{{ position:'right', labels:{{ boxWidth:10, padding:8 }} }} }} }}
  }});

  const tlLabels = (data.timeline || []).map(t => t.day.slice(5));
  const tlCounts = (data.timeline || []).map(t => t.count);
  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(document.getElementById('timelineChart'), {{
    type:'line', data:{{ labels:tlLabels,
      datasets:[{{ label:'Events', data:tlCounts, borderColor:'#00d2d3',
        backgroundColor:'rgba(0,210,211,0.1)', fill:true, tension:0.4,
        pointBackgroundColor:'#00d2d3', pointRadius:4 }}] }},
    options:{{ responsive:true, maintainAspectRatio:true,
      plugins:{{ legend:{{display:false}} }},
      scales:{{ x:{{ grid:{{color:'rgba(255,255,255,0.03)'}} }}, y:{{ grid:{{color:'rgba(255,255,255,0.05)'}} }} }}
    }}
  }});

  const ctLabels = (data.countries || []).map(c => c.country);
  const ctCounts = (data.countries || []).map(c => c.count);
  if (countryChart) countryChart.destroy();
  countryChart = new Chart(document.getElementById('countryChart'), {{
    type:'bar', data:{{ labels:ctLabels,
      datasets:[{{ label:'Attacks', data:ctCounts,
        backgroundColor:'rgba(162,155,254,0.6)', borderColor:'#a29bfe', borderWidth:1, borderRadius:3 }}] }},
    options:{{ indexAxis:'y', responsive:true, maintainAspectRatio:true,
      plugins:{{ legend:{{display:false}} }},
      scales:{{ x:{{ grid:{{color:'rgba(255,255,255,0.05)'}} }}, y:{{ grid:{{color:'rgba(255,255,255,0.03)'}} }} }}
    }}
  }});
}}

const map = L.map('attackMap', {{ center:[20,0], zoom:2, attributionControl:false }});
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{ maxZoom:18 }}).addTo(map);
const attackIcon = L.divIcon({{
  className:'',
  html:'<div style="width:10px;height:10px;background:#ff4757;border-radius:50%;border:2px solid #ff000088;box-shadow:0 0 8px #ff4757"></div>',
  iconSize:[10,10], iconAnchor:[5,5]
}});
let markerLayer = L.layerGroup().addTo(map);

function updateMap(pts) {{
  markerLayer.clearLayers();
  (pts || []).forEach(p => {{
    if (p.lat && p.lon)
      L.marker([p.lat,p.lon],{{icon:attackIcon}})
       .bindPopup(`<b style="color:#ff4757">${{p.type}}</b><br>IP: ${{p.ip}}<br>Country: ${{p.country||'Unknown'}}`)
       .addTo(markerLayer);
  }});
}}

let countdown = 30;
function tick() {{
  countdown--;
  document.getElementById('refreshTimer').textContent = `⟳ refreshing in ${{countdown}}s`;
  if (countdown <= 0) {{ refreshStats(); countdown = 30; }}
}}
setInterval(tick, 1000);

function refreshStats() {{
  fetch('/stats').then(r=>r.json()).then(data => {{
    window._lastStats = data;
    document.getElementById('s-attacks').textContent = data.total_attacks;
    document.getElementById('s-events').textContent  = data.total_events;
    document.getElementById('s-ip').textContent      = data.top_ip;
    document.getElementById('s-ep').textContent      = data.top_endpoint;
    document.getElementById('s-creds').textContent   = data.cred_count;
    document.getElementById('lastUpdated').textContent = 'Updated ' + new Date().toLocaleTimeString();
    updateMap(data.geo_points);
    if (document.getElementById('tab-analytics').classList.contains('active'))
      initCharts(data);
  }}).catch(e => console.warn('Refresh failed:', e));
}}
refreshStats();

function applyFilters() {{
  const q      = document.getElementById('searchInput').value.toLowerCase();
  const type   = document.getElementById('typeFilter').value.toLowerCase();
  const method = document.getElementById('methodFilter').value.toLowerCase();
  const rows   = document.querySelectorAll('#logTable .log-row');
  let visible  = 0;
  rows.forEach(row => {{
    const text    = row.textContent.toLowerCase();
    const rType   = (row.dataset.type   || '').toLowerCase();
    const rMethod = (row.querySelector('.method-badge')?.textContent || '').toLowerCase();
    const show = (!q || text.includes(q)) && (!type || rType === type) && (!method || rMethod === method);
    row.classList.toggle('hidden', !show);
    if (show) visible++;
  }});
  document.getElementById('resultCount').textContent =
    (q||type||method) ? `${{visible}} result${{visible!==1?'s':''}} shown` : '';
}}
document.getElementById('searchInput').addEventListener('input', applyFilters);
document.getElementById('typeFilter').addEventListener('change', applyFilters);
document.getElementById('methodFilter').addEventListener('change', applyFilters);
function clearFilters() {{
  document.getElementById('searchInput').value = '';
  document.getElementById('typeFilter').value  = '';
  document.getElementById('methodFilter').value = '';
  applyFilters();
}}
</script>
</body>
</html>""")
        except Exception as e:
            logger.error(f"Dashboard render failed: {e}")
            self.set_status(500)
            self.write(f"<h1>Error</h1><p>{e}</p>")


class HealthHandler(tornado.web.RequestHandler):
    async def get(self):
        try:
            async with db_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            self.write({"status": "ok", "service": "monitor", "db": "connected"})
        except Exception as e:
            self.set_status(503)
            self.write({"status": "degraded", "db": str(e)})


def make_app():
    return tornado.web.Application([
        (r"/health", HealthHandler),
        (r"/",       DashboardHandler),
        (r"/stats",  StatsHandler),
        (r"/export", ExportHandler),
    ])


async def main():
    await init_db()
    app = make_app()
    app.listen(MONITOR_PORT)
    logger.info(f"📊 Dashboard running on http://localhost:{MONITOR_PORT}")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
