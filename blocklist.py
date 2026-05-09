"""
blocklist.py — Persistent IP blocklist with in-memory cache.

Rules
-----
- An IP is auto-blocked after BLOCK_THRESHOLD events within BLOCK_WINDOW seconds.
- Block entries live in the `blocked_ips` table and are loaded into memory on startup.
- The in-memory set is the hot path; DB is the source of truth across restarts.
- Severity weights: high-severity event types count double toward the threshold.
"""

import asyncio
import datetime
import logging
import os
import time
from typing import Optional

import asyncpg

logger = logging.getLogger(__name__)

# ── Tunables (override via env) ──────────────────────────────────────────────
BLOCK_THRESHOLD = int(os.getenv("BLOCK_THRESHOLD", 10))    # events before auto-block
BLOCK_WINDOW    = int(os.getenv("BLOCK_WINDOW_SECONDS", 60))  # rolling window (seconds)
BLOCK_DURATION  = int(os.getenv("BLOCK_DURATION_SECONDS", 3600))  # 0 = permanent

HIGH_SEVERITY = {
    "CVE Exploit Probe",
    "Command Injection Attempt",
    "SQL Injection Attempt",
    "Path Traversal / LFI Attempt",
    "Credential Submission",
}

# ── In-memory state ──────────────────────────────────────────────────────────
_blocked:  set[str]              = set()           # currently blocked IPs
_hits:     dict[str, list[float]] = {}             # ip → [epoch, epoch, ...]


# ── DB helpers ───────────────────────────────────────────────────────────────

async def init_blocklist(pool: asyncpg.Pool) -> None:
    """Create the blocked_ips table and load existing blocks into memory."""
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id          BIGSERIAL PRIMARY KEY,
                ip          TEXT NOT NULL UNIQUE,
                reason      TEXT,
                blocked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at  TIMESTAMPTZ,
                manual      BOOLEAN NOT NULL DEFAULT FALSE,
                hit_count   INTEGER NOT NULL DEFAULT 0
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip)"
        )
        # Load active blocks (not expired)
        rows = await conn.fetch("""
            SELECT ip FROM blocked_ips
            WHERE expires_at IS NULL OR expires_at > NOW()
        """)
        for r in rows:
            _blocked.add(r["ip"])
    logger.info(f"🚫 Blocklist ready — {len(_blocked)} IPs currently blocked")


async def block_ip(pool: asyncpg.Pool, ip: str, reason: str,
                   manual: bool = False, hit_count: int = 0) -> None:
    """Add an IP to the blocklist (DB + memory)."""
    _blocked.add(ip)
    expires_at = (
        None if BLOCK_DURATION == 0
        else datetime.datetime.utcnow() + datetime.timedelta(seconds=BLOCK_DURATION)
    )
    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO blocked_ips (ip, reason, expires_at, manual, hit_count)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (ip) DO UPDATE
              SET reason     = EXCLUDED.reason,
                  blocked_at = NOW(),
                  expires_at = EXCLUDED.expires_at,
                  hit_count  = EXCLUDED.hit_count
        """, ip, reason, expires_at, manual, hit_count)
    tag = "MANUAL" if manual else "AUTO"
    logger.warning(f"🚫 [{tag}] Blocked {ip} — {reason}")


async def unblock_ip(pool: asyncpg.Pool, ip: str) -> bool:
    """Remove an IP from the blocklist. Returns True if it was blocked."""
    was_blocked = ip in _blocked
    _blocked.discard(ip)
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM blocked_ips WHERE ip = $1", ip)
    if was_blocked:
        logger.info(f"✅ Unblocked {ip}")
    return was_blocked


def is_blocked(ip: str) -> bool:
    """Hot-path check — purely in-memory."""
    return ip in _blocked


async def expire_blocks(pool: asyncpg.Pool) -> None:
    """Periodic task: remove expired blocks from DB and memory."""
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            DELETE FROM blocked_ips
            WHERE expires_at IS NOT NULL AND expires_at <= NOW()
            RETURNING ip
        """)
    for r in rows:
        _blocked.discard(r["ip"])
        logger.info(f"⏰ Block expired for {r['ip']}")


# ── Rate / hit tracking ──────────────────────────────────────────────────────

def record_hit(ip: str, event_type: str) -> Optional[str]:
    """
    Record a hit for this IP. Returns a block reason string if the threshold
    is breached, otherwise None.
    """
    now = time.monotonic()
    weight = 2 if event_type in HIGH_SEVERITY else 1

    bucket = _hits.setdefault(ip, [])
    # Expand by weight (double-count high-severity)
    bucket.extend([now] * weight)
    # Trim events outside the window
    cutoff = now - BLOCK_WINDOW
    _hits[ip] = [t for t in bucket if t >= cutoff]

    if len(_hits[ip]) >= BLOCK_THRESHOLD:
        _hits.pop(ip, None)  # reset so re-block doesn't fire every event
        return (
            f"Auto-blocked: {len(_hits.get(ip, []))+weight} weighted hits "
            f"in {BLOCK_WINDOW}s — last event: {event_type}"
        )
    return None


async def maybe_auto_block(pool: asyncpg.Pool, ip: str, event_type: str) -> bool:
    """
    Check rate and auto-block if threshold breached.
    Returns True if the IP was just blocked.
    """
    if is_blocked(ip):
        return True
    reason = record_hit(ip, event_type)
    if reason:
        await block_ip(pool, ip, reason, manual=False,
                       hit_count=BLOCK_THRESHOLD)
        return True
    return False


async def get_blocked_list(pool: asyncpg.Pool) -> list[dict]:
    """Return all active blocks for the monitor dashboard."""
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT ip, reason, blocked_at, expires_at, manual, hit_count
            FROM blocked_ips
            WHERE expires_at IS NULL OR expires_at > NOW()
            ORDER BY blocked_at DESC
        """)
    return [dict(r) for r in rows]


# ── Background expiry loop ───────────────────────────────────────────────────

async def start_expiry_loop(pool: asyncpg.Pool) -> None:
    """Run expire_blocks every 60 seconds."""
    while True:
        await asyncio.sleep(60)
        try:
            await expire_blocks(pool)
        except Exception as e:
            logger.error(f"[BLOCKLIST] Expiry error: {e}")
