"""Пул соединений, миграции и запросы к базе."""
from __future__ import annotations

import json
from datetime import date, datetime, time
from pathlib import Path

import asyncpg

from . import policy

MIGRATION_LOCK = 1717171701
TELEGRAM_LOCK = 1717171702


async def _init_conn(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


async def create_pool(dsn: str) -> asyncpg.Pool:
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=10, init=_init_conn)
    sql = (Path(__file__).with_name("schema.sql")).read_text(encoding="utf-8")
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock($1)", MIGRATION_LOCK)
            await conn.execute(sql)
    return pool


# ---------- настройки ----------

async def get_settings(conn) -> dict:
    rows = await conn.fetch("SELECT key, value FROM ft_settings")
    return policy.merge_settings({r["key"]: r["value"] for r in rows})


async def set_setting(conn, key: str, value, by: str) -> None:
    await conn.execute(
        """INSERT INTO ft_settings (key, value, updated_by) VALUES ($1, $2, $3)
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(),
           updated_by = EXCLUDED.updated_by""",
        key, value, by)


# ---------- дети и правила ----------

async def list_children(conn, enabled_only: bool = False):
    q = "SELECT * FROM ft_children"
    if enabled_only:
        q += " WHERE enabled"
    return await conn.fetch(q + " ORDER BY display_name")


async def get_child(conn, username: str):
    return await conn.fetchrow("SELECT * FROM ft_children WHERE username = $1", username.lower())


async def add_child(conn, username: str, display_name: str) -> None:
    username = username.strip().lower()
    async with conn.transaction():
        await conn.execute(
            "INSERT INTO ft_children (username, display_name) VALUES ($1, $2) "
            "ON CONFLICT (username) DO UPDATE SET display_name = EXCLUDED.display_name, enabled = true",
            username, display_name.strip() or username)
        for wd, (lim, a, b) in enumerate(policy.DEFAULT_RULES):
            await conn.execute(
                "INSERT INTO ft_rules VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                username, wd, lim, a, b)


async def get_rules(conn, username: str) -> dict[int, policy.Rule]:
    rows = await conn.fetch("SELECT * FROM ft_rules WHERE username = $1", username)
    out = {}
    for wd in range(7):
        lim, a, b = policy.DEFAULT_RULES[wd]
        out[wd] = policy.Rule(lim, a, b)
    for r in rows:
        out[r["weekday"]] = policy.Rule(r["limit_minutes"], r["window_from"], r["window_to"])
    return out


async def set_rule(conn, username: str, weekday: int, limit: int | None,
                   a: time | None, b: time | None) -> None:
    await conn.execute(
        """INSERT INTO ft_rules VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (username, weekday) DO UPDATE SET limit_minutes = EXCLUDED.limit_minutes,
           window_from = EXCLUDED.window_from, window_to = EXCLUDED.window_to""",
        username, weekday, limit, a, b)


async def bonus_minutes(conn, username: str, day: date) -> int:
    return await conn.fetchval(
        "SELECT COALESCE(SUM(minutes), 0) FROM ft_bonus WHERE username = $1 AND day = $2",
        username, day)


async def add_bonus(conn, username: str, day: date, minutes: int, reason: str, by: str) -> None:
    await conn.execute(
        "INSERT INTO ft_bonus (username, day, minutes, reason, created_by) VALUES ($1,$2,$3,$4,$5)",
        username, day, minutes, reason, by)


async def usage(conn, username: str, day: date) -> tuple[int, int]:
    r = await conn.fetchrow(
        "SELECT counted_seconds, free_seconds FROM ft_usage WHERE username = $1 AND day = $2",
        username, day)
    return (r["counted_seconds"], r["free_seconds"]) if r else (0, 0)


async def child_status(conn, username: str, now_local: datetime) -> dict:
    """Состояние ребёнка на текущий момент: лимит, бонусы, остаток, режим."""
    day = now_local.date()
    rules = await get_rules(conn, username)
    rule = rules[day.weekday()]
    bonus = await bonus_minutes(conn, username, day)
    counted, free = await usage(conn, username, day)
    st = policy.compute_status(rule, bonus, counted, now_local)
    st.update(day=day, rule=rule, bonus_minutes=bonus, free_seconds=free, rules=rules)
    return st


async def usage_history(conn, username: str, days: int, today: date):
    return await conn.fetch(
        """SELECT d::date AS day, COALESCE(u.counted_seconds, 0) AS counted,
                  COALESCE(u.free_seconds, 0) AS free
           FROM generate_series($2::date - ($3 - 1), $2::date, interval '1 day') d
           LEFT JOIN ft_usage u ON u.username = $1 AND u.day = d::date
           ORDER BY d""",
        username, today, days)


async def top_activity(conn, username: str, day_from: date, day_to: date, limit: int = 15):
    return await conn.fetch(
        """SELECT a.kind, a.name, COALESCE(n.name, a.name) AS label,
                  SUM(a.counted_seconds) AS counted, SUM(a.free_seconds) AS free,
                  SUM(a.counted_seconds + a.free_seconds) AS total
           FROM ft_activity a
           LEFT JOIN ft_app_names n ON a.kind = 'app' AND n.exe = a.name
           WHERE a.username = $1 AND a.day BETWEEN $2 AND $3
           GROUP BY a.kind, a.name, n.name ORDER BY total DESC LIMIT $4""",
        username, day_from, day_to, limit)


async def presence(conn, username: str):
    return await conn.fetch(
        """SELECT p.*, d.hostname FROM ft_presence p JOIN ft_devices d ON d.id = p.device_id
           WHERE p.username = $1 AND p.last_seen > now() - interval '3 minutes'
           ORDER BY p.last_seen DESC""",
        username)


async def save_app_names(conn, names: dict[str, str]) -> None:
    """exe → понятное название от агента (описание файла или название приложения из Store)."""
    for exe, name in names.items():
        await conn.execute(
            """INSERT INTO ft_app_names (exe, name) VALUES ($1, $2)
               ON CONFLICT (exe) DO UPDATE SET name = EXCLUDED.name, updated_at = now()
               WHERE ft_app_names.name IS DISTINCT FROM EXCLUDED.name""",
            exe, name)


async def kv_get(conn, key: str) -> str | None:
    return await conn.fetchval("SELECT value FROM ft_kv WHERE key = $1", key)


async def kv_set(conn, key: str, value: str) -> None:
    await conn.execute(
        "INSERT INTO ft_kv VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        key, value)
