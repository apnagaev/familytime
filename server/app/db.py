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
            await _migrate_v2(conn)
    return pool


async def _migrate_v2(conn) -> None:
    """1.1 → 1.2: общие настройки и подписки становятся настройками каждого ребёнка,
    все существующие дети и компьютеры — в семью «Семья». Один раз."""
    if (await conn.fetchval("SELECT value FROM ft_kv WHERE key = 'schema_version'")) == "2":
        return
    rows = await conn.fetch("SELECT key, value FROM ft_settings")
    glob = policy.merge_settings({r["key"]: r["value"] for r in rows})
    children = [r["username"] for r in await conn.fetch("SELECT username FROM ft_children")]
    if children:
        fam = await conn.fetchval("SELECT id FROM ft_families ORDER BY id LIMIT 1")
        if fam is None:
            fam = await conn.fetchval(
                "INSERT INTO ft_families (name, messages) VALUES ('Семья', $1) RETURNING id",
                {k: glob["messages"][k] for k in policy.FAMILY_MESSAGE_KEYS})
        await conn.execute("UPDATE ft_children SET family_id = $1 WHERE family_id IS NULL", fam)
        await conn.execute("UPDATE ft_devices SET family_id = $1 WHERE family_id IS NULL", fam)
        child_set = {k: glob[k] for k in policy.CHILD_KEYS}
        await conn.execute("UPDATE ft_children SET settings = $1 WHERE settings = '{}'::jsonb",
                           child_set)
        for sub in await conn.fetch("SELECT * FROM ft_lists WHERE username IS NULL"):
            for u in children:
                await conn.execute(
                    """INSERT INTO ft_lists (username, category, name, url, enabled, interval_hours,
                       entries, count, last_fetch, last_ok, error, etag, last_modified)
                       SELECT $2, category, name, url, enabled, interval_hours, entries, count,
                              last_fetch, last_ok, error, etag, last_modified
                       FROM ft_lists WHERE id = $1 ON CONFLICT DO NOTHING""", sub["id"], u)
    await conn.execute("DELETE FROM ft_lists WHERE username IS NULL")
    await conn.execute(
        "INSERT INTO ft_kv VALUES ('schema_version', '2') ON CONFLICT (key) DO UPDATE SET value = '2'")


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


# ---------- семьи ----------

async def parent_families(conn, username: str) -> list[int]:
    return [r["family_id"] for r in await conn.fetch(
        "SELECT family_id FROM ft_family_parents WHERE username = $1", username.lower())]


async def list_families(conn, ids: list[int] | None = None):
    q = """SELECT f.*, COALESCE((SELECT array_agg(username ORDER BY username)
                  FROM ft_family_parents p WHERE p.family_id = f.id), '{}') AS parents
           FROM ft_families f"""
    if ids is not None:
        return await conn.fetch(q + " WHERE f.id = ANY($1::bigint[]) ORDER BY f.name", ids)
    return await conn.fetch(q + " ORDER BY f.name")


async def create_family(conn, name: str, parent: str | None = None) -> int:
    fid = await conn.fetchval("INSERT INTO ft_families (name) VALUES ($1) RETURNING id",
                              name.strip()[:100] or "Семья")
    if parent:
        await conn.execute("INSERT INTO ft_family_parents VALUES ($1, $2) ON CONFLICT DO NOTHING",
                           fid, parent.lower())
    return fid


# ---------- дети и правила ----------

async def list_children(conn, enabled_only: bool = False, families: list[int] | None = None):
    """families=None — все (админ, агенты); список — только дети этих семей."""
    q = "SELECT * FROM ft_children WHERE true"
    args: list = []
    if enabled_only:
        q += " AND enabled"
    if families is not None:
        args.append(families)
        q += " AND family_id = ANY($1::bigint[])"
    return await conn.fetch(q + " ORDER BY display_name", *args)


async def get_child(conn, username: str):
    return await conn.fetchrow("SELECT * FROM ft_children WHERE username = $1", username.lower())


async def child_by_login(conn, username: str, email: str = ""):
    """Ребёнок по логину Keycloak или подтверждённой почте (дети на ПК вне домена)."""
    r = await conn.fetchrow("SELECT * FROM ft_children WHERE username = $1", username.lower())
    if r is None and email:
        r = await conn.fetchrow("SELECT * FROM ft_children WHERE email <> '' AND lower(email) = $1",
                                email.lower())
    return r


async def windows_logins(conn) -> dict[str, str]:
    """Логин Windows (основной и дополнительные) → ребёнок, только включённые."""
    out: dict[str, str] = {}
    for r in await conn.fetch("SELECT username, aliases FROM ft_children WHERE enabled"):
        out[r["username"]] = r["username"]
        for a in r["aliases"] or []:
            out.setdefault(a, r["username"])
    return out


async def add_child(conn, username: str, display_name: str, family_id: int | None = None) -> None:
    username = username.strip().lower()
    async with conn.transaction():
        await conn.execute(
            """INSERT INTO ft_children (username, display_name, family_id, settings)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (username) DO UPDATE SET display_name = EXCLUDED.display_name,
               enabled = true, family_id = COALESCE(EXCLUDED.family_id, ft_children.family_id)""",
            username, display_name.strip() or username, family_id, policy.child_settings({}))
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
