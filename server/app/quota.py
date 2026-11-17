"""Учёт запросов к Яндекс Локатору по ключам и обновление старых точек перед концом суток.

У ключа лимит (по умолчанию 100 запросов в сутки, сутки — с полуночи по Москве). FamilyTime
считает каждый запрос по каждому ключу и выбирает наименее израсходованный ключ; ключ,
который Яндекс отклонил (403/429) или который выбрал лимит, до конца суток не используется.
За LOCATOR_REFRESH_BEFORE минут до конца суток неизрасходованный остаток каждого ключа,
кроме LOCATOR_RESERVE запросов, тратится на обновление самых старых мест по IP (ft_geoip).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

log = logging.getLogger("familytime.quota")

REFRESH_LOCK = 1717171704
CHECK_EVERY = 60


def key_id(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def key_label(key: str) -> str:
    return f"{key[:4]}…{key[-4:]}" if len(key) > 10 else "…" + key[-2:]


def day_tz(cfg) -> ZoneInfo:
    try:
        return ZoneInfo(cfg.locator_day_tz)
    except Exception:  # noqa: BLE001
        return ZoneInfo("Europe/Moscow")


def quota_day(cfg, now: datetime | None = None) -> date:
    return (now or datetime.now(timezone.utc)).astimezone(day_tz(cfg)).date()


def day_end(cfg, day: date) -> datetime:
    """Конец суток лимита (следующая полночь в часовом поясе лимита), в UTC."""
    return datetime.combine(day + timedelta(days=1), time(0), day_tz(cfg)).astimezone(timezone.utc)


async def usage_today(conn, cfg, now: datetime | None = None) -> dict[str, dict]:
    day = quota_day(cfg, now)
    rows = await conn.fetch("SELECT * FROM ft_locator_usage WHERE day = $1", day)
    return {r["key_id"]: dict(r) for r in rows}


async def pick_keys(conn, cfg) -> list[str]:
    """Ключи по возрастанию расхода за сутки; исчерпанные и отклонённые — пропускаются."""
    keys = list(dict.fromkeys(cfg.yandex_locator_keys))
    if conn is None:
        return keys
    used = await usage_today(conn, cfg)
    out = []
    for k in keys:
        u = used.get(key_id(k)) or {}
        if u.get("rejected") or u.get("requests", 0) >= cfg.locator_daily_limit:
            continue
        out.append((u.get("requests", 0), k))
    return [k for _, k in sorted(out, key=lambda x: x[0])]


async def count(conn, cfg, key: str, kind: str, status: str) -> None:
    """kind: wifi | ip | refresh; status: found | empty | rejected | error."""
    if conn is None:
        return
    now = datetime.now(timezone.utc)
    await conn.execute(
        f"""INSERT INTO ft_locator_usage (key_id, day, label, requests, {kind}, found, rejected,
                                          errors, last_at)
            VALUES ($1, $2, $3, 1, 1, $4, $5, $6, $7)
            ON CONFLICT (key_id, day) DO UPDATE SET requests = ft_locator_usage.requests + 1,
              {kind} = ft_locator_usage.{kind} + 1,
              found = ft_locator_usage.found + EXCLUDED.found,
              rejected = ft_locator_usage.rejected + EXCLUDED.rejected,
              errors = ft_locator_usage.errors + EXCLUDED.errors,
              label = EXCLUDED.label, last_at = EXCLUDED.last_at""",
        key_id(key), quota_day(cfg, now), key_label(key), int(status == "found"),
        int(status == "rejected"), int(status == "error"), now)


async def refresh_due(pool, http, cfg, now: datetime | None = None) -> int | None:
    """Если до конца суток лимита осталось не больше LOCATOR_REFRESH_BEFORE минут и сегодня
    обновления ещё не было — потратить остаток ключей (кроме резерва) на самые старые места
    по IP. Возвращает число обновлённых мест или None, если время не пришло."""
    from . import locator
    now = now or datetime.now(timezone.utc)
    day = quota_day(cfg, now)
    if not cfg.yandex_locator_keys or day_end(cfg, day) - now > timedelta(minutes=cfg.locator_refresh_before):
        return None
    async with pool.acquire() as conn:
        if await conn.fetchval("SELECT 1 FROM ft_locator_refresh WHERE day = $1", day):
            return None
        used = await usage_today(conn, cfg, now)
        details, total = {}, 0
        busy: set[str] = set()                     # адреса, уже обновлённые сегодня
        for key in dict.fromkeys(cfg.yandex_locator_keys):
            u = used.get(key_id(key)) or {}
            if u.get("rejected"):
                details[key_label(key)] = {"budget": 0, "refreshed": 0, "note": "ключ отклонён"}
                continue
            budget = cfg.locator_daily_limit - cfg.locator_reserve - int(u.get("requests", 0))
            done = 0
            if budget > 0:
                rows = await conn.fetch(
                    "SELECT ip FROM ft_geoip WHERE NOT (ip = ANY($2::text[])) "
                    "ORDER BY fetched_at LIMIT $1", budget, list(busy))
                for r in rows:
                    busy.add(r["ip"])
                    fix, status = await locator.locate_with(http, cfg, key, {"ip": [{"address": r["ip"]}]})
                    await count(conn, cfg, key, "refresh", status)
                    if status in ("rejected", "error"):
                        break
                    if fix:
                        if not fix.accuracy:
                            fix.accuracy = locator.GEOIP_ACCURACY
                        await conn.execute(
                            """UPDATE ft_geoip SET lat = $2, lon = $3, accuracy = $4,
                               source = 'yandex-ip', fetched_at = $5 WHERE ip = $1""",
                            r["ip"], fix.lat, fix.lon, fix.accuracy, now)
                    else:                           # Яндекс не знает — прежнее место в силе
                        await conn.execute("UPDATE ft_geoip SET fetched_at = $2 WHERE ip = $1",
                                           r["ip"], now)
                    done += 1
            details[key_label(key)] = {"budget": max(budget, 0), "refreshed": done}
            total += done
        await conn.execute(
            """INSERT INTO ft_locator_refresh (day, done_at, refreshed, details) VALUES ($1, $2, $3, $4)
               ON CONFLICT (day) DO NOTHING""", day, now, total, details)
    log.info("Локатор: обновлено старых мест по IP: %s (%s)", total, details)
    return total


async def refresher(state) -> None:
    """Фоновая проверка раз в минуту; работает один узел (advisory lock)."""
    await asyncio.sleep(30)
    while True:
        try:
            async with state.pool.acquire() as conn:
                if await conn.fetchval("SELECT pg_try_advisory_lock($1)", REFRESH_LOCK):
                    try:
                        await refresh_due(state.pool, state.http, state.cfg)
                    finally:
                        await conn.execute("SELECT pg_advisory_unlock($1)", REFRESH_LOCK)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            log.warning("обновление мест по IP: %s", e)
        await asyncio.sleep(CHECK_EVERY)


async def stats(conn, cfg, days: int = 7) -> dict:
    """Для страницы настроек: по каждому ключу из конфигурации — сегодня и за days суток."""
    today = quota_day(cfg)
    rows = await conn.fetch("SELECT * FROM ft_locator_usage WHERE day > $1 ORDER BY day",
                            today - timedelta(days=days))
    by = {}
    for r in rows:
        by.setdefault(r["key_id"], {})[r["day"]] = dict(r)
    keys = []
    for k in dict.fromkeys(cfg.yandex_locator_keys):
        hist = by.get(key_id(k), {})
        t = hist.get(today, {})
        keys.append({"label": key_label(k), "today": t,
                     "left": max(cfg.locator_daily_limit - int(t.get("requests", 0)), 0),
                     "history": [(today - timedelta(days=i), int(hist.get(today - timedelta(days=i), {})
                                                                .get("requests", 0)))
                                 for i in range(days - 1, -1, -1)]})
    last = await conn.fetchrow("SELECT * FROM ft_locator_refresh ORDER BY day DESC LIMIT 1")
    oldest = await conn.fetchval("SELECT min(fetched_at) FROM ft_geoip")
    cached = await conn.fetchval("SELECT count(*) FROM ft_geoip")
    return {"rows": keys, "limit": cfg.locator_daily_limit, "reserve": cfg.locator_reserve,
            "before": cfg.locator_refresh_before, "refresh_at": day_end(cfg, today)
            - timedelta(minutes=cfg.locator_refresh_before), "last": dict(last) if last else None,
            "oldest": oldest, "cached": cached}
