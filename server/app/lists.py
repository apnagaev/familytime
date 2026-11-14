"""Списки сайтов и программ: ручные записи из настроек + подписки по ссылкам с автообновлением.

Форматы подписок (как у Pi-hole и AdGuard):
  hosts         0.0.0.0 ads.example.com      127.0.0.1 a.com b.com
  adblock       ||ads.example.com^           ||ads.example.com^$important
  простой       ads.example.com              (по строке)
  программы     game.exe                     (по строке, для списков программ)
Комментарии: # ! ; и строки [Adblock …]. Исключения @@… и правила с путями, масками и
модификаторами вроде $client= пропускаются: FamilyTime блокирует домены целиком.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta, timezone

import httpx

from . import policy

log = logging.getLogger("familytime.lists")

# категория → (тип записей, подпись)
CATEGORIES = {
    "edu_domains": ("domain", "Учебные сайты"),
    "blocked_domains": ("domain", "Запрещённые сайты"),
    "edu_apps": ("exe", "Учебные программы"),
    "blocked_apps": ("exe", "Запрещённые программы"),
}
POLICY_LIMIT = 1000            # столько адресов принимают политики URLBlocklist/URLAllowlist
MAX_DOWNLOAD = 30 * 1024 * 1024
MAX_ENTRIES = 500_000
UPDATE_LOCK = 1717171703
CHECK_EVERY = 300              # с: как часто искать подписки, которым пора обновиться

_ADBLOCK = re.compile(r"^\|\|([^\^/\$\*|]+)\^(?:\$(important|all|document))?$")
_HOSTS_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
               "ip6-loopback", "0.0.0.0"}


def _is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def _domain(token: str) -> str:
    d = policy.norm_domain(token)
    return d if d and "." in d and not _is_ip(d) else ""


def parse(text: str, kind: str) -> list[str]:
    """Текст списка → уникальные домены или имена exe в исходном порядке."""
    out: list[str] = []
    seen: set[str] = set()

    def add(x: str) -> None:
        if x and x not in seen and len(out) < MAX_ENTRIES:
            seen.add(x)
            out.append(x)

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!;[" or line.startswith("@@"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if kind == "exe":
            tok = line.split()[0].strip("\"'")
            if tok.lower().endswith(".exe"):
                add(policy.norm_exe(tok))
            continue
        if line.startswith("||"):
            m = _ADBLOCK.match(line)
            if m:
                add(_domain(m.group(1)))
            continue
        if line[0] in "|/" or "*" in line or "$" in line:
            continue
        parts = line.split()
        if len(parts) > 1 and _is_ip(parts[0]):          # hosts
            for p in parts[1:]:
                if p.lower() not in _HOSTS_SKIP:
                    add(_domain(p))
            continue
        if len(parts) == 1:
            add(_domain(parts[0]))
    return out


# ---------- итоговые списки ----------

_cache: dict = {}          # ключ (ребёнок или union:…) → {"version": …, "data": …}


async def _subs_signature(conn, usernames: list[str]) -> str:
    return await conn.fetchval(
        """SELECT COALESCE(string_agg(id || ':' || enabled || ':' ||
                  COALESCE(extract(epoch FROM last_ok)::bigint, 0), ',' ORDER BY id), '')
           FROM ft_lists WHERE username = ANY($1::text[])""", usernames) or ""


def _manual(settings_list: list[dict]) -> dict:
    """Ручные записи нескольких детей (для одного ребёнка — его собственные)."""
    out: dict = {}
    for k in (*CATEGORIES, "edu_schemes"):
        merged: list[str] = []
        seen: set[str] = set()
        for st in settings_list:
            for x in st.get(k, []):
                if x not in seen:
                    seen.add(x)
                    merged.append(x)
        out[k] = merged
    return out


async def _build(conn, key: str, usernames: list[str], settings_list: list[dict]) -> dict:
    manual = _manual(settings_list)
    sig = json.dumps(manual, sort_keys=True, ensure_ascii=False) + "|" + \
        await _subs_signature(conn, usernames)
    version = hashlib.sha1(sig.encode()).hexdigest()[:16]
    cached = _cache.get(key)
    if cached and cached["version"] == version:
        return cached["data"]
    data: dict = {"version": version, "edu_schemes": manual["edu_schemes"]}
    rows = await conn.fetch(
        "SELECT category, entries FROM ft_lists WHERE enabled AND username = ANY($1::text[]) "
        "ORDER BY id", usernames)
    for cat in CATEGORIES:
        merged: list[str] = []
        seen: set[str] = set()
        for x in manual[cat] + [e for r in rows if r["category"] == cat
                                for e in (r["entries"] or [])]:
            if x not in seen:
                seen.add(x)
                merged.append(x)
        data[cat] = merged
        data[cat + "_set"] = seen
    # запрещённое не считается учебным
    data["edu_domains"] = [d for d in data["edu_domains"]
                           if not policy.domain_matches(d, data["blocked_domains_set"])]
    data["edu_domains_set"] = set(data["edu_domains"])
    if len(_cache) > 500:
        _cache.clear()
    _cache[key] = {"version": version, "data": data}
    return data


async def effective(conn, child) -> dict:
    """Итоговые списки ребёнка: его ручные записи + его включённые подписки.
    Ручные идут первыми: в политику браузера они попадают в первую очередь.
    Кеш по подписи (ручные + время обновления подписок)."""
    st = policy.child_settings(child["settings"])
    return await _build(conn, "c:" + child["username"], [child["username"]], [st])


async def effective_union(conn, family_id: int | None) -> dict:
    """Для агентов 1.1 (один набор списков на компьютер): объединение по детям семьи
    компьютера, а у компьютера без семьи — по всем детям."""
    if family_id is None:
        kids = await conn.fetch("SELECT username, settings FROM ft_children WHERE enabled")
    else:
        kids = await conn.fetch(
            "SELECT username, settings FROM ft_children WHERE enabled AND family_id = $1", family_id)
    return await _build(conn, f"u:{family_id}", [k["username"] for k in kids],
                        [policy.child_settings(k["settings"]) for k in kids])


def counts(data: dict) -> dict:
    return {cat: len(data[cat]) for cat in CATEGORIES}


# ---------- загрузка подписок ----------

async def fetch_one(pool, http: httpx.AsyncClient, list_id: int) -> str:
    """Скачивает и разбирает одну подписку. Возвращает текст для портала."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM ft_lists WHERE id = $1", list_id)
    if not row:
        return "Список не найден"
    kind = CATEGORIES[row["category"]][0]
    headers = {"User-Agent": "familytime-lists/1.0"}
    if row["etag"] and row["count"]:
        headers["If-None-Match"] = row["etag"]
    if row["last_modified"] and row["count"]:
        headers["If-Modified-Since"] = row["last_modified"]
    now = datetime.now(timezone.utc)
    try:
        async with http.stream("GET", row["url"], headers=headers, timeout=60,
                               follow_redirects=True) as r:
            if r.status_code == 304:
                async with pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE ft_lists SET last_fetch = $2, error = '' WHERE id = $1",
                        list_id, now)
                return f"Без изменений: {row['count']} записей"
            if r.status_code != 200:
                raise ValueError(f"HTTP {r.status_code}")
            body = bytearray()
            async for chunk in r.aiter_bytes():
                body += chunk
                if len(body) > MAX_DOWNLOAD:
                    raise ValueError("список больше 30 МБ")
            etag = r.headers.get("etag", "")
            lastmod = r.headers.get("last-modified", "")
        text = body.decode("utf-8", errors="replace")
        entries = parse(text, kind)
        if not entries:
            raise ValueError("в списке не найдено ни одной записи нужного формата")
    except (httpx.HTTPError, ValueError) as e:
        msg = str(e) or type(e).__name__
        async with pool.acquire() as conn:
            await conn.execute("UPDATE ft_lists SET last_fetch = $2, error = $3 WHERE id = $1",
                               list_id, now, msg[:300])
        log.warning("список %s (%s): %s", list_id, row["url"], msg)
        return "Ошибка: " + msg
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE ft_lists SET entries = $2, count = $3, last_fetch = $4, last_ok = $4,
               error = '', etag = $5, last_modified = $6 WHERE id = $1""",
            list_id, entries, len(entries), now, etag[:200], lastmod[:100])
    log.info("список %s обновлён: %s записей", list_id, len(entries))
    return f"Обновлено: {len(entries)} записей"


async def update_due(pool, http) -> None:
    async with pool.acquire() as conn:
        ids = await conn.fetch(
            """SELECT id FROM ft_lists WHERE enabled AND (last_fetch IS NULL OR
               last_fetch < now() - make_interval(hours => interval_hours)) ORDER BY id""")
    for r in ids:
        await fetch_one(pool, http, r["id"])


async def updater(pool, http) -> None:
    """Фоновое обновление подписок; работает один узел (advisory lock)."""
    await asyncio.sleep(20)
    while True:
        try:
            async with pool.acquire() as conn:
                if await conn.fetchval("SELECT pg_try_advisory_lock($1)", UPDATE_LOCK):
                    try:
                        await update_due(pool, http)
                    finally:
                        await conn.execute("SELECT pg_advisory_unlock($1)", UPDATE_LOCK)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — обновление не должно падать навсегда
            log.warning("обновление списков: %s", e)
        await asyncio.sleep(CHECK_EVERY)


def next_update(row) -> datetime | None:
    if not row["enabled"]:
        return None
    if not row["last_fetch"]:
        return datetime.now(timezone.utc)
    return row["last_fetch"] + timedelta(hours=row["interval_hours"])
