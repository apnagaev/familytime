"""API для агентов на компьютерах: регистрация, пульс с учётом времени, локация."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from . import db, lists, locator, policy

router = APIRouter(prefix="/api/agent")

MAX_SAMPLE_AGE = timedelta(days=7)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def client_ip(request: Request) -> str:
    cfg = request.app.state.cfg
    v = request.headers.get(cfg.trusted_proxy_header, "")
    if v:
        return v.split(",")[0].strip()
    return request.client.host if request.client else ""


def norm_user(value: str | None) -> str:
    """'EXAMPLE\\Son' / 'son@example.local' / 'son' -> 'son'."""
    if not value:
        return ""
    v = value.strip().lower()
    if "\\" in v:
        v = v.split("\\", 1)[1]
    if "@" in v:
        v = v.split("@", 1)[0]
    return v


async def current_device(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "no token")
    th = token_hash(auth[7:].strip())
    async with request.app.state.pool.acquire() as conn:
        dev = await conn.fetchrow("SELECT * FROM ft_devices WHERE token_hash = $1", th)
    if not dev:
        raise HTTPException(401, "unknown device")
    return dev


# ---------- модели ----------

class EnrollIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    secret: str
    mode: str = "control"
    os: str = ""
    agent_version: str = ""


class Sample(BaseModel):
    t: int                                  # unix-время начала отрезка
    user: str
    sec: int = Field(ge=1, le=3600)
    exe: str = ""
    domain: str = ""
    app: str = ""                           # понятное название программы


class Current(BaseModel):
    exe: str = ""
    domain: str = ""
    app: str = ""


class HeartbeatIn(BaseModel):
    seq: int = Field(ge=0)
    agent_version: str = ""
    os: str = ""
    session: str = "none"                   # active | locked | none
    user: str = ""
    current: Current | None = None
    samples: list[Sample] = Field(default_factory=list, max_length=5000)
    caps: list[str] = Field(default_factory=list)   # "lists": списки забирает отдельно по версии


class WifiAP(BaseModel):
    bssid: str
    rssi: int                               # дБм


class LocationIn(BaseModel):
    wifi: list[WifiAP] = Field(default_factory=list, max_length=100)
    ssid: str = ""
    battery: int | None = None
    on_ac: bool | None = None
    session: str = "none"
    user: str = ""
    local_ip: str = ""
    reason: str = "timer"


# ---------- политика для агента ----------

def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


OLD_AGENT_LIMIT = 5000      # агентам 1.0.x списки идут в каждом ответе — не раздуваем


def restricted_domains(cfg, eff: dict) -> list[str]:
    """Открытые в режиме «только учёба»: протоколы (telemost:*), портал и Keycloak, учебные."""
    out: list[str] = [f"{sch}:*" for sch in eff.get("edu_schemes", [])]
    for extra in [_host(cfg.public_url), _host(cfg.oidc_issuer), *cfg.extra_allowed_domains]:
        extra = policy.norm_domain(extra)
        if extra and extra not in out:
            out.append(extra)
    out += [d for d in eff["edu_domains"] if d not in out]
    return out


def lists_payload(cfg, eff: dict, limit: int | None = None) -> dict:
    cut = (lambda x: x[:limit]) if limit else (lambda x: x)
    return {
        "edu_apps": cut(eff["edu_apps"]),
        "edu_domains": cut(eff["edu_domains"]),
        "blocked_apps": cut(eff["blocked_apps"]),
        "blocked_domains": cut(eff["blocked_domains"]),
        "restricted_domains": cut(restricted_domains(cfg, eff)),
    }


def device_policy(cfg, dev, settings: dict, union: dict | None, caps=(), child_set: dict | None = None) -> dict:
    """Политика компьютера. Агент 1.2 (caps userlists) берёт списки, простой и предупреждения
    из политики ребёнка; агентам 1.1 и 1.0 отдаётся один набор на компьютер — объединение
    по детям его семьи (union)."""
    loc = settings["location"]
    interval = loc["lost_interval_minutes"] if dev["lost"] else loc["interval_minutes"]
    cs = child_set or policy.child_settings({})
    out: dict = {}
    if "userlists" not in caps and union is not None:
        out = {"lists_version": union["version"]} if "lists" in caps \
            else lists_payload(cfg, union, OLD_AGENT_LIMIT)
    return {
        **out,
        "mode": dev["mode"],
        "browsers": settings["browsers"],
        "restricted_kill": cs["restricted_kill"],
        "idle_minutes": int(cs["idle_minutes"]),
        "warn_minutes": [int(x) for x in cs["warn_minutes"]],
        "location_interval": max(60, int(interval) * 60),
        "portal_url": cfg.public_url,
        "lost": {
            "on": dev["lost"],
            "lock": dev["lost_lock"],
            "message": dev["lost_message"] or settings["messages"]["lost"],
        },
    }


async def user_policy(conn, cfg, child, now_local: datetime) -> dict:
    """Политика ребёнка: лимит и остаток, тексты его семьи, его списки (версия), простой."""
    username = child["username"]
    st = await db.child_status(conn, username, now_local)
    rule = st["rule"]
    values = {
        "name": child["display_name"],
        "limit": policy.fmt_minutes(st["limit_seconds"]),
        "used": policy.fmt_minutes(st["counted_seconds"]),
        "from": policy.fmt_time(rule.window_from),
        "to": policy.fmt_time(rule.window_to),
    }
    fam = await conn.fetchval("SELECT messages FROM ft_families WHERE id = $1", child["family_id"])
    msgs = policy.family_messages(fam)
    cs = policy.child_settings(child["settings"])
    eff = await lists.effective(conn, child)
    return {
        "child": True,
        "name": child["display_name"],
        "day": st["day"].isoformat(),
        "mode": st["mode"],
        "reason": st["reason"],
        "limit_seconds": st["limit_seconds"],
        "counted_seconds": st["counted_seconds"],
        "remaining_seconds": st["remaining_seconds"],
        "window_change_in": st["window_change_in"],
        "messages": {k: policy.render(msgs.get(k, ""), values) for k in ("warn", "limit", "window")},
        "lists_version": eff["version"],
        "restricted_kill": cs["restricted_kill"],
        "idle_minutes": int(cs["idle_minutes"]),
        "warn_minutes": [int(x) for x in cs["warn_minutes"]],
        # на случай работы без связи: правила недели, бонусы не учитываются
        "rules": {
            str(wd): {
                "limit": r.limit_minutes,
                "from": policy.fmt_time(r.window_from) or None,
                "to": policy.fmt_time(r.window_to) or None,
            } for wd, r in st["rules"].items()
        },
    }


# ---------- обработчики ----------

@router.post("/enroll")
async def enroll(body: EnrollIn, request: Request):
    cfg = request.app.state.cfg
    if not cfg.enroll_secret or not hmac.compare_digest(body.secret, cfg.enroll_secret):
        raise HTTPException(403, "bad secret")
    hostname = body.hostname.strip().lower()
    mode = body.mode if body.mode in ("control", "track") else "control"
    token = secrets.token_urlsafe(32)
    async with request.app.state.pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO ft_devices (hostname, token_hash, mode, os_version, agent_version, last_ip)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (hostname) DO UPDATE SET token_hash = EXCLUDED.token_hash,
                 os_version = EXCLUDED.os_version, agent_version = EXCLUDED.agent_version,
                 last_seq = 0""",
            hostname, token_hash(token), mode, body.os[:200], body.agent_version[:50],
            client_ip(request))
    return {"token": token, "hostname": hostname}


def classify(sample: Sample, rules: dict) -> tuple[str, str, bool]:
    exe = policy.norm_exe(sample.exe)
    domain = policy.norm_domain(sample.domain)
    free = policy.is_free(exe, domain, rules)
    if domain and exe in rules["browsers"]:
        return "site", domain, free
    return "app", exe or "неизвестно", free


@router.post("/heartbeat")
async def heartbeat(body: HeartbeatIn, request: Request, dev=Depends(current_device)):
    cfg = request.app.state.cfg
    now = datetime.now(timezone.utc)
    now_local = now.astimezone(cfg.tz)
    async with request.app.state.pool.acquire() as conn:
        settings = await db.get_settings(conn)
        logins = await db.windows_logins(conn)          # логин Windows → ребёнок
        kids = {r["username"]: r for r in await db.list_children(conn, enabled_only=True)}
        rules_cache: dict[str, dict] = {}

        async def rules_of(child_name: str) -> dict:
            if child_name not in rules_cache:
                eff = await lists.effective(conn, kids[child_name])
                rules_cache[child_name] = {"edu_apps": eff["edu_apps_set"],
                                           "edu_domains": eff["edu_domains_set"],
                                           "browsers": settings["browsers"]}
            return rules_cache[child_name]

        names: dict[str, str] = {}
        for x in [*body.samples, body.current or Current()]:
            exe, app = policy.norm_exe(x.exe), x.app.strip()[:80]
            if exe and app and app.lower() != exe:
                names[exe] = app
        accepted = 0
        async with conn.transaction():
            locked = await conn.fetchrow(
                "SELECT last_seq FROM ft_devices WHERE id = $1 FOR UPDATE", dev["id"])
            # повтор того же пакета (ответ потерялся) не считается второй раз
            fresh = body.seq > locked["last_seq"]
            if fresh and dev["mode"] == "control":
                usage_add: dict = defaultdict(lambda: [0, 0])
                act_add: dict = defaultdict(lambda: [0, 0])
                for s in body.samples:
                    user = logins.get(norm_user(s.user))
                    if not user:
                        continue
                    ts = datetime.fromtimestamp(s.t, timezone.utc)
                    if ts > now + timedelta(minutes=5) or ts < now - MAX_SAMPLE_AGE:
                        continue
                    day = ts.astimezone(cfg.tz).date()
                    kind, name, free = classify(s, await rules_of(user))
                    i = 1 if free else 0
                    usage_add[(user, day)][i] += s.sec
                    act_add[(user, day, kind, name[:200])][i] += s.sec
                    accepted += 1
                for (user, day), (c, f) in usage_add.items():
                    await conn.execute(
                        """INSERT INTO ft_usage VALUES ($1, $2, $3, $4)
                           ON CONFLICT (username, day) DO UPDATE SET
                           counted_seconds = ft_usage.counted_seconds + EXCLUDED.counted_seconds,
                           free_seconds = ft_usage.free_seconds + EXCLUDED.free_seconds""",
                        user, day, c, f)
                for (user, day, kind, name), (c, f) in act_add.items():
                    await conn.execute(
                        """INSERT INTO ft_activity VALUES ($1, $2, $3, $4, $5, $6)
                           ON CONFLICT (username, day, kind, name) DO UPDATE SET
                           counted_seconds = ft_activity.counted_seconds + EXCLUDED.counted_seconds,
                           free_seconds = ft_activity.free_seconds + EXCLUDED.free_seconds""",
                        user, day, kind, name, c, f)
            if names:
                await db.save_app_names(conn, names)
            win_user = norm_user(body.user)
            cur_child = logins.get(win_user)
            family_id = dev["family_id"]
            if family_id is None and cur_child and kids[cur_child]["family_id"] is not None:
                # компьютер без семьи привязывается к семье первого вошедшего ребёнка
                family_id = kids[cur_child]["family_id"]
            await conn.execute(
                """UPDATE ft_devices SET last_seen = $2, last_ip = $3, last_user = $4,
                   last_session = $5, agent_version = $6, os_version = $7,
                   last_seq = GREATEST(last_seq, $8), family_id = $9 WHERE id = $1""",
                dev["id"], now, client_ip(request), win_user or None, body.session[:20],
                body.agent_version[:50], body.os[:200], body.seq, family_id)
            if cur_child and dev["mode"] == "control":
                cur = body.current or Current()
                await conn.execute(
                    """INSERT INTO ft_presence (username, device_id, last_seen, session, exe, domain, app)
                       VALUES ($1, $2, $3, $4, $5, $6, $7)
                       ON CONFLICT (username, device_id) DO UPDATE SET last_seen = EXCLUDED.last_seen,
                       session = EXCLUDED.session, exe = EXCLUDED.exe, domain = EXCLUDED.domain,
                       app = EXCLUDED.app""",
                    cur_child, dev["id"], now, body.session[:20],
                    policy.norm_exe(cur.exe), policy.norm_domain(cur.domain), cur.app.strip()[:80])

        # политики — по логинам Windows, как их знает агент
        users = {win_user} | {norm_user(s.user) for s in body.samples}
        users.discard("")
        policies = {}
        if dev["mode"] == "control":
            for u in sorted(users):
                child_name = logins.get(u)
                policies[u] = await user_policy(conn, cfg, kids[child_name], now_local) \
                    if child_name else {"child": False, "mode": "none"}
        dev = await conn.fetchrow("SELECT * FROM ft_devices WHERE id = $1", dev["id"])
        union = None if "userlists" in body.caps \
            else await lists.effective_union(conn, dev["family_id"])
        child_set = policy.child_settings(kids[cur_child]["settings"]) if cur_child else None
    return {
        "server_time": now.timestamp(),
        "utc_offset": int(now_local.utcoffset().total_seconds()),
        "accepted": accepted,
        "seq": body.seq,
        "device": device_policy(cfg, dev, settings, union, body.caps, child_set),
        "users": policies,
    }


class ListsIn(BaseModel):
    user: str = ""          # логин Windows; пусто — агент 1.1, один набор на компьютер


@router.post("/lists")
async def agent_lists(request: Request, body: ListsIn | None = None, dev=Depends(current_device)):
    """Полные списки; агент забирает их, только когда меняется lists_version."""
    cfg = request.app.state.cfg
    async with request.app.state.pool.acquire() as conn:
        login = norm_user(body.user) if body else ""
        if login:
            child_name = (await db.windows_logins(conn)).get(login)
            if not child_name:
                raise HTTPException(404, "not a child")
            eff = await lists.effective(conn, await db.get_child(conn, child_name))
        else:
            eff = await lists.effective_union(conn, dev["family_id"])
    return {"version": eff["version"], **lists_payload(cfg, eff)}


@router.post("/location")
async def location(body: LocationIn, request: Request, dev=Depends(current_device)):
    cfg = request.app.state.cfg
    ip = client_ip(request)
    fix = await locator.locate(request.app.state.http, cfg, body.wifi, ip)
    now = datetime.now(timezone.utc)
    async with request.app.state.pool.acquire() as conn:
        settings = await db.get_settings(conn)
        if fix:
            await conn.execute(
                """UPDATE ft_devices SET last_lat = $2, last_lon = $3, last_accuracy = $4,
                   last_fix_at = $5, last_fix_source = $6, battery = $7, on_ac = $8 WHERE id = $1""",
                dev["id"], fix.lat, fix.lon, fix.accuracy, now, fix.source, body.battery, body.on_ac)
        else:
            await conn.execute("UPDATE ft_devices SET battery = $2, on_ac = $3 WHERE id = $1",
                               dev["id"], body.battery, body.on_ac)
        sent = False
        if fix and cfg.traccar_osmand_url:
            if not dev["traccar_ok"]:
                ok = await locator.ensure_traccar_device(
                    request.app.state.http, cfg, dev["hostname"], body.user)
                if ok:
                    await conn.execute("UPDATE ft_devices SET traccar_ok = true WHERE id = $1",
                                       dev["id"])
            sent = await locator.send_osmand(
                request.app.state.http, cfg, dev, fix, body, ip, now)
    loc = settings["location"]
    interval = loc["lost_interval_minutes"] if dev["lost"] else loc["interval_minutes"]
    return {
        "ok": bool(fix),
        "sent": sent,
        "lat": fix.lat if fix else None,
        "lon": fix.lon if fix else None,
        "accuracy": fix.accuracy if fix else None,
        "next_interval": max(60, int(interval) * 60),
    }
