"""Портал: страницы родителя и ребёнка."""
from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import auth, db, lists, policy, requests_logic

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).with_name("templates")))
templates.env.globals.update(
    fmt=policy.fmt_minutes, fmt_time=policy.fmt_time, WEEKDAYS=policy.WEEKDAYS,
    WEEKDAYS_SHORT=policy.WEEKDAYS_SHORT)


STOP_REASON = "закончить на сегодня"


class LoginRequired(Exception):
    def __init__(self, next_url: str):
        self.next_url = next_url


def now_local(request: Request) -> datetime:
    return datetime.now(timezone.utc).astimezone(request.app.state.cfg.tz)


def need_user(request: Request) -> auth.User:
    u = auth.current_user(request)
    if not u:
        raise LoginRequired(str(request.url.path))
    return u


def need_parent(request: Request) -> auth.User:
    u = need_user(request)
    if not u.parent:
        raise HTTPException(403, "Страница только для родителей")
    return u


def page(request: Request, name: str, user: auth.User | None, **ctx) -> HTMLResponse:
    ctx.update(request=request, user=user, cfg=request.app.state.cfg,
               flash=request.query_params.get("ok", ""), err=request.query_params.get("err", ""))
    return templates.TemplateResponse(request, name, ctx)


def back(url: str, ok: str = "", err: str = "") -> RedirectResponse:
    from urllib.parse import urlencode
    q = urlencode({k: v for k, v in (("ok", ok), ("err", err)) if v})
    return RedirectResponse(url + ("?" + q if q else ""), 303)


def parse_time(v: str) -> time | None:
    v = (v or "").strip()
    if not v:
        return None
    h, m = v.split(":")[:2]
    return time(int(h) % 24, int(m) % 60)


def parse_limit(v: str) -> int | None:
    v = (v or "").strip()
    if v in ("", "-", "∞"):
        return None
    return max(0, min(24 * 60, int(v)))


async def child_view(conn, request: Request, username: str) -> dict:
    nl = now_local(request)
    child = await db.get_child(conn, username)
    if not child:
        raise HTTPException(404, "Нет такого ребёнка")
    st = await db.child_status(conn, username, nl)
    hist = await db.usage_history(conn, username, 14, nl.date())
    peak = max([r["counted"] + r["free"] for r in hist] + [st["limit_seconds"] or 0, 3600])
    top_day = await db.top_activity(conn, username, nl.date(), nl.date())
    top_week = await db.top_activity(conn, username, nl.date() - timedelta(days=6), nl.date())
    pres = await db.presence(conn, username)
    reqs = await conn.fetch(
        "SELECT * FROM ft_requests WHERE username = $1 ORDER BY created_at DESC LIMIT 5", username)
    bonuses = await conn.fetch(
        "SELECT * FROM ft_bonus WHERE username = $1 AND day = $2 ORDER BY created_at", username,
        nl.date())
    pct = 0
    if st["limit_seconds"]:
        pct = min(100, int(100 * st["counted_seconds"] / st["limit_seconds"]))
    elif st["limit_seconds"] == 0:
        pct = 100
    stop = next((b for b in reversed(bonuses) if b["reason"] == STOP_REASON), None)
    return dict(child=child, st=st, hist=hist, peak=peak, top_day=top_day, top_week=top_week,
                presence=pres, reqs=reqs, bonuses=bonuses, stop=stop, pct=pct, today=nl.date(),
                now=nl)


# ---------- вход ----------

@router.get("/login")
async def login(request: Request, next: str = "/"):
    cfg = request.app.state.cfg
    if cfg.dev_login:
        return HTMLResponse('<form action="/dev-login">user <input name="u"> parent '
                            '<input name="parent" type="checkbox" value="1"><button>go</button></form>')
    return await auth.login_redirect(request, next)


@router.get("/dev-login")
async def dev_login(request: Request, u: str, parent: str = ""):
    cfg = request.app.state.cfg
    if not cfg.dev_login:
        raise HTTPException(404)
    resp = RedirectResponse("/", 302)
    auth.make_session(cfg, resp, u.lower(), u, parent == "1")
    return resp


@router.get("/oidc/callback")
async def oidc_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error or not code:
        raise HTTPException(401, "Вход отменён: " + error)
    return await auth.callback(request, code, state)


@router.get("/logout")
async def logout(request: Request):
    return await auth.logout_redirect(request)


@router.get("/")
async def home(request: Request):
    u = need_user(request)
    return RedirectResponse("/dashboard" if u.parent else "/me", 302)


# ---------- ребёнок ----------

@router.get("/me")
async def me(request: Request):
    u = need_user(request)
    async with request.app.state.pool.acquire() as conn:
        child = await db.get_child(conn, u.username)
        if not child:
            if u.parent:
                return RedirectResponse("/dashboard", 302)
            return page(request, "not_child.html", u)
        v = await child_view(conn, request, u.username)
    return page(request, "me.html", u, **v)


@router.post("/me/request")
async def me_request(request: Request, minutes: int = Form(...), reason: str = Form(""),
                     csrf: str = Form("")):
    u = need_user(request)
    auth.check_csrf(request, u, csrf)
    minutes = max(5, min(240, minutes))
    msg = await requests_logic.create(request.app.state.pool, request.app.state.cfg,
                                      request.app.state.tg, u.username, minutes, reason.strip())
    return back("/me", ok=msg)


# ---------- родитель: дети ----------

@router.get("/dashboard")
async def dashboard(request: Request):
    u = need_parent(request)
    async with request.app.state.pool.acquire() as conn:
        rows = []
        for c in await db.list_children(conn):
            v = await child_view(conn, request, c["username"])
            rows.append(v)
        pending = await conn.fetchval("SELECT count(*) FROM ft_requests WHERE status = 'pending'")
    return page(request, "dashboard.html", u, rows=rows, pending=pending)


@router.post("/children")
async def children_add(request: Request, username: str = Form(...), display_name: str = Form(""),
                       csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    username = username.strip().lower().split("\\")[-1].split("@")[0]
    if not username:
        return back("/dashboard", err="Укажите логин")
    async with request.app.state.pool.acquire() as conn:
        await db.add_child(conn, username, display_name or username)
    return back(f"/child/{username}", ok="Добавлено. Проверьте правила по дням")


@router.get("/child/{username}")
async def child_page(request: Request, username: str):
    u = need_parent(request)
    async with request.app.state.pool.acquire() as conn:
        v = await child_view(conn, request, username.lower())
    return page(request, "child.html", u, **v)


@router.post("/child/{username}/rules")
async def child_rules(request: Request, username: str):
    u = need_parent(request)
    form = await request.form()
    auth.check_csrf(request, u, str(form.get("csrf", "")))
    try:
        rules = []
        for wd in range(7):
            lim = parse_limit(str(form.get(f"limit{wd}", "")))
            a = parse_time(str(form.get(f"from{wd}", "")))
            b = parse_time(str(form.get(f"to{wd}", "")))
            if (a is None) != (b is None):
                return back(f"/child/{username}", err=f"{policy.WEEKDAYS[wd]}: укажите оба времени")
            rules.append((wd, lim, a, b))
    except ValueError:
        return back(f"/child/{username}", err="Неверное число или время")
    async with request.app.state.pool.acquire() as conn:
        async with conn.transaction():
            for wd, lim, a, b in rules:
                await db.set_rule(conn, username, wd, lim, a, b)
    return back(f"/child/{username}", ok="Правила сохранены")


@router.post("/child/{username}/bonus")
async def child_bonus(request: Request, username: str, minutes: int = Form(...),
                      reason: str = Form(""), csrf: str = Form(""), ret: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    minutes = max(-24 * 60, min(24 * 60, minutes))
    async with request.app.state.pool.acquire() as conn:
        if minutes == 0:
            st = await db.child_status(conn, username, now_local(request))
            # «закончить на сегодня»: бонус, обнуляющий остаток
            if st["remaining_seconds"]:
                minutes = -((st["remaining_seconds"] + 59) // 60)
                reason = STOP_REASON
            else:
                return back(ret or f"/child/{username}", ok="Время уже закончилось")
        await db.add_bonus(conn, username, now_local(request).date(), minutes, reason.strip(),
                           u.username)
    word = f"+{minutes}" if minutes > 0 else str(minutes)
    return back(ret if ret.startswith("/") else f"/child/{username}", ok=f"Сегодня {word} мин")


@router.post("/child/{username}/bonus/{bonus_id}/delete")
async def child_bonus_delete(request: Request, username: str, bonus_id: int, csrf: str = Form(""),
                             ret: str = Form("")):
    """Отмена сегодняшней корректировки, в том числе «хватит на сегодня»."""
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    async with request.app.state.pool.acquire() as conn:
        r = await conn.fetchrow(
            "DELETE FROM ft_bonus WHERE id = $1 AND username = $2 AND day = $3 RETURNING minutes",
            bonus_id, username, now_local(request).date())
    url = ret if ret.startswith("/") else f"/child/{username}"
    if not r:
        return back(url, err="Корректировка не найдена или уже не сегодняшняя")
    return back(url, ok=f"Отменено: {r['minutes']:+d} мин")


@router.post("/child/{username}/settings")
async def child_settings(request: Request, username: str, display_name: str = Form(...),
                         enabled: str = Form(""), csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    async with request.app.state.pool.acquire() as conn:
        await conn.execute("UPDATE ft_children SET display_name = $2, enabled = $3 WHERE username = $1",
                           username, display_name.strip() or username, enabled == "1")
    return back(f"/child/{username}", ok="Сохранено")


@router.post("/child/{username}/delete")
async def child_delete(request: Request, username: str, csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    async with request.app.state.pool.acquire() as conn:
        await conn.execute("DELETE FROM ft_children WHERE username = $1", username)
    return back("/dashboard", ok="Удалено вместе со статистикой")


# ---------- родитель: настройки ----------

@router.get("/settings")
async def settings_page(request: Request):
    u = need_parent(request)
    async with request.app.state.pool.acquire() as conn:
        s = await db.get_settings(conn)
        eff = await lists.effective(conn, s)
        subs = await conn.fetch(
            "SELECT id, category, name, url, enabled, interval_hours, count, last_fetch, last_ok, "
            "error FROM ft_lists ORDER BY category, id")
    return page(request, "settings.html", u, s=s, defaults=policy.DEFAULT_SETTINGS,
                subs=subs, counts=lists.counts(eff), categories=lists.CATEGORIES,
                policy_limit=lists.POLICY_LIMIT, next_update=lists.next_update)


@router.post("/settings")
async def settings_save(request: Request):
    u = need_parent(request)
    form = await request.form()
    auth.check_csrf(request, u, str(form.get("csrf", "")))
    section = str(form.get("section", ""))
    async with request.app.state.pool.acquire() as conn:
        if section == "lists":
            for key, kind in (("edu_apps", "exe"), ("edu_domains", "domain"),
                              ("blocked_apps", "exe"), ("blocked_domains", "domain"),
                              ("edu_schemes", "scheme"), ("restricted_kill", "exe")):
                await db.set_setting(conn, key, policy.clean_list(str(form.get(key, "")), kind),
                                     u.username)
        elif section == "messages":
            msgs = {k: str(form.get(k, "")).strip()[:1000] for k in ("warn", "limit", "window", "lost")}
            msgs = {k: v or policy.DEFAULT_SETTINGS["messages"][k] for k, v in msgs.items()}
            await db.set_setting(conn, "messages", msgs, u.username)
        elif section == "options":
            try:
                idle = max(0, min(120, int(form.get("idle_minutes", 15))))
                warn = sorted({max(1, min(60, int(x))) for x in
                               str(form.get("warn_minutes", "")).replace(",", " ").split()},
                              reverse=True)
                loc = {"interval_minutes": max(1, min(240, int(form.get("interval_minutes", 15)))),
                       "lost_interval_minutes": max(1, min(60, int(form.get("lost_interval_minutes", 2))))}
            except ValueError:
                return back("/settings", err="Неверное число")
            await db.set_setting(conn, "idle_minutes", idle, u.username)
            await db.set_setting(conn, "warn_minutes", warn, u.username)
            await db.set_setting(conn, "location", loc, u.username)
        elif section == "reset_messages":
            await conn.execute("DELETE FROM ft_settings WHERE key = 'messages'")
    return back("/settings", ok="Сохранено. Компьютеры получат изменения в течение минуты")


# ---------- родитель: подписки на списки ----------

@router.post("/lists")
async def list_add(request: Request, category: str = Form(...), url: str = Form(...),
                   name: str = Form(""), interval_hours: int = Form(24), csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    url = url.strip()
    if category not in lists.CATEGORIES:
        return back("/settings", err="Неизвестный тип списка")
    if not url.lower().startswith(("http://", "https://")):
        return back("/settings", err="Ссылка должна начинаться с http:// или https://")
    interval_hours = max(1, min(720, interval_hours))
    async with request.app.state.pool.acquire() as conn:
        lid = await conn.fetchval(
            """INSERT INTO ft_lists (category, url, name, interval_hours) VALUES ($1, $2, $3, $4)
               ON CONFLICT (category, url) DO UPDATE SET name = EXCLUDED.name,
               interval_hours = EXCLUDED.interval_hours, enabled = true RETURNING id""",
            category, url[:1000], (name.strip() or url)[:200], interval_hours)
    msg = await lists.fetch_one(request.app.state.pool, request.app.state.http, lid)
    if msg.startswith("Ошибка"):
        return back("/settings", err="Список добавлен, но не загрузился. " + msg)
    return back("/settings", ok="Список добавлен. " + msg)


@router.post("/lists/{list_id}")
async def list_action(request: Request, list_id: int, action: str = Form(...),
                      interval_hours: int = Form(24), csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    pool = request.app.state.pool
    async with pool.acquire() as conn:
        if action == "delete":
            await conn.execute("DELETE FROM ft_lists WHERE id = $1", list_id)
            return back("/settings", ok="Подписка удалена")
        if action in ("enable", "disable"):
            await conn.execute("UPDATE ft_lists SET enabled = $2 WHERE id = $1", list_id,
                               action == "enable")
            return back("/settings", ok="Включена" if action == "enable" else "Выключена")
        if action == "interval":
            await conn.execute("UPDATE ft_lists SET interval_hours = $2 WHERE id = $1", list_id,
                               max(1, min(720, interval_hours)))
            return back("/settings", ok="Интервал обновления сохранён")
    if action == "refresh":
        async with pool.acquire() as conn:      # принудительно, без If-None-Match
            await conn.execute("UPDATE ft_lists SET etag = '', last_modified = '' WHERE id = $1",
                               list_id)
        msg = await lists.fetch_one(pool, request.app.state.http, list_id)
        return back("/settings", **({"err": msg} if msg.startswith("Ошибка") else {"ok": msg}))
    return back("/settings", err="Неизвестное действие")


# ---------- родитель: устройства ----------

@router.get("/devices")
async def devices_page(request: Request):
    u = need_parent(request)
    async with request.app.state.pool.acquire() as conn:
        devs = await conn.fetch("SELECT * FROM ft_devices ORDER BY hostname")
    return page(request, "devices.html", u, devices=devs,
                now=datetime.now(timezone.utc))


@router.post("/devices/{dev_id}")
async def device_save(request: Request, dev_id: UUID, mode: str = Form("control"),
                      lost: str = Form(""), lost_lock: str = Form(""), lost_message: str = Form(""),
                      csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    mode = mode if mode in ("control", "track") else "control"
    async with request.app.state.pool.acquire() as conn:
        await conn.execute(
            "UPDATE ft_devices SET mode = $2, lost = $3, lost_lock = $4, lost_message = $5 WHERE id = $1",
            dev_id, mode, lost == "1", lost_lock == "1", lost_message.strip()[:500])
    return back("/devices", ok="Сохранено")


@router.post("/devices/{dev_id}/delete")
async def device_delete(request: Request, dev_id: UUID, csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    async with request.app.state.pool.acquire() as conn:
        await conn.execute("DELETE FROM ft_devices WHERE id = $1", dev_id)
    return back("/devices", ok="Удалено. Агент на компьютере зарегистрируется заново при следующем запуске")


# ---------- родитель: запросы ----------

@router.get("/requests")
async def requests_page(request: Request):
    u = need_parent(request)
    async with request.app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT r.*, c.display_name FROM ft_requests r JOIN ft_children c USING (username)
               ORDER BY (r.status = 'pending') DESC, r.created_at DESC LIMIT 50""")
    return page(request, "requests.html", u, rows=rows)


@router.post("/requests/{req_id}")
async def request_decide(request: Request, req_id: int, action: str = Form(...),
                         csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    msg = await requests_logic.decide(request.app.state.pool, request.app.state.cfg,
                                      request.app.state.tg, req_id, action == "approve", u.username)
    return back("/requests", ok=msg)
