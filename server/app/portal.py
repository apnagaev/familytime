"""Портал: страницы администратора, родителя и ребёнка.

Права: admin (роль клиента Keycloak) видит все семьи; parent — только детей и компьютеры
семей, в которых он записан родителем; остальные — только свою страницу /me, если их логин
или подтверждённая почта совпадают с записью ребёнка.
"""
from __future__ import annotations

import re
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode
from uuid import UUID

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import auth, db, lists, locator, policy, requests_logic

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).with_name("templates")))
templates.env.globals.update(
    fmt=policy.fmt_minutes, fmt_time=policy.fmt_time, WEEKDAYS=policy.WEEKDAYS,
    WEEKDAYS_SHORT=policy.WEEKDAYS_SHORT)

STOP_REASON = "закончить на сегодня"
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_LOGIN = re.compile(r"^[^\s\\/]{1,100}$")


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


def need_admin(request: Request) -> auth.User:
    u = need_user(request)
    if not u.admin:
        raise HTTPException(403, "Страница только для администратора")
    return u


async def scope(conn, u: auth.User) -> list[int] | None:
    """Семьи, которые видит пользователь: None — все (админ), иначе список id."""
    return None if u.admin else await db.parent_families(conn, u.username)


async def child_access(conn, u: auth.User, username: str):
    """Ребёнок, если он в зоне видимости пользователя; иначе 404 (не раскрываем, что он есть)."""
    child = await db.get_child(conn, username)
    fams = await scope(conn, u)
    if not child or (fams is not None and child["family_id"] not in fams):
        raise HTTPException(404, "Нет такого ребёнка")
    return child


async def family_access(conn, u: auth.User, family_id: int):
    fams = await scope(conn, u)
    if fams is not None and family_id not in fams:
        raise HTTPException(404, "Нет такой семьи")
    rows = await db.list_families(conn, [family_id])
    if not rows:
        raise HTTPException(404, "Нет такой семьи")
    return rows[0]


def page(request: Request, name: str, user: auth.User | None, **ctx) -> HTMLResponse:
    ctx.update(request=request, user=user, cfg=request.app.state.cfg,
               flash=request.query_params.get("ok", ""), err=request.query_params.get("err", ""))
    return templates.TemplateResponse(request, name, ctx)


def back(url: str, ok: str = "", err: str = "") -> RedirectResponse:
    q = urlencode({k: v for k, v in (("ok", ok), ("err", err)) if v})
    return RedirectResponse(url + ("?" + q if q else ""), 303)


def norm_login(v: str) -> str:
    """Логин: DOMAIN\\login → login, нижний регистр. Почта в логине не обрезается."""
    v = (v or "").strip().lower().split("\\")[-1]
    return v if _LOGIN.match(v) else ""


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


async def child_view(conn, request: Request, child) -> dict:
    nl = now_local(request)
    username = child["username"]
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
        return HTMLResponse('<form action="/dev-login">user <input name="u"> '
                            'parent <input name="parent" type="checkbox" value="1"> '
                            'admin <input name="admin" type="checkbox" value="1"> '
                            'email <input name="email"><button>go</button></form>')
    return await auth.login_redirect(request, next)


@router.get("/dev-login")
async def dev_login(request: Request, u: str, parent: str = "", admin: str = "", email: str = ""):
    cfg = request.app.state.cfg
    if not cfg.dev_login:
        raise HTTPException(404)
    resp = RedirectResponse("/", 302)
    auth.make_session(cfg, resp, u.lower(), u, parent == "1", admin == "1", email.lower())
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
        child = await db.child_by_login(conn, u.username, u.email)
        if not child:
            if u.parent:
                return RedirectResponse("/dashboard", 302)
            return page(request, "not_child.html", u)
        v = await child_view(conn, request, child)
    return page(request, "me.html", u, **v)


@router.post("/me/request")
async def me_request(request: Request, minutes: int = Form(...), reason: str = Form(""),
                     csrf: str = Form("")):
    u = need_user(request)
    auth.check_csrf(request, u, csrf)
    minutes = max(5, min(240, minutes))
    async with request.app.state.pool.acquire() as conn:
        child = await db.child_by_login(conn, u.username, u.email)
    if not child:
        return back("/me", err="Вы не в списке детей")
    msg = await requests_logic.create(request.app.state.pool, request.app.state.cfg,
                                      request.app.state.tg, child["username"], minutes,
                                      reason.strip())
    return back("/me", ok=msg)


# ---------- родитель: дети ----------

@router.get("/dashboard")
async def dashboard(request: Request):
    u = need_parent(request)
    async with request.app.state.pool.acquire() as conn:
        fams = await scope(conn, u)
        families = await db.list_families(conn, fams)
        fam_names = {f["id"]: f["name"] for f in families}
        rows = [await child_view(conn, request, c)
                for c in await db.list_children(conn, families=fams)]
        if fams is None:
            pending = await conn.fetchval("SELECT count(*) FROM ft_requests WHERE status = 'pending'")
        else:
            pending = await conn.fetchval(
                """SELECT count(*) FROM ft_requests r JOIN ft_children c USING (username)
                   WHERE r.status = 'pending' AND c.family_id = ANY($1::bigint[])""", fams)
    return page(request, "dashboard.html", u, rows=rows, pending=pending, families=families,
                fam_names=fam_names)


@router.post("/children")
async def children_add(request: Request, username: str = Form(...), display_name: str = Form(""),
                       family_id: str = Form(""), csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    username = norm_login(username)
    if not username:
        return back("/dashboard", err="Укажите логин ребёнка без пробелов")
    async with request.app.state.pool.acquire() as conn:
        async with conn.transaction():
            if await db.get_child(conn, username):
                # чужого ребёнка «добавлением» забрать нельзя
                return back("/dashboard", err=f"Логин {username} уже добавлен. Если это ваш "
                                              "ребёнок в другой семье, обратитесь к администратору")
            fams = await scope(conn, u)
            fid = int(family_id) if family_id.strip().isdigit() else None
            if fid is not None:
                await family_access(conn, u, fid)
            elif fams:
                fid = fams[0]
            elif fams is None:
                first = await db.list_families(conn)
                fid = first[0]["id"] if first else await db.create_family(conn, "Семья")
            else:                                   # у родителя ещё нет семьи — создаём
                fid = await db.create_family(conn, f"Семья {u.name}", u.username)
            await db.add_child(conn, username, display_name or username, fid)
    return back(f"/child/{username}", ok="Добавлено. Проверьте правила по дням и настройки")


@router.get("/child/{username}")
async def child_page(request: Request, username: str):
    u = need_parent(request)
    async with request.app.state.pool.acquire() as conn:
        child = await child_access(conn, u, username.lower())
        v = await child_view(conn, request, child)
        fams = await scope(conn, u)
        eff = await lists.effective(conn, child)
        subs = await conn.fetch(
            "SELECT id, category, name, url, enabled, interval_hours, count, last_fetch, last_ok, "
            "error FROM ft_lists WHERE username = $1 ORDER BY category, id", child["username"])
        others = [c for c in await db.list_children(conn, families=fams)
                  if c["username"] != child["username"]]
        families = await db.list_families(conn, fams)
    return page(request, "child.html", u, **v, s=policy.child_settings(child["settings"]),
                subs=subs, counts=lists.counts(eff), categories=lists.CATEGORIES,
                policy_limit=lists.POLICY_LIMIT, others=others, families=families)


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
        await child_access(conn, u, username)
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
        await child_access(conn, u, username)
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
        await child_access(conn, u, username)
        r = await conn.fetchrow(
            "DELETE FROM ft_bonus WHERE id = $1 AND username = $2 AND day = $3 RETURNING minutes",
            bonus_id, username, now_local(request).date())
    url = ret if ret.startswith("/") else f"/child/{username}"
    if not r:
        return back(url, err="Корректировка не найдена или уже не сегодняшняя")
    return back(url, ok=f"Отменено: {r['minutes']:+d} мин")


@router.post("/child/{username}/settings")
async def child_account(request: Request, username: str, display_name: str = Form(...),
                        enabled: str = Form(""), email: str = Form(""), aliases: str = Form(""),
                        family_id: str = Form(""), csrf: str = Form("")):
    """Учётная запись: имя, почта для входа в портал, дополнительные логины Windows, семья."""
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    url = f"/child/{username}"
    email = email.strip().lower()
    if email and not _EMAIL.match(email):
        return back(url, err="Почта указана неверно")
    names = []
    for a in re.split(r"[\s,;]+", aliases.strip()):
        a = norm_login(a)
        if a and a != username and a not in names:
            names.append(a)
    async with request.app.state.pool.acquire() as conn:
        child = await child_access(conn, u, username)
        if email and await conn.fetchval(
                "SELECT 1 FROM ft_children WHERE lower(email) = $1 AND username <> $2", email, username):
            return back(url, err="Эта почта уже указана у другого ребёнка")
        for a in names:
            clash = await conn.fetchval(
                "SELECT username FROM ft_children WHERE username <> $2 AND "
                "(username = $1 OR aliases @> to_jsonb($1::text))", a, username)
            if clash:
                return back(url, err=f"Логин Windows «{a}» уже занят другим ребёнком")
        fid = child["family_id"]
        if u.admin and family_id.strip().isdigit():
            fid = int(family_id)
            await family_access(conn, u, fid)
        await conn.execute(
            """UPDATE ft_children SET display_name = $2, enabled = $3, email = $4, aliases = $5,
               family_id = $6 WHERE username = $1""",
            username, display_name.strip() or username, enabled == "1", email, names, fid)
    return back(url, ok="Сохранено")


@router.post("/child/{username}/lists")
async def child_lists(request: Request, username: str):
    """Сайты, программы, протоколы, простой и предупреждения — настройки этого ребёнка."""
    u = need_parent(request)
    form = await request.form()
    auth.check_csrf(request, u, str(form.get("csrf", "")))
    url = f"/child/{username}"
    async with request.app.state.pool.acquire() as conn:
        child = await child_access(conn, u, username)
        st = policy.child_settings(child["settings"])
        for key, kind in policy.CHILD_LIST_KEYS.items():
            if key in form:
                st[key] = policy.clean_list(str(form.get(key, "")), kind)
        try:
            if "idle_minutes" in form:
                st["idle_minutes"] = max(0, min(120, int(form.get("idle_minutes") or 0)))
            if "warn_minutes" in form:
                st["warn_minutes"] = sorted(
                    {max(1, min(60, int(x))) for x in
                     str(form.get("warn_minutes", "")).replace(",", " ").split()}, reverse=True)
        except ValueError:
            return back(url, err="Неверное число")
        await conn.execute("UPDATE ft_children SET settings = $2 WHERE username = $1", username, st)
    return back(url, ok="Сохранено. Компьютеры получат изменения в течение минуты")


@router.post("/child/{username}/copy")
async def child_copy(request: Request, username: str):
    """Копирует настройки ребёнка (сайты, программы, протоколы, простой, предупреждения,
    подписки) другим детям, которых видит пользователь. Лимиты, почта и логины не копируются."""
    u = need_parent(request)
    form = await request.form()
    auth.check_csrf(request, u, str(form.get("csrf", "")))
    targets = [str(t).lower() for t in form.getlist("target")]
    url = f"/child/{username}"
    if not targets:
        return back(url, err="Отметьте, кому скопировать")
    async with request.app.state.pool.acquire() as conn:
        src = await child_access(conn, u, username)
        async with conn.transaction():
            done = []
            for t in targets:
                if t == username:
                    continue
                dst = await child_access(conn, u, t)
                await conn.execute("UPDATE ft_children SET settings = $2 WHERE username = $1",
                                   t, policy.child_settings(src["settings"]))
                await conn.execute("DELETE FROM ft_lists WHERE username = $1", t)
                await conn.execute(
                    """INSERT INTO ft_lists (username, category, name, url, enabled, interval_hours,
                       entries, count, last_fetch, last_ok, error, etag, last_modified)
                       SELECT $2, category, name, url, enabled, interval_hours, entries, count,
                              last_fetch, last_ok, error, etag, last_modified
                       FROM ft_lists WHERE username = $1""", username, t)
                done.append(dst["display_name"])
    return back(url, ok="Настройки скопированы: " + ", ".join(done))


@router.post("/child/{username}/delete")
async def child_delete(request: Request, username: str, csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    async with request.app.state.pool.acquire() as conn:
        await child_access(conn, u, username)
        await conn.execute("DELETE FROM ft_children WHERE username = $1", username)
    return back("/dashboard", ok="Удалено вместе со статистикой")


# ---------- родитель: подписки ребёнка ----------

@router.post("/child/{username}/subs")
async def sub_add(request: Request, username: str, category: str = Form(...), url: str = Form(...),
                  name: str = Form(""), interval_hours: int = Form(24), csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    page_url = f"/child/{username}"
    url = url.strip()
    if category not in lists.CATEGORIES:
        return back(page_url, err="Неизвестный тип списка")
    if not url.lower().startswith(("http://", "https://")):
        return back(page_url, err="Ссылка должна начинаться с http:// или https://")
    interval_hours = max(1, min(720, interval_hours))
    async with request.app.state.pool.acquire() as conn:
        await child_access(conn, u, username)
        lid = await conn.fetchval(
            """INSERT INTO ft_lists (username, category, url, name, interval_hours)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (username, category, url) DO UPDATE SET name = EXCLUDED.name,
               interval_hours = EXCLUDED.interval_hours, enabled = true RETURNING id""",
            username, category, url[:1000], (name.strip() or url)[:200], interval_hours)
    msg = await lists.fetch_one(request.app.state.pool, request.app.state.http, lid)
    if msg.startswith("Ошибка"):
        return back(page_url, err="Список добавлен, но не загрузился. " + msg)
    return back(page_url, ok="Список добавлен. " + msg)


@router.post("/child/{username}/subs/{list_id}")
async def sub_action(request: Request, username: str, list_id: int, action: str = Form(...),
                     interval_hours: int = Form(24), csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    page_url = f"/child/{username}"
    pool = request.app.state.pool
    async with pool.acquire() as conn:
        await child_access(conn, u, username)
        if not await conn.fetchval("SELECT 1 FROM ft_lists WHERE id = $1 AND username = $2",
                                   list_id, username):
            return back(page_url, err="Подписка не найдена")
        if action == "delete":
            await conn.execute("DELETE FROM ft_lists WHERE id = $1", list_id)
            return back(page_url, ok="Подписка удалена")
        if action in ("enable", "disable"):
            await conn.execute("UPDATE ft_lists SET enabled = $2 WHERE id = $1", list_id,
                               action == "enable")
            return back(page_url, ok="Включена" if action == "enable" else "Выключена")
        if action == "interval":
            await conn.execute("UPDATE ft_lists SET interval_hours = $2 WHERE id = $1", list_id,
                               max(1, min(720, interval_hours)))
            return back(page_url, ok="Интервал обновления сохранён")
        if action == "refresh":                    # принудительно, без If-None-Match
            await conn.execute("UPDATE ft_lists SET etag = '', last_modified = '' WHERE id = $1",
                               list_id)
    if action == "refresh":
        msg = await lists.fetch_one(pool, request.app.state.http, list_id)
        return back(page_url, **({"err": msg} if msg.startswith("Ошибка") else {"ok": msg}))
    return back(page_url, err="Неизвестное действие")


# ---------- семьи ----------

@router.get("/family")
async def family_page(request: Request):
    u = need_parent(request)
    async with request.app.state.pool.acquire() as conn:
        fams = await scope(conn, u)
        families = await db.list_families(conn, fams)
        kids = await db.list_children(conn, families=fams)
        orphans = [c for c in await db.list_children(conn) if c["family_id"] is None] \
            if u.admin else []
    return page(request, "family.html", u, families=families, kids=kids, orphans=orphans,
                msg=policy.family_messages)


@router.post("/families")
async def family_create(request: Request, name: str = Form(...), parent: str = Form(""),
                        csrf: str = Form("")):
    u = need_admin(request)
    auth.check_csrf(request, u, csrf)
    async with request.app.state.pool.acquire() as conn:
        await db.create_family(conn, name, norm_login(parent) or None)
    return back("/family", ok="Семья создана")


@router.post("/family/{family_id}")
async def family_save(request: Request, family_id: int):
    u = need_parent(request)
    form = await request.form()
    auth.check_csrf(request, u, str(form.get("csrf", "")))
    section = str(form.get("section", ""))
    async with request.app.state.pool.acquire() as conn:
        fam = await family_access(conn, u, family_id)
        if section == "name":
            await conn.execute("UPDATE ft_families SET name = $2 WHERE id = $1", family_id,
                               str(form.get("name", "")).strip()[:100] or fam["name"])
        elif section == "messages":
            msgs = {k: str(form.get(k, "")).strip()[:1000] for k in policy.FAMILY_MESSAGE_KEYS}
            await conn.execute("UPDATE ft_families SET messages = $2 WHERE id = $1", family_id,
                               {k: v for k, v in msgs.items() if v})
        elif section == "telegram":
            chats = [c for c in re.split(r"[\s,;]+", str(form.get("telegram_chats", "")))
                     if re.fullmatch(r"-?\d{3,20}", c)]
            await conn.execute("UPDATE ft_families SET telegram_chats = $2 WHERE id = $1",
                               family_id, chats[:10])
        elif section == "add_parent":
            login = norm_login(str(form.get("parent", "")))
            if not login:
                return back("/family", err="Укажите логин родителя (как в Keycloak)")
            await conn.execute("INSERT INTO ft_family_parents VALUES ($1, $2) ON CONFLICT DO NOTHING",
                               family_id, login)
        elif section == "remove_parent":
            login = norm_login(str(form.get("parent", "")))
            if login == u.username and not u.admin:
                return back("/family", err="Себя убрать нельзя: попросите другого родителя или "
                                           "администратора")
            await conn.execute("DELETE FROM ft_family_parents WHERE family_id = $1 AND username = $2",
                               family_id, login)
        elif section == "delete":
            if not u.admin:
                raise HTTPException(403, "Удалить семью может только администратор")
            await conn.execute("DELETE FROM ft_families WHERE id = $1", family_id)
            return back("/family", ok="Семья удалена. Её дети и компьютеры остались без семьи: "
                                      "их видит только администратор")
        else:
            return back("/family", err="Неизвестное действие")
    return back("/family", ok="Сохранено")


# ---------- администратор: общие настройки ----------

@router.get("/settings")
async def settings_page(request: Request):
    u = need_admin(request)
    async with request.app.state.pool.acquire() as conn:
        s = await db.get_settings(conn)
    return page(request, "settings.html", u, s=s,
                ip_locations=locator.format_ip_locations(s["ip_locations"]))


@router.post("/settings")
async def settings_save(request: Request):
    u = need_admin(request)
    form = await request.form()
    auth.check_csrf(request, u, str(form.get("csrf", "")))
    try:
        loc = {"interval_minutes": max(1, min(240, int(form.get("interval_minutes", 15)))),
               "lost_interval_minutes": max(1, min(60, int(form.get("lost_interval_minutes", 2))))}
    except ValueError:
        return back("/settings", err="Неверное число")
    lost = str(form.get("lost", "")).strip()[:1000] or policy.DEFAULT_SETTINGS["messages"]["lost"]
    known, errors = locator.parse_ip_locations(str(form.get("ip_locations", "")))
    if errors:
        return back("/settings", err="Известные адреса, не разобрано: " + "; ".join(errors[:3]))
    async with request.app.state.pool.acquire() as conn:
        s = await db.get_settings(conn)
        await db.set_setting(conn, "ip_locations", known[:500], u.username)
        await db.set_setting(conn, "location", loc, u.username)
        await db.set_setting(conn, "messages", {**s["messages"], "lost": lost}, u.username)
    return back("/settings", ok="Сохранено. Компьютеры получат изменения в течение минуты")


# ---------- компьютеры ----------

async def device_access(conn, u: auth.User, dev_id: UUID):
    dev = await conn.fetchrow("SELECT * FROM ft_devices WHERE id = $1", dev_id)
    fams = await scope(conn, u)
    if not dev or (fams is not None and dev["family_id"] not in fams):
        raise HTTPException(404, "Нет такого компьютера")
    return dev


@router.get("/devices")
async def devices_page(request: Request):
    u = need_parent(request)
    async with request.app.state.pool.acquire() as conn:
        fams = await scope(conn, u)
        if fams is None:
            devs = await conn.fetch("SELECT * FROM ft_devices ORDER BY hostname")
        else:
            devs = await conn.fetch(
                "SELECT * FROM ft_devices WHERE family_id = ANY($1::bigint[]) ORDER BY hostname", fams)
        families = await db.list_families(conn, fams)
    return page(request, "devices.html", u, devices=devs, families=families,
                fam_names={f["id"]: f["name"] for f in families}, now=datetime.now(timezone.utc))


@router.post("/devices/{dev_id}")
async def device_save(request: Request, dev_id: UUID, mode: str = Form("control"),
                      lost: str = Form(""), lost_lock: str = Form(""), lost_message: str = Form(""),
                      family_id: str = Form(""), csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    mode = mode if mode in ("control", "track") else "control"
    async with request.app.state.pool.acquire() as conn:
        dev = await device_access(conn, u, dev_id)
        fid = dev["family_id"]
        if u.admin:                                  # семью компьютера меняет только админ
            fid = int(family_id) if family_id.strip().isdigit() else None
        await conn.execute(
            """UPDATE ft_devices SET mode = $2, lost = $3, lost_lock = $4, lost_message = $5,
               family_id = $6 WHERE id = $1""",
            dev_id, mode, lost == "1", lost_lock == "1", lost_message.strip()[:500], fid)
    return back("/devices", ok="Сохранено")


@router.post("/devices/{dev_id}/delete")
async def device_delete(request: Request, dev_id: UUID, csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    async with request.app.state.pool.acquire() as conn:
        await device_access(conn, u, dev_id)
        await conn.execute("DELETE FROM ft_devices WHERE id = $1", dev_id)
    return back("/devices", ok="Удалено. Агент на компьютере зарегистрируется заново при следующем запуске")


# ---------- запросы времени ----------

@router.get("/requests")
async def requests_page(request: Request):
    u = need_parent(request)
    async with request.app.state.pool.acquire() as conn:
        fams = await scope(conn, u)
        q = """SELECT r.*, c.display_name FROM ft_requests r JOIN ft_children c USING (username)
               {where} ORDER BY (r.status = 'pending') DESC, r.created_at DESC LIMIT 50"""
        if fams is None:
            rows = await conn.fetch(q.format(where=""))
        else:
            rows = await conn.fetch(q.format(where="WHERE c.family_id = ANY($1::bigint[])"), fams)
    return page(request, "requests.html", u, rows=rows)


@router.post("/requests/{req_id}")
async def request_decide(request: Request, req_id: int, action: str = Form(...),
                         csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    async with request.app.state.pool.acquire() as conn:
        who = await conn.fetchval("SELECT username FROM ft_requests WHERE id = $1", req_id)
        if not who:
            return back("/requests", err="Запрос не найден")
        await child_access(conn, u, who)
    msg = await requests_logic.decide(request.app.state.pool, request.app.state.cfg,
                                      request.app.state.tg, req_id, action == "approve", u.username)
    return back("/requests", ok=msg)
