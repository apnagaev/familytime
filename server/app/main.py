"""Точка входа FastAPI."""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, agent_api, auth, db, lists, phones, portal
from .config import Config
from .telegram import Telegram

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("familytime")


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or Config.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        problems = cfg.check()
        if problems:
            raise RuntimeError("Не заданы переменные: " + ", ".join(problems))
        app.state.cfg = cfg
        app.state.http = httpx.AsyncClient(follow_redirects=False)
        app.state.pool = await db.create_pool(cfg.database_url)
        app.state.oidc = auth.OIDC(cfg, app.state.http)
        app.state.tg = Telegram(cfg, app.state.http, app.state.pool)
        task = asyncio.create_task(app.state.tg.run())
        lists_task = asyncio.create_task(lists.updater(app.state.pool, app.state.http))
        log.info("familytime %s запущен", __version__)
        try:
            yield
        finally:
            task.cancel()
            lists_task.cancel()
            await app.state.pool.close()
            await app.state.http.aclose()

    app = FastAPI(title="FamilyTime", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(agent_api.router)
    app.include_router(phones.router)
    app.include_router(portal.router)
    app.mount("/static", StaticFiles(directory=str(Path(__file__).with_name("static"))), name="static")

    kind_cache: dict[str, tuple[float, str]] = {}
    app.state.kind_cache = kind_cache        # очищается при смене типа семьи

    async def user_kind(request: Request, user) -> str | None:
        """Тип групп пользователя: семьи родителя и семья ребёнка. Разные — None."""
        hit = kind_cache.get(user.username)
        if hit and time.monotonic() - hit[0] < 30:
            return hit[1] or None
        async with request.app.state.pool.acquire() as conn:
            kinds = {r["kind"] for r in await conn.fetch(
                """SELECT f.kind FROM ft_families f
                   JOIN ft_family_parents p ON p.family_id = f.id WHERE p.username = $1
                   UNION
                   SELECT f.kind FROM ft_families f JOIN ft_children c ON c.family_id = f.id
                   WHERE c.username = $1 OR (c.email <> '' AND lower(c.email) = $2)""",
                user.username, user.email or "-")}
        kind = kinds.pop() if len(kinds) == 1 else ""
        kind_cache[user.username] = (time.monotonic(), kind)
        return kind or None

    @app.middleware("http")
    async def portal_kind(request: Request, call_next):
        """Семья или компания для страниц портала: у администратора — выбранная вкладка,
        у родителя и ребёнка — тип их групп, иначе — по имени сайта (COMPANY_HOSTS)."""
        if not request.url.path.startswith(("/api/", "/osmand", "/static", "/health")):
            host = (request.headers.get("host") or "").split(":")[0].lower()
            kind = "company" if host in cfg.company_hosts else "family"
            user = auth.current_user(request)
            try:
                if user and user.admin:
                    tab = request.cookies.get("ft_kind")
                    kind = tab if tab in ("family", "company") else kind
                elif user:
                    kind = await user_kind(request, user) or kind
            except Exception:  # noqa: BLE001 — слова не важнее страницы
                pass
            request.state.kind = kind
        return await call_next(request)

    @app.exception_handler(portal.LoginRequired)
    async def _login(request: Request, exc: portal.LoginRequired):
        return RedirectResponse("/login?next=" + exc.next_url, 302)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith("/api/") or request.url.path == "/health":
            return JSONResponse({"detail": exc.detail}, exc.status_code)
        kind = getattr(request.state, "kind", None) or "family"
        t = portal.company_templates if kind == "company" else portal.templates
        return t.TemplateResponse(
            request, "error.html",
            {"request": request, "user": auth.current_user(request), "code": exc.status_code,
             "detail": exc.detail, "cfg": cfg, "flash": "", "err": "", "kind": kind,
             "kind_labels": portal.KIND_LABELS, "kind_options": portal.KIND_OPTIONS},
            status_code=exc.status_code)

    @app.get("/health")
    async def health(request: Request):
        async with request.app.state.pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"ok": True, "version": __version__}

    return app


app = create_app()
