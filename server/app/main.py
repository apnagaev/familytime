"""Точка входа FastAPI."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, agent_api, auth, db, lists, portal
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
    app.include_router(portal.router)
    app.mount("/static", StaticFiles(directory=str(Path(__file__).with_name("static"))), name="static")

    @app.exception_handler(portal.LoginRequired)
    async def _login(request: Request, exc: portal.LoginRequired):
        return RedirectResponse("/login?next=" + exc.next_url, 302)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith("/api/") or request.url.path == "/health":
            return JSONResponse({"detail": exc.detail}, exc.status_code)
        return portal.templates.TemplateResponse(
            request, "error.html",
            {"request": request, "user": auth.current_user(request), "code": exc.status_code,
             "detail": exc.detail, "cfg": cfg, "flash": "", "err": ""},
            status_code=exc.status_code)

    @app.get("/health")
    async def health(request: Request):
        async with request.app.state.pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"ok": True, "version": __version__}

    return app


app = create_app()
