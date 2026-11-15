"""Установка и обновление агента на компьютерах вне домена.

Администратор загружает в общих настройках архив агента (FamilyTime-<версия>.zip из build.ps1),
он хранится в базе. Родитель на странице «Компьютеры» скачивает файл FamilyTime-setup.cmd со
своим кодом установки (действует 7 дней, на любое число компьютеров его семьи). Файл
запускается двойным щелчком: просит права администратора, скачивает setup.ps1 и пакет с
портала, проверяет контрольную сумму и ставит службу. Компьютер регистрируется по коду сразу
в семье родителя. Дальше агент (с 1.4.0) обновляется сам, когда администратор загружает
новую версию; тот же файл можно запустить ещё раз — он обновит агент, не меняя настроек.
"""
from __future__ import annotations

import hashlib
import io
import logging
import re
import secrets
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse, Response

from . import auth
from .portal import back, list_scope, need_admin, need_parent

log = logging.getLogger("familytime.dist")
router = APIRouter()

CODE_DAYS = 7
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"     # без 0/O и 1/I
MAX_PACKAGE = 300 * 1024 * 1024
KEEP_PACKAGES = 3
SETUP_PS1 = Path(__file__).with_name("agent_files") / "setup.ps1"


def vtuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4]) or (0,)


# ---------- коды установки ----------

def norm_code(code: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (code or "").upper())


def code_hash(code: str) -> str:
    return hashlib.sha256(("ft-install:" + norm_code(code)).encode()).hexdigest()


def new_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(12))
    return "-".join(raw[i:i + 4] for i in range(0, 12, 4))


async def find_code(conn, code: str):
    """Действующий код установки или None."""
    if len(norm_code(code)) != 12:
        return None
    return await conn.fetchrow(
        """SELECT c.*, f.name AS family_name FROM ft_install_codes c
           LEFT JOIN ft_families f ON f.id = c.family_id
           WHERE c.code_hash = $1 AND NOT c.revoked AND c.expires_at > now()""",
        code_hash(code))


async def use_code(conn, row) -> None:
    await conn.execute("UPDATE ft_install_codes SET uses = uses + 1, last_used = now() "
                       "WHERE id = $1", row["id"])


def setup_cmd(url: str, code: str, mode: str) -> str:
    """Файл для двойного щелчка: только ASCII, строки CRLF — так его понимает любой cmd."""
    lines = [
        "@echo off",
        "rem FamilyTime: install or update the agent. Double-click this file.",
        "setlocal",
        f'set "FT_URL={url}"',
        f'set "FT_CODE={code}"',
        f'set "FT_MODE={mode}"',
        "net session >nul 2>&1",
        "if errorlevel 1 (",
        "  powershell -NoProfile -Command \"Start-Process -FilePath '%~f0' -Verb RunAs\"",
        "  exit /b",
        ")",
        "powershell -NoProfile -ExecutionPolicy Bypass -Command \""
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
        "$w=New-Object Net.WebClient;$w.Encoding=[Text.Encoding]::UTF8;"
        "iex $w.DownloadString($env:FT_URL+'/agent/setup.ps1')\"",
        "echo.",
        "pause",
    ]
    return "\r\n".join(lines) + "\r\n"


# ---------- пакет агента ----------

async def latest_meta(conn):
    rows = await conn.fetch("SELECT version, sha256, size, uploaded_at, uploaded_by "
                            "FROM ft_agent_packages")
    return max(rows, key=lambda r: vtuple(r["version"]), default=None)


def inspect_zip(data: bytes) -> str:
    """Версия из архива build.ps1 или ValueError с понятной причиной."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError("это не zip-архив") from None
    names = {n.replace("\\", "/") for n in z.namelist()}
    for need in ("install.ps1", "FamilyTime/familytime-agent.exe", "FamilyTime/version.txt"):
        if need not in names:
            raise ValueError(f"в архиве нет {need} — нужен FamilyTime-<версия>.zip из build.ps1")
    ver = z.read("FamilyTime/version.txt").decode("utf-8-sig", "replace").strip()
    if not re.fullmatch(r"\d+(\.\d+){1,3}", ver):
        raise ValueError(f"непонятная версия в version.txt: {ver[:20]!r}")
    return ver


async def package_bytes(request: Request) -> tuple[dict, bytes] | None:
    """Последний пакет: метаданные и содержимое (в памяти процесса, пока версия та же)."""
    async with request.app.state.pool.acquire() as conn:
        meta = await latest_meta(conn)
        if not meta:
            return None
        cache = getattr(request.app.state, "agent_pkg", None)
        if not cache or cache[0] != meta["sha256"]:
            data = await conn.fetchval("SELECT data FROM ft_agent_packages WHERE version = $1",
                                       meta["version"])
            cache = (meta["sha256"], bytes(data))
            request.app.state.agent_pkg = cache
    return dict(meta), cache[1]


# ---------- для установщика (без входа) ----------

@router.get("/agent/setup.ps1")
async def agent_setup_ps1():
    return PlainTextResponse(SETUP_PS1.read_text(encoding="utf-8"),
                             media_type="text/plain; charset=utf-8",
                             headers={"Cache-Control": "no-store"})


@router.get("/agent/latest")
async def agent_latest(request: Request, code: str = ""):
    async with request.app.state.pool.acquire() as conn:
        meta = await latest_meta(conn)
        row = await find_code(conn, code) if code else None
    out = {"version": meta["version"], "sha256": meta["sha256"], "size": meta["size"]} \
        if meta else {"version": ""}
    if code:
        out["code_ok"] = bool(row)
        if row:
            out.update(family=row["family_name"] or "", mode=row["mode"])
    return out


@router.get("/agent/package.zip")
async def agent_package(request: Request):
    got = await package_bytes(request)
    if not got:
        raise HTTPException(404, "пакет агента не загружен")
    meta, data = got
    return Response(data, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="FamilyTime-{meta["version"]}.zip"',
        "X-Agent-Version": meta["version"], "X-Agent-Sha256": meta["sha256"]})


# ---------- портал ----------

@router.post("/settings/agent")
async def agent_upload(request: Request, package: UploadFile = File(...), csrf: str = Form("")):
    u = need_admin(request)
    auth.check_csrf(request, u, csrf)
    data = await package.read(MAX_PACKAGE + 1)
    if len(data) > MAX_PACKAGE:
        return back("/settings", err="Архив больше 300 МБ")
    try:
        ver = inspect_zip(data)
    except ValueError as e:
        return back("/settings", err=f"Пакет не принят: {e}")
    sha = hashlib.sha256(data).hexdigest()
    async with request.app.state.pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO ft_agent_packages (version, sha256, size, data, uploaded_by)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (version) DO UPDATE SET sha256 = EXCLUDED.sha256, size = EXCLUDED.size,
               data = EXCLUDED.data, uploaded_at = now(), uploaded_by = EXCLUDED.uploaded_by""",
            ver, sha, len(data), data, u.username)
        rows = await conn.fetch("SELECT version FROM ft_agent_packages")
        old = sorted((r["version"] for r in rows), key=vtuple)[:-KEEP_PACKAGES]
        if old:
            await conn.execute("DELETE FROM ft_agent_packages WHERE version = ANY($1::text[])", old)
    request.app.state.agent_pkg = None
    log.info("загружен пакет агента %s (%d байт) — %s", ver, len(data), u.username)
    return back("/settings", ok=f"Агент {ver} загружен. Компьютеры с агентом 1.4 и новее "
                               "обновятся сами в течение нескольких минут")


@router.post("/devices/installer")
async def installer(request: Request, family_id: str = Form(""), mode: str = Form("control"),
                    csrf: str = Form("")):
    """Новый код установки и файл FamilyTime-setup.cmd с ним."""
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    mode = mode if mode in ("control", "track") else "control"
    async with request.app.state.pool.acquire() as conn:
        if not await latest_meta(conn):
            return back("/devices", err="Администратор ещё не загрузил агент в общих настройках")
        fams = await list_scope(conn, u, request)
        fid = int(family_id) if family_id.strip().isdigit() else (fams[0] if fams else None)
        if fid is None and not u.admin:
            return back("/devices", err="Сначала добавьте ребёнка — семья создастся сама")
        if fid is not None and fid not in fams:
            raise HTTPException(403)
        code = new_code()
        await conn.execute(
            """INSERT INTO ft_install_codes (code_hash, family_id, mode, created_by, expires_at)
               VALUES ($1, $2, $3, $4, $5)""",
            code_hash(code), fid, mode, u.username,
            datetime.now(timezone.utc) + timedelta(days=CODE_DAYS))
    url = request.app.state.cfg.base_url(request.headers.get("host"))
    return Response(setup_cmd(url, code, mode).encode("ascii"), media_type="application/octet-stream",
                    headers={"Content-Disposition": 'attachment; filename="FamilyTime-setup.cmd"',
                             "Cache-Control": "no-store"})


@router.post("/devices/codes/{code_id}/revoke")
async def code_revoke(request: Request, code_id: int, csrf: str = Form("")):
    u = need_parent(request)
    auth.check_csrf(request, u, csrf)
    async with request.app.state.pool.acquire() as conn:
        fams = await list_scope(conn, u, request)
        r = await conn.execute(
            """UPDATE ft_install_codes SET revoked = true WHERE id = $1
               AND (family_id = ANY($2::bigint[]) OR ($3 AND family_id IS NULL))""",
            code_id, fams, u.admin)
    if r.endswith(" 0"):
        return back("/devices", err="Код не найден")
    return back("/devices", ok="Код отозван: скачанными с ним файлами больше нельзя установить "
                               "агент на новый компьютер")


async def devices_extra(conn, u, fams: list[int]) -> dict:
    """Для страницы «Компьютеры»: версия агента на сервере и действующие коды."""
    meta = await latest_meta(conn)
    codes = await conn.fetch(
        """SELECT c.id, c.mode, c.created_by, c.created_at, c.expires_at, c.uses, c.last_used,
                  f.name AS family_name
           FROM ft_install_codes c LEFT JOIN ft_families f ON f.id = c.family_id
           WHERE NOT c.revoked AND c.expires_at > now()
             AND (c.family_id = ANY($1::bigint[]) OR ($2 AND c.family_id IS NULL))
           ORDER BY c.created_at DESC LIMIT 20""", fams, u.admin)
    return {"agent_meta": meta, "codes": codes}


async def settings_extra(conn) -> dict:
    return {"agent_meta": await latest_meta(conn),
            "agent_versions": await conn.fetch(
                "SELECT version, size, uploaded_at, uploaded_by FROM ft_agent_packages "
                "ORDER BY uploaded_at DESC")}


async def update_offer(conn, settings: dict, caps: list[str], version: str) -> dict | None:
    """Предложение обновиться для агентов, которые умеют обновляться сами (caps: update)."""
    if "update" not in caps or not settings.get("auto_update", True):
        return None
    meta = await latest_meta(conn)
    if not meta or vtuple(meta["version"]) <= vtuple(version):
        return None
    return {"version": meta["version"], "sha256": meta["sha256"], "size": meta["size"],
            "url": "/agent/package.zip"}


__all__ = ["router", "find_code", "use_code", "update_offer", "devices_extra", "settings_extra"]
