"""Приём точек Traccar Client (протокол OsmAnd).

Телефон шлёт точки на https://<портал>/osmand — FamilyTime пересылает запрос в Traccar как
есть (метод, параметры, тело) и, если телефон в списке «Телефоны» общих настроек, запоминает
его точку вместе с сетью, из которой она пришла. Компьютер из той же сети в ближайшие
минуты получает это место вместо известного адреса или Wi-Fi — точнее и без запросов к API.

/osmand/mirror — то же без пересылки: для nginx `mirror`, когда телефоны по-прежнему шлют
точки прямо в Traccar, а сюда приходит копия.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import Response

from . import db, locator
from .agent_api import client_ip

log = logging.getLogger("familytime.phones")
router = APIRouter()

KEEP_DAYS = 2
HOP_HEADERS = {"host", "content-length", "connection", "keep-alive", "transfer-encoding",
               "te", "trailer", "upgrade", "proxy-authorization", "proxy-authenticate",
               "x-real-ip", "x-forwarded-for"}


def _num(v) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f == f else None             # NaN


def parse_point(query: dict, body: bytes, content_type: str) -> dict | None:
    """id, lat, lon, accuracy из параметров, формы или JSON (новые версии Traccar Client)."""
    p = {k: v[-1] for k, v in query.items()}
    ct = (content_type or "").split(";")[0].strip().lower()
    if body and ct == "application/x-www-form-urlencoded":
        p.update({k: v[-1] for k, v in parse_qs(body.decode("utf-8", "replace")).items()})
    elif body and (ct == "application/json" or body[:1] in (b"{", b"[")):
        try:
            j = json.loads(body)
        except ValueError:
            j = None
        if isinstance(j, dict):
            loc = j.get("location") if isinstance(j.get("location"), dict) else j
            coords = loc.get("coords") if isinstance(loc.get("coords"), dict) else loc
            p.setdefault("id", j.get("device_id") or j.get("deviceid") or j.get("id"))
            p.setdefault("lat", coords.get("latitude", coords.get("lat")))
            p.setdefault("lon", coords.get("longitude", coords.get("lon")))
            p.setdefault("accuracy", coords.get("accuracy"))
    dev = str(p.get("id") or p.get("deviceid") or "").strip()
    lat, lon = _num(p.get("lat")), _num(p.get("lon"))
    if (lat is None or lon is None) and p.get("location"):
        parts = str(p["location"]).split(",")
        if len(parts) == 2:
            lat, lon = _num(parts[0]), _num(parts[1])
    if not dev or lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    if lat == 0 and lon == 0:
        return None
    if str(p.get("valid", "true")).lower() in ("false", "0"):
        return None
    acc = _num(p.get("accuracy"))
    return {"id": dev, "lat": lat, "lon": lon, "accuracy": acc if acc is not None else 9999.0}


async def remember(request: Request, point: dict | None, ip: str) -> bool:
    if not point:
        return False
    async with request.app.state.pool.acquire() as conn:
        settings = await db.get_settings(conn)
        allowed = {x.lower() for x in settings.get("phone_ids", [])}
        key = locator.net_key(ip)
        if point["id"].lower() not in allowed or not key:
            return False
        await conn.execute(
            "INSERT INTO ft_phone_fixes (net, device, lat, lon, accuracy, at) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            key, point["id"][:100], point["lat"], point["lon"], point["accuracy"],
            datetime.now(timezone.utc))
        await conn.execute(
            "DELETE FROM ft_phone_fixes WHERE at < now() - make_interval(days => $1)", KEEP_DAYS)
    return True


async def _handle(request: Request, forward: bool) -> Response:
    cfg = request.app.state.cfg
    body = await request.body()
    ip = client_ip(request)
    point = parse_point(parse_qs(request.url.query), body, request.headers.get("content-type", ""))
    try:
        await remember(request, point, ip)
    except Exception as e:  # noqa: BLE001 — точка в Traccar важнее
        log.warning("точка телефона не сохранена: %s", e)
    if not forward:
        return Response(status_code=200)
    target = cfg.osmand_forward_url or cfg.traccar_osmand_url
    if not target:
        return Response(status_code=503)
    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_HEADERS}
    headers["X-Real-IP"] = ip
    headers["X-Forwarded-For"] = ip
    try:
        r = await request.app.state.http.request(
            request.method, target + "/", params=request.url.query or None, content=body,
            headers=headers, timeout=15)
    except httpx.HTTPError as e:
        log.warning("пересылка в Traccar: %s", e)
        return Response(status_code=502)
    return Response(content=r.content, status_code=r.status_code,
                    media_type=r.headers.get("content-type"))


@router.api_route("/osmand", methods=["GET", "POST"])
async def osmand(request: Request):
    return await _handle(request, forward=True)


@router.api_route("/osmand/mirror", methods=["GET", "POST"])
async def osmand_mirror(request: Request):
    return await _handle(request, forward=False)
