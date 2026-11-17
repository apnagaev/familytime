"""Приём точек Traccar Client (протокол OsmAnd).

Телефон шлёт точки на https://<портал>/osmand — FamilyTime пересылает запрос в Traccar
(метод, параметры, тело). Если телефон есть в списке «Телефоны» общих настроек и пришёл
с известного адреса (таблица «Известные адреса», как у компьютеров), координаты точки
заменяются местом из таблицы — с разбросом в пределах её точности, как у ноутбуков.
Остальные точки уходят без изменений.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from urllib.parse import parse_qs, parse_qsl, urlencode

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


def _rewrite_pairs(pairs: list[tuple[str, str]], lat: float, lon: float, acc: float,
                   place: str) -> tuple[list[tuple[str, str]], bool]:
    keys = {k for k, _ in pairs}
    if not ({"lat", "lon"} <= keys or "location" in keys):
        return pairs, False
    out = []
    for k, v in pairs:
        if k == "lat":
            v = f"{lat:.6f}"
        elif k == "lon":
            v = f"{lon:.6f}"
        elif k == "location":
            v = f"{lat:.6f},{lon:.6f}"
        elif k in ("accuracy", "source", "place"):
            continue
        out.append((k, v))
    out += [("accuracy", f"{acc:.0f}"), ("source", "known-ip")]
    if place:
        out.append(("place", place))
    return out, True


def rewrite(query: str, body: bytes, content_type: str, lat: float, lon: float, acc: float,
            place: str) -> tuple[str, bytes]:
    """Подменяет координаты и точность там, где они пришли: в параметрах, форме или JSON."""
    pairs, changed = _rewrite_pairs(parse_qsl(query, keep_blank_values=True), lat, lon, acc, place)
    if changed:
        query = urlencode(pairs)
    ct = (content_type or "").split(";")[0].strip().lower()
    if body and ct == "application/x-www-form-urlencoded":
        pairs, ch = _rewrite_pairs(parse_qsl(body.decode("utf-8", "replace"),
                                             keep_blank_values=True), lat, lon, acc, place)
        if ch:
            body = urlencode(pairs).encode()
    elif body and (ct == "application/json" or body[:1] == b"{"):
        try:
            j = json.loads(body)
        except ValueError:
            j = None
        if isinstance(j, dict):
            loc = j.get("location") if isinstance(j.get("location"), dict) else j
            coords = loc.get("coords") if isinstance(loc.get("coords"), dict) else loc
            for la, lo in (("latitude", "longitude"), ("lat", "lon")):
                if la in coords or lo in coords:
                    coords[la], coords[lo] = round(lat, 6), round(lon, 6)
                    coords["accuracy"] = round(acc)
                    extras = loc.get("extras") if isinstance(loc.get("extras"), dict) else {}
                    extras.update({"source": "known-ip", **({"place": place} if place else {})})
                    loc["extras"] = extras
                    body = json.dumps(j, ensure_ascii=False).encode()
                    break
    return query, body


def set_ip(query: str, body: bytes, content_type: str, ip: str,
           extra: dict | None = None) -> tuple[str, bytes]:
    """Настоящий адрес телефона в точке — как traccar-real-ip.conf перед Traccar: Traccar пишет
    в атрибут ip адрес соединения (здесь это был бы адрес FamilyTime или шлюза Docker), а
    заголовки X-Forwarded-For для точек не читает. JSON → location.extras.ip, параметры в
    адресе → &ip=, иначе form-тело → &ip= (тело Traccar читает, только если в адресе
    параметров нет). Присланный клиентом ip перезаписывается. extra — ещё атрибуты
    (operator), так же."""
    attrs = {k: v for k, v in {"ip": ip, **(extra or {})}.items() if v}
    if not attrs:
        return query, body
    ct = (content_type or "").split(";")[0].strip().lower()
    if body and (ct == "application/json" or body[:1] == b"{"):
        try:
            j = json.loads(body)
        except ValueError:
            j = None
        if isinstance(j, dict):
            loc = j.get("location") if isinstance(j.get("location"), dict) else j
            extras = loc.get("extras") if isinstance(loc.get("extras"), dict) else {}
            extras.update(attrs)
            loc["extras"] = extras
            return query, json.dumps(j, ensure_ascii=False).encode()
    if query or not (body and ct == "application/x-www-form-urlencoded"):
        pairs = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True) if k not in attrs]
        return urlencode(pairs + list(attrs.items())), body
    pairs = [(k, v) for k, v in parse_qsl(body.decode("utf-8", "replace"),
                                          keep_blank_values=True) if k not in attrs]
    return query, urlencode(pairs + list(attrs.items())).encode()


async def refine(request: Request, point: dict | None, ip: str) -> dict | None:
    """Место из «Известных адресов» для телефона из списка; None — точку не трогать.
    Последние точки телефонов из списка видны в общих настройках."""
    if not point:
        return None
    async with request.app.state.pool.acquire() as conn:
        settings = await db.get_settings(conn)
        allowed = {x.lower() for x in settings.get("phone_ids", [])}
        if point["id"].lower() not in allowed:
            return None
        known = locator.match_known(settings.get("ip_locations", []), ip)
        out = None
        if known:
            lat, lon = (locator.jitter(known.lat, known.lon, known.accuracy)
                        if settings.get("jitter", True) else (known.lat, known.lon))
            out = {"lat": lat, "lon": lon, "accuracy": known.accuracy, "place": known.place}
        await conn.execute(
            "INSERT INTO ft_phone_fixes (net, device, lat, lon, accuracy, at, place) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7)",
            ip[:64], point["id"][:100], point["lat"], point["lon"], point["accuracy"],
            datetime.now(timezone.utc), (known.place or "известный адрес") if known else "")
        await conn.execute(
            "DELETE FROM ft_phone_fixes WHERE at < now() - make_interval(days => $1)", KEEP_DAYS)
    return out


async def _handle(request: Request) -> Response:
    cfg = request.app.state.cfg
    body = await request.body()
    ip = client_ip(request)
    query = request.url.query
    ctype = request.headers.get("content-type", "")
    point = parse_point(parse_qs(query), body, ctype)
    try:
        fix = await refine(request, point, ip)
    except Exception as e:  # noqa: BLE001 — точка в Traccar важнее
        log.warning("точка телефона: %s", e)
        fix = None
    if fix:
        query, body = rewrite(query, body, ctype, fix["lat"], fix["lon"], fix["accuracy"],
                              fix["place"])
    op = ""
    if point:
        try:
            async with request.app.state.pool.acquire() as conn:
                op = await locator.operator(request.app.state.http, cfg, conn, ip)
        except Exception as e:  # noqa: BLE001 — точка важнее
            log.info("оператор телефона: %s", e)
    query, body = set_ip(query, body, ctype, ip, {"operator": op})
    target = cfg.osmand_forward_url or cfg.traccar_osmand_url
    if not target:
        return Response(status_code=503)
    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_HEADERS}
    headers["X-Real-IP"] = ip
    headers["X-Forwarded-For"] = ip
    try:
        r = await request.app.state.http.request(
            request.method, target + "/", params=query or None, content=body,
            headers=headers, timeout=15)
    except httpx.HTTPError as e:
        log.warning("пересылка в Traccar: %s", e)
        return Response(status_code=502)
    return Response(content=r.content, status_code=r.status_code,
                    media_type=r.headers.get("content-type"))


@router.api_route("/osmand", methods=["GET", "POST"])
async def osmand(request: Request):
    return await _handle(request)
