"""Приём точек Traccar Client (протокол OsmAnd).

Телефон шлёт точки на https://<портал>/osmand — FamilyTime пересылает запрос в Traccar
(метод, параметры, тело). Если телефон есть в списке «Телефоны» общих настроек и пришёл
с известного адреса (таблица «Известные адреса», как у компьютеров), координаты точки
заменяются местом из таблицы — с разбросом в пределах её точности, как у ноутбуков.
Остальные точки уходят без изменений.

С 1.7 обогащаются только устройства, которые есть хотя бы в одной семье (ft_family_traccar),
остальные идут транзитом. Устройства VPN (префикс из списка «VPN», например wg- от vpngeo)
приходят с сервера WireGuard; их место считается по extip/localip из самой точки — см.
refine_vpn. Телефоны и устройства VPN FamilyTime в Traccar не создаёт.
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


def point_params(query: str, body: bytes, content_type: str) -> dict:
    """Все параметры точки одним словарём, имена в нижнем регистре: адрес, форма или JSON
    (верхний уровень, location, coords, extras)."""
    p = {k.lower(): v for k, v in parse_qsl(query, keep_blank_values=True)}
    ct = (content_type or "").split(";")[0].strip().lower()
    if body and ct == "application/x-www-form-urlencoded":
        p.update({k.lower(): v for k, v in parse_qsl(body.decode("utf-8", "replace"),
                                                       keep_blank_values=True)})
    elif body and (ct == "application/json" or body[:1] == b"{"):
        try:
            j = json.loads(body)
        except ValueError:
            j = None
        if isinstance(j, dict):
            loc = j.get("location") if isinstance(j.get("location"), dict) else {}
            for part in (j, loc, loc.get("coords") or {}, loc.get("extras") or {}):
                if isinstance(part, dict):
                    p.update({str(k).lower(): v for k, v in part.items()
                              if not isinstance(v, (dict, list))})
            p.setdefault("id", j.get("device_id") or j.get("deviceid") or "")
    return p


def is_vpn(device: str, prefixes) -> bool:
    d = (device or "").lower()
    return bool(d) and any(d.startswith(str(x).lower()) for x in prefixes or [] if str(x).strip())


def _rewrite_pairs(pairs: list[tuple[str, str]], lat: float, lon: float, acc: float,
                   place: str, source: str = "known-ip") -> tuple[list[tuple[str, str]], bool]:
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
    out += [("accuracy", f"{acc:.0f}"), ("source", source)]
    if place:
        out.append(("place", place))
    return out, True


def rewrite(query: str, body: bytes, content_type: str, lat: float, lon: float, acc: float,
            place: str, source: str = "known-ip") -> tuple[str, bytes]:
    """Подменяет координаты и точность там, где они пришли: в параметрах, форме или JSON."""
    pairs, changed = _rewrite_pairs(parse_qsl(query, keep_blank_values=True), lat, lon, acc,
                                    place, source)
    if changed:
        query = urlencode(pairs)
    ct = (content_type or "").split(";")[0].strip().lower()
    if body and ct == "application/x-www-form-urlencoded":
        pairs, ch = _rewrite_pairs(parse_qsl(body.decode("utf-8", "replace"),
                                             keep_blank_values=True), lat, lon, acc, place,
                                     source)
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
                    extras.update({"source": source, **({"place": place} if place else {})})
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


async def _journal(conn, net: str, device: str, point: dict, place: str) -> None:
    await conn.execute(
        "INSERT INTO ft_phone_fixes (net, device, lat, lon, accuracy, at, place) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7)",
        net[:64], device[:100], point["lat"], point["lon"], point["accuracy"],
        datetime.now(timezone.utc), place[:60])
    await conn.execute(
        "DELETE FROM ft_phone_fixes WHERE at < now() - make_interval(days => $1)", KEEP_DAYS)


def _spread(settings: dict, fix) -> tuple[float, float]:
    return (locator.jitter(fix.lat, fix.lon, fix.accuracy) if settings.get("jitter", True)
            else (fix.lat, fix.lon))


def refine_phone(settings: dict, ip: str) -> dict | None:
    """Телефон семьи: место из «Известных адресов» по адресу, с которого он пришёл."""
    known = locator.match_known(settings.get("ip_locations", []), ip)
    if not known:
        return None
    lat, lon = _spread(settings, known)
    return {"lat": lat, "lon": lon, "accuracy": known.accuracy, "place": known.place,
            "source": "known-ip"}


async def refine_vpn(request: Request, settings: dict, point: dict | None, params: dict,
                     ip: str) -> tuple[dict | None, str]:
    """Пир VPN (vpngeo): соединение приходит с сервера WireGuard, поэтому сеть берётся из
    параметров точки — localip (адрес в туннеле) и extip (внешний адрес подключения).
    Место: «Известные адреса» (самая узкая подсеть из обоих) → Яндекс Локатор по extip
    (кеш месяц) → служба GeoIP. Своё смещение отправителя игнорируется, разброс — как у
    компьютеров FamilyTime. Возвращает новое место (или None) и внешний адрес."""
    ext = locator.public_ip(str(params.get("extip") or ""))
    local = str(params.get("localip") or "").strip()
    fix = locator.match_known(settings.get("ip_locations", []), local, ext)
    async with request.app.state.pool.acquire() as conn:
        if not fix and ext:
            fix = await locator.ip_location(request.app.state.http, request.app.state.cfg, conn, ext)
    if not fix:
        return None, ext
    lat, lon = _spread(settings, fix)
    return {"lat": lat, "lon": lon, "accuracy": fix.accuracy or locator.GEOIP_ACCURACY,
            "place": fix.place, "source": fix.source}, ext


async def _handle(request: Request) -> Response:
    """Устройство в какой-нибудь семье — точка обогащается (место, ip, operator) и устройство
    показывается на карте пользователей этих семей. Остальные — транзитом: в Traccar как есть,
    только телефонам дописывается их настоящий ip. Устройства телефонов и VPN FamilyTime в
    Traccar не создаёт — их заводят вручную."""
    cfg = request.app.state.cfg
    http = request.app.state.http
    body = await request.body()
    ip = client_ip(request)
    query = request.url.query
    ctype = request.headers.get("content-type", "")
    params = point_params(query, body, ctype)
    device = str(params.get("id") or params.get("deviceid") or "").strip()
    point = parse_point(parse_qs(query), body, ctype)
    attr_ip, fix, op, vpn, fams = ip, None, "", False, []
    try:
        async with request.app.state.pool.acquire() as conn:
            settings = await db.get_settings(conn)
            if device:
                fams = [r["family_id"] for r in await conn.fetch(
                    "SELECT family_id FROM ft_family_traccar WHERE unique_id = $1", device.lower())]
            vpn = is_vpn(device, settings.get("vpn_prefixes"))
            if fams and point:
                if vpn:
                    fix, ext = await refine_vpn(request, settings, point, params, ip)
                    attr_ip = ext or ip
                else:
                    fix = refine_phone(settings, ip)
                op = await locator.operator(http, cfg, conn, attr_ip)
            if point and device:
                await _journal(conn, (str(params.get("extip") or "") if vpn else "") or ip, device,
                               point, ((fix["place"] or fix["source"]) if fix else
                                       ("" if fams else "транзит")))
        if fams and device:
            did = await locator.traccar_device_id(http, cfg, device)
            if did:
                async with request.app.state.pool.acquire() as conn:
                    viewers: list[str] = []
                    for f in fams:
                        viewers += await locator.family_viewers(conn, f)
                    await locator.link_device(http, cfg, conn, device, viewers)
    except Exception as e:  # noqa: BLE001 — точка в Traccar важнее
        log.warning("точка %s: %s", device, e)
    if fix:
        acc = locator.traccar_accuracy(fix.get("source", "known-ip"), fix["accuracy"], fix["place"])
        query, body = rewrite(query, body, ctype, fix["lat"], fix["lon"], acc,
                              fix["place"], fix.get("source", "known-ip"))
    if fams:
        query, body = set_ip(query, body, ctype, attr_ip, {"operator": op})
    elif not vpn:
        # транзит: только настоящий адрес телефона (иначе Traccar записал бы адрес FamilyTime)
        query, body = set_ip(query, body, ctype, ip)
    target = cfg.osmand_forward_url or cfg.traccar_osmand_url
    if not target:
        return Response(status_code=503)
    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_HEADERS}
    headers["X-Real-IP"] = attr_ip
    headers["X-Forwarded-For"] = attr_ip
    try:
        r = await http.request(request.method, target + "/", params=query or None, content=body,
                               headers=headers, timeout=15)
    except httpx.HTTPError as e:
        log.warning("пересылка в Traccar: %s", e)
        return Response(status_code=502)
    return Response(content=r.content, status_code=r.status_code,
                    media_type=r.headers.get("content-type"))


@router.api_route("/osmand", methods=["GET", "POST"])
async def osmand(request: Request):
    return await _handle(request)
