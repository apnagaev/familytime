"""Место компьютера и отправка точки в Traccar (OsmAnd).

Порядок, от дешёвого к дорогому (resolve):
  1. известный адрес — таблица «IP или подсеть → координаты» из общих настроек, без запросов;
  2. те же точки Wi-Fi и тот же IP, что в прошлый раз — прошлое место, без запроса;
  3. Wi-Fi (+ IP) → Яндекс Локатор;
  4. без Wi-Fi: место по внешнему IP — из кеша (неделя), иначе Яндекс Локатор по IP,
     иначе служба GeoIP (GEOIP_URL); точность — город.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import random
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx

log = logging.getLogger("familytime.locator")

_BSSID = re.compile(r"^[0-9a-f]{12}$")
# адрес, широта, долгота, [точность], [название]; между полями — пробелы, запятые или ;
_KNOWN_LINE = re.compile(
    r"^([0-9a-fA-F:./]+)[\s,;]+(-?\d+(?:\.\d+)?)[\s,;]+(-?\d+(?:\.\d+)?)"
    r"(?:[\s,;]+(\d+(?:\.\d+)?)(?=[\s,;]|$))?(?:[\s,;]+(.*))?$")


WIFI_REUSE = timedelta(hours=24)      # те же точки Wi-Fi и IP — место не переспрашиваем
GEOIP_TTL = timedelta(days=7)         # сколько помнить место по IP
GEOIP_ACCURACY = 10000.0              # м: место по IP — это город


@dataclass
class Fix:
    lat: float
    lon: float
    accuracy: float
    source: str           # known-ip | yandex-wifi | yandex-ip | geoip
    place: str = ""       # название известного места
    cached: bool = False  # взято без запроса наружу


# ---------- известные адреса ----------

def parse_ip_locations(text: str) -> tuple[list[dict], list[str]]:
    """Строки «IP-или-подсеть широта долгота [точность_м] [название]» → записи и ошибки."""
    out, errors = [], []
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _KNOWN_LINE.match(line)
        try:
            if not m:
                raise ValueError
            net = ipaddress.ip_network(m.group(1), strict=False)
            lat, lon = float(m.group(2)), float(m.group(3))
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                raise ValueError
            out.append({"net": str(net), "lat": lat, "lon": lon,
                        "accuracy": float(m.group(4) or 50),
                        "name": (m.group(5) or "").strip()[:60]})
        except (ValueError, IndexError):
            errors.append(f"строка {n}: «{raw.strip()[:60]}»")
    return out, errors


def format_ip_locations(items: list[dict]) -> str:
    return "\n".join(
        f"{i['net']} {i['lat']} {i['lon']} {int(i['accuracy'])} {i.get('name', '')}".rstrip()
        for i in items or [])


def match_known(items: list[dict], ip: str) -> Fix | None:
    """Самая узкая подсеть, в которую попадает адрес."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best = None
    for i in items or []:
        net = ipaddress.ip_network(i["net"], strict=False)
        if addr.version == net.version and addr in net and \
                (best is None or net.prefixlen > best[0]):
            best = (net.prefixlen, i)
    if not best:
        return None
    i = best[1]
    return Fix(i["lat"], i["lon"], i["accuracy"], "known-ip", i.get("name", ""), True)


def wifi_signature(wifi) -> str:
    """Подпись окружения: пять самых сильных точек, без учёта порядка и уровня сигнала."""
    top = sorted((norm_bssid(ap.bssid) for ap in
                  sorted(wifi, key=lambda a: a.rssi, reverse=True)[:5]))
    top = [b for b in top if b]
    return hashlib.sha1(",".join(top).encode()).hexdigest()[:16] if top else ""


def norm_bssid(v: str) -> str:
    v = re.sub(r"[^0-9a-fA-F]", "", v or "").lower()
    if not _BSSID.match(v) or v in ("000000000000", "ffffffffffff"):
        return ""
    return ":".join(v[i:i + 2] for i in range(0, 12, 2))


def public_ip(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    return "" if (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved) else str(a)


def build_request(wifi, ip: str) -> dict:
    body: dict = {}
    aps = []
    seen = set()
    for ap in sorted(wifi, key=lambda a: a.rssi, reverse=True):
        b = norm_bssid(ap.bssid)
        if b and b not in seen:
            seen.add(b)
            aps.append({"bssid": b, "signal_strength": max(-120, min(-1, int(ap.rssi)))})
    if aps:
        body["wifi"] = aps[:50]
    pip = public_ip(ip)
    if pip:
        body["ip"] = [{"address": pip}]
    return body


async def locate(http: httpx.AsyncClient, cfg, wifi, ip: str) -> Fix | None:
    body = build_request(wifi, ip)
    if not body or not cfg.yandex_locator_keys:
        return None
    keys = list(cfg.yandex_locator_keys)
    random.shuffle(keys)
    for key in keys:
        try:
            r = await http.post(cfg.yandex_locator_url, params={"apikey": key}, json=body,
                                headers={"User-Agent": "familytime/1.0"}, timeout=15)
        except httpx.HTTPError as e:
            log.warning("locator: %s", e)
            return None
        if r.status_code in (403, 429):
            log.warning("locator: ключ отклонён (%s), пробую следующий", r.status_code)
            continue
        if r.status_code != 200:
            log.warning("locator: HTTP %s %s", r.status_code, r.text[:200])
            return None
        loc = (r.json() or {}).get("location")
        if not loc:
            return None
        src = "yandex-wifi" if "wifi" in body else "yandex-ip"
        return Fix(float(loc["point"]["lat"]), float(loc["point"]["lon"]),
                   float(loc.get("accuracy") or 0), src)
    return None


async def geoip(http: httpx.AsyncClient, cfg, ip: str) -> Fix | None:
    """Место по IP у внешней службы (по умолчанию ip-api.com). Ответ — JSON с lat/lon."""
    if not cfg.geoip_url:
        return None
    try:
        r = await http.get(cfg.geoip_url.replace("{ip}", ip), timeout=10,
                           headers={"User-Agent": "familytime/1.0"})
        d = r.json() if r.status_code == 200 else {}
    except (httpx.HTTPError, ValueError) as e:
        log.warning("geoip: %s", e)
        return None
    lat = d.get("lat", d.get("latitude"))
    lon = d.get("lon", d.get("longitude"))
    if lat in (None, "") or lon in (None, "") or d.get("status") == "fail":
        log.warning("geoip: нет места для %s", ip)
        return None
    return Fix(float(lat), float(lon), GEOIP_ACCURACY, "geoip", str(d.get("city") or "")[:60])


async def resolve(http, cfg, conn, settings: dict, dev, wifi, ip: str) -> tuple[Fix | None, str]:
    """Место компьютера (см. порядок в начале файла) и подпись Wi-Fi для следующего раза."""
    sig = wifi_signature(wifi)
    known = match_known(settings.get("ip_locations", []), ip)
    if known:
        return known, sig
    now = datetime.now(timezone.utc)
    if sig:
        if (dev["last_wifi_sig"] == sig and dev["last_ip"] == ip and dev["last_fix_at"]
                and now - dev["last_fix_at"] < WIFI_REUSE
                and dev["last_fix_source"] == "yandex-wifi"):
            return Fix(dev["last_lat"], dev["last_lon"], dev["last_accuracy"] or 0,
                       "yandex-wifi", cached=True), sig
        fix = await locate(http, cfg, wifi, ip)
        if fix:
            return fix, sig
    pip = public_ip(ip)
    if not pip:
        return None, sig
    row = await conn.fetchrow("SELECT * FROM ft_geoip WHERE ip = $1", pip)
    if row and now - row["fetched_at"] < GEOIP_TTL:
        return Fix(row["lat"], row["lon"], row["accuracy"], row["source"], row["place"], True), sig
    fix = await locate(http, cfg, [], pip) or await geoip(http, cfg, pip)
    if fix:
        if fix.source == "yandex-ip" and not fix.accuracy:
            fix.accuracy = GEOIP_ACCURACY
        await conn.execute(
            """INSERT INTO ft_geoip (ip, lat, lon, accuracy, source, place, fetched_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (ip) DO UPDATE SET lat = EXCLUDED.lat, lon = EXCLUDED.lon,
               accuracy = EXCLUDED.accuracy, source = EXCLUDED.source, place = EXCLUDED.place,
               fetched_at = EXCLUDED.fetched_at""",
            pip, fix.lat, fix.lon, fix.accuracy, fix.source, fix.place, now)
    return fix, sig


def osmand_params(dev, fix: Fix, body, ip: str, now: datetime) -> dict:
    """Параметры OsmAnd (https://www.traccar.org/osmand/).

    Имена wifi и cell у Traccar зарезервированы под формат «MAC,сигнал» — число точек идёт
    как wifiCount. ip не передаётся: его дописывает прокси перед Traccar; адрес, с которого
    агент пришёл на портал, — extip. status — стандартный числовой атрибут Traccar, поэтому
    состояние сеанса — session.
    """
    p = {
        "id": dev["hostname"],
        "timestamp": int(now.timestamp()),
        "lat": f"{fix.lat:.6f}",
        "lon": f"{fix.lon:.6f}",
        "accuracy": f"{fix.accuracy:.0f}",
        "ignition": "true" if body.session == "active" else "false",
        "source": fix.source,
        "wifiCount": len(body.wifi),
        "session": body.session,
        "channel": "familytime",
    }
    if fix.place:
        p["place"] = fix.place
    if ip:
        p["extip"] = ip
    if body.battery is not None:
        p["batt"] = body.battery
    if body.on_ac is not None:
        p["charge"] = "true" if body.on_ac else "false"
    if body.user:
        p["username"] = body.user.lower()
    if body.ssid:
        p["ssid"] = body.ssid
    if body.local_ip:
        p["localIP"] = body.local_ip
    if dev["lost"]:
        p["alarm"] = "lost"
    return p


async def send_osmand(http, cfg, dev, fix: Fix, body, ip: str, now: datetime) -> bool:
    try:
        r = await http.get(cfg.traccar_osmand_url + "/", params=osmand_params(dev, fix, body, ip, now),
                           timeout=10)
        if r.status_code >= 400:
            log.warning("traccar osmand: HTTP %s", r.status_code)
        return r.status_code < 400
    except httpx.HTTPError as e:
        log.warning("traccar osmand: %s", e)
        return False


async def ensure_traccar_device(http, cfg, hostname: str, user: str) -> bool:
    """Создаёт устройство в Traccar, если его нет (нужны TRACCAR_API_URL и TRACCAR_TOKEN)."""
    if not (cfg.traccar_api_url and cfg.traccar_token):
        return True        # регистрация вручную или registerUnknown в Traccar
    h = {"Authorization": f"Bearer {cfg.traccar_token}"}
    try:
        r = await http.get(cfg.traccar_api_url + "/devices", params={"uniqueId": hostname},
                           headers=h, timeout=10)
        if r.status_code == 200 and r.json():
            return True
        name = hostname.split(".")[0]
        if user:
            name = f"{name} ({user.split(chr(92))[-1]})"
        data = {"name": name, "uniqueId": hostname, "category": "laptop"}
        if cfg.traccar_group_id:
            data["groupId"] = cfg.traccar_group_id
        r = await http.post(cfg.traccar_api_url + "/devices", json=data, headers=h, timeout=10)
        if r.status_code >= 400:
            log.warning("traccar: не создал устройство %s: HTTP %s %s", hostname, r.status_code,
                        r.text[:200])
        return r.status_code < 400
    except httpx.HTTPError as e:
        log.warning("traccar api: %s", e)
        return False
