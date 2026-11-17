"""Место компьютера и отправка точки в Traccar (OsmAnd).

Порядок, от дешёвого к дорогому (resolve):
  1. известный адрес — таблица «IP или подсеть → координаты» из общих настроек, без запросов;
  2. те же точки Wi-Fi и тот же IP, что в прошлый раз — прошлое место, без запроса;
  3. Wi-Fi (+ IP) → Яндекс Локатор;
  4. без Wi-Fi: место, которое агент узнал вместе с внешним адресом (ip-api.com), иначе
     по внешнему IP на сервере — из кеша (неделя), Яндекс Локатор по IP, служба GEOIP_URL;
     точность — город.
Раньше всех — свежая точка GPS телефона (Traccar Client через FamilyTime) из той же сети.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import math
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
GEOIP_TTL = timedelta(days=30)        # сколько помнить место по IP (экономия запросов к Локатору)
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


def match_known(items: list[dict], *ips: str) -> Fix | None:
    """Самая узкая подсеть, в которую попадает любой из адресов."""
    best = None
    for ip in ips:
        try:
            addr = ipaddress.ip_address((ip or "").strip())
        except ValueError:
            continue
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


async def resolve(http, cfg, conn, settings: dict, dev, wifi, ip: str, ext_ip: str = "",
                  ext_geo=None) -> tuple[Fix | None, str]:
    """Место компьютера и подпись Wi-Fi для следующего раза.

    ip — адрес, с которого агент пришёл на сервер (дома — внутренний), ext_ip — внешний адрес,
    который агент узнал сам, ext_geo — место по нему от той же службы.
    Порядок: известный адрес → Wi-Fi → место по IP.
    """
    sig = wifi_signature(wifi)
    ext_ip = public_ip(ext_ip)
    for addr in (ip, ext_ip):
        known = match_known(settings.get("ip_locations", []), addr) if addr else None
        if known:
            return known, sig
    now = datetime.now(timezone.utc)
    seen_ip = ext_ip or ip
    if sig:
        if (dev["last_wifi_sig"] == sig and (dev["ext_ip"] or dev["last_ip"]) == seen_ip
                and dev["last_fix_at"] and now - dev["last_fix_at"] < WIFI_REUSE
                and dev["last_fix_source"] == "yandex-wifi"):
            return Fix(dev["last_lat"], dev["last_lon"], dev["last_accuracy"] or 0,
                       "yandex-wifi", cached=True), sig
        fix = await locate(http, cfg, wifi, ext_ip or ip)
        if fix:
            return fix, sig
    # без Wi-Fi: место, которое агент уже узнал вместе с внешним адресом, — без запросов
    if ext_geo is not None and ext_geo.lat is not None and ext_geo.lon is not None:
        return Fix(float(ext_geo.lat), float(ext_geo.lon), GEOIP_ACCURACY, "geoip",
                   (ext_geo.city or "")[:60], True), sig
    pip = ext_ip or public_ip(ip)
    if not pip:
        return None, sig
    return await ip_location(http, cfg, conn, pip), sig


async def ip_location(http, cfg, conn, pip: str) -> Fix | None:
    """Место по внешнему адресу: Яндекс Локатор по IP, иначе служба GeoIP. Ответ хранится
    в ft_geoip месяц — повторные точки с того же адреса Локатор не тратят."""
    pip = public_ip(pip)
    if not pip:
        return None
    now = datetime.now(timezone.utc)
    row = await conn.fetchrow("SELECT * FROM ft_geoip WHERE ip = $1", pip)
    if row and now - row["fetched_at"] < GEOIP_TTL:
        return Fix(row["lat"], row["lon"], row["accuracy"], row["source"], row["place"], True)
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
    return fix


JITTER_MAX = 2000.0       # м: дальше не разбрасываем, даже если точность хуже (место по IP)


OPERATOR_TTL = timedelta(days=7)       # провайдер адреса меняется редко
OPERATOR_FAIL_TTL = timedelta(hours=6)  # не узнали — не спрашиваем снова какое-то время


def operator_name(d: dict) -> str:
    """Название провайдера из ответа ip-api.com (isp, иначе org, иначе as без номера)."""
    for k in ("isp", "org", "operator", "provider"):
        v = str(d.get(k) or "").strip()
        if v:
            return v[:80]
    asn = str(d.get("as") or "").strip()
    return re.sub(r"^AS\d+\s+", "", asn)[:80]


async def operator(http, cfg, conn, ip: str) -> str:
    """Провайдер по внешнему адресу; внутренние адреса — пусто. Ответ запоминается в базе
    на неделю (неудача — на 6 часов), чтобы не упираться в лимиты службы."""
    ip = public_ip(ip)
    if not ip or not cfg.operator_url:
        return ""
    row = await conn.fetchrow("SELECT operator, fetched_at FROM ft_ip_operator WHERE ip = $1", ip)
    now = datetime.now(timezone.utc)
    if row and now - row["fetched_at"] < (OPERATOR_TTL if row["operator"] else OPERATOR_FAIL_TTL):
        return row["operator"]
    name = ""
    try:
        r = await http.get(cfg.operator_url.replace("{ip}", ip), timeout=5,
                           headers={"User-Agent": "familytime/1.0"})
        d = r.json() if r.status_code == 200 else {}
        if isinstance(d, dict) and d.get("status") != "fail":
            name = operator_name(d)
    except (httpx.HTTPError, ValueError) as e:
        log.info("оператор для %s: %s", ip, e)
    if not name and row and row["operator"]:
        name = row["operator"]                     # служба не ответила — прежнее значение
    await conn.execute(
        """INSERT INTO ft_ip_operator (ip, operator, fetched_at) VALUES ($1, $2, $3)
           ON CONFLICT (ip) DO UPDATE SET operator = EXCLUDED.operator, fetched_at = EXCLUDED.fetched_at""",
        ip, name, now)
    return name


def jitter(lat: float, lon: float, radius: float, rnd: random.Random | None = None) -> tuple[float, float]:
    """Случайная точка внутри круга радиусом radius метров, равномерно по площади,
    чтобы точки одного места не ложились друг на друга."""
    radius = min(max(radius, 0.0), JITTER_MAX)
    if radius <= 0:
        return lat, lon
    rnd = rnd or random
    r = radius * math.sqrt(rnd.random())
    t = rnd.random() * 2 * math.pi
    dlat = r * math.cos(t) / 111_320
    dlon = r * math.sin(t) / (111_320 * max(math.cos(math.radians(lat)), 0.01))
    return lat + dlat, lon + dlon


def osmand_params(dev, fix: Fix, body, ip: str, now: datetime, spread: bool = True,
                  operator: str = "") -> dict:
    """Параметры OsmAnd (https://www.traccar.org/osmand/).

    Имена wifi и cell у Traccar зарезервированы под формат «MAC,сигнал» — число точек идёт
    как wifiCount. ip не передаётся: его дописывает прокси перед Traccar. extip — внешний
    адрес, который агент узнал сам (ip-api.com), localIP — адрес, с которого агент пришёл
    на сервер. status — стандартный числовой атрибут Traccar, поэтому состояние сеанса — session.
    spread — разброс точки в пределах точности.
    """
    lat, lon = jitter(fix.lat, fix.lon, fix.accuracy) if spread else (fix.lat, fix.lon)
    p = {
        "id": dev["hostname"],
        "timestamp": int(now.timestamp()),
        "lat": f"{lat:.6f}",
        "lon": f"{lon:.6f}",
        "accuracy": f"{fix.accuracy:.0f}",
        "ignition": "true" if body.session == "active" else "false",
        "source": fix.source,
        "wifiCount": len(body.wifi),
        "session": body.session,
        "channel": "familytime",
    }
    if fix.place:
        p["place"] = fix.place
    ext = public_ip(body.ext_ip) or public_ip(ip)
    if ext:
        p["extip"] = ext
    if ip:
        p["localIP"] = ip
    if operator:
        p["operator"] = operator
    if body.battery is not None:
        p["batt"] = body.battery
    if body.on_ac is not None:
        p["charge"] = "true" if body.on_ac else "false"
    if body.user:
        p["username"] = body.user.lower()
    if body.ssid:
        p["ssid"] = body.ssid
    if dev["lost"]:
        p["alarm"] = "lost"
    return p


async def send_osmand(http, cfg, dev, fix: Fix, body, ip: str, now: datetime,
                      spread: bool = True, operator: str = "") -> bool:
    try:
        r = await http.get(cfg.traccar_osmand_url + "/",
                           params=osmand_params(dev, fix, body, ip, now, spread, operator),
                           timeout=10)
        if r.status_code >= 400:
            log.warning("traccar osmand: HTTP %s", r.status_code)
        return r.status_code < 400
    except httpx.HTTPError as e:
        log.warning("traccar osmand: %s", e)
        return False


_group_ids: dict[str, int] = {}
_ensured: dict[str, str] = {}            # uniqueId → группа, уже проверено в этом процессе


async def traccar_group(http, cfg, name: str) -> int | None:
    """Номер группы Traccar по имени; нет такой — создаётся."""
    name = (name or "").strip()
    if not name:
        return None
    if name in _group_ids:
        return _group_ids[name]
    h = {"Authorization": f"Bearer {cfg.traccar_token}"}
    r = await http.get(cfg.traccar_api_url + "/groups", params={"all": "true"}, headers=h, timeout=10)
    groups = r.json() if r.status_code == 200 else []
    for g in groups if isinstance(groups, list) else []:
        if isinstance(g, dict) and str(g.get("name", "")).strip().lower() == name.lower():
            _group_ids[name] = int(g["id"])
            return _group_ids[name]
    r = await http.post(cfg.traccar_api_url + "/groups", json={"name": name}, headers=h, timeout=10)
    if r.status_code >= 400:
        log.warning("traccar: не создал группу %s: HTTP %s %s", name, r.status_code, r.text[:200])
        return None
    _group_ids[name] = int(r.json()["id"])
    log.info("traccar: создана группа %s", name)
    return _group_ids[name]


async def ensure_traccar_device(http, cfg, unique_id: str, user: str = "", group: str = "",
                                name: str = "", category: str = "") -> bool:
    """Устройство в Traccar: создаётся, если его нет, и кладётся в группу group (по имени;
    группа создаётся сама). Уже существующее переносится в эту группу. Проверяется один раз
    за запуск сервера. Нужны TRACCAR_API_URL и TRACCAR_TOKEN (администратора)."""
    if not (cfg.traccar_api_url and cfg.traccar_token):
        return True        # регистрация вручную или registerUnknown в Traccar
    if _ensured.get(unique_id) == group:
        return True
    h = {"Authorization": f"Bearer {cfg.traccar_token}"}
    try:
        gid = await traccar_group(http, cfg, group) if group else cfg.traccar_group_id
        r = await http.get(cfg.traccar_api_url + "/devices",
                           params={"uniqueId": unique_id, "all": "true"}, headers=h, timeout=10)
        found = r.json() if r.status_code == 200 else []
        found = [d for d in found if isinstance(d, dict)] if isinstance(found, list) else []
        if found:
            d = found[0]
            if gid and d.get("groupId") != gid:
                d["groupId"] = gid
                r = await http.put(f"{cfg.traccar_api_url}/devices/{d['id']}", json=d, headers=h,
                                   timeout=10)
                if r.status_code >= 400:
                    log.warning("traccar: %s не перенесён в группу %s: HTTP %s", unique_id, group,
                                r.status_code)
                    return False
                log.info("traccar: %s → группа %s", unique_id, group)
            _ensured[unique_id] = group
            return True
        if not name:
            name = unique_id.split(".")[0] if "." in unique_id and not unique_id[0].isdigit() \
                else unique_id
            if user:
                name = f"{name} ({user.split(chr(92))[-1]})"
        data = {"name": name[:120], "uniqueId": unique_id}
        if category:
            data["category"] = category
        if gid:
            data["groupId"] = gid
        r = await http.post(cfg.traccar_api_url + "/devices", json=data, headers=h, timeout=10)
        if r.status_code >= 400:
            log.warning("traccar: не создал устройство %s: HTTP %s %s", unique_id, r.status_code,
                        r.text[:200])
            return False
        log.info("traccar: создано устройство %s (%s)", unique_id, group or "без группы")
        _ensured[unique_id] = group
        return True
    except Exception as e:  # noqa: BLE001 — точка важнее устройства в Traccar
        log.warning("traccar api: %s", e)
        return False
