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
COUNTRY_ACCURACY = 50000.0            # м: место по IP грубее — это уже страна
# Точность, которую получает Traccar для места по IP: настоящий радиус (километры) рисует на
# карте огромные синие круги, поэтому город отдаётся как 1 м, страна — как 2 м. В портале
# хранится настоящая точность, разброс точки тоже считается по ней.
TRACCAR_CITY_ACCURACY = 1
TRACCAR_COUNTRY_ACCURACY = 2


def traccar_accuracy(source: str, accuracy: float, place: str = "") -> float:
    if source not in ("yandex-ip", "geoip"):
        return accuracy
    if (accuracy or 0) > COUNTRY_ACCURACY or (source == "geoip" and not place):
        return TRACCAR_COUNTRY_ACCURACY
    return TRACCAR_CITY_ACCURACY


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


async def traccar_device_id(http, cfg, unique_id: str) -> int | None:
    """Номер существующего устройства Traccar (без создания)."""
    if not (cfg.traccar_api_url and cfg.traccar_token):
        return None
    if unique_id in _device_ids:
        return _device_ids[unique_id]
    try:
        d = await find_traccar_device(http, cfg, unique_id)
    except Exception as e:  # noqa: BLE001
        log.warning("traccar api: %s", e)
        return None
    if d:
        _device_ids[unique_id] = int(d["id"])
        return _device_ids[unique_id]
    return None


async def user_traccar_devices(http, cfg, conn, username: str, email: str = "") -> list[dict]:
    """Устройства Traccar, доступные этому пользователю портала (его пользователь Traccar
    находится по логину или по почте, с которой он входил через Keycloak). Только их он и
    может добавить в семью — устройство другого родителя так не захватить."""
    if not (cfg.traccar_api_url and cfg.traccar_token) or not username:
        return []
    ids = await user_traccar_ids(http, cfg, conn, username, email)
    h = {"Authorization": f"Bearer {cfg.traccar_token}"}
    out: dict[str, dict] = {}
    for uid in sorted(ids):
        r = await http.get(cfg.traccar_api_url + "/devices", params={"userId": uid},
                           headers=h, timeout=20)
        items = r.json() if r.status_code == 200 else []
        for d in items if isinstance(items, list) else []:
            if isinstance(d, dict) and d.get("uniqueId"):
                out.setdefault(str(d["uniqueId"]).lower(), d)
    return sorted(out.values(), key=lambda d: str(d.get("name") or d.get("uniqueId")).lower())


async def traccar_users(http, cfg) -> list[dict]:
    """Пользователи Traccar (нужен токен администратора), список хранится 5 минут."""
    import time as _t
    if _t.monotonic() - _users["at"] < ALL_DEVICES_TTL:
        return _users["items"]
    h = {"Authorization": f"Bearer {cfg.traccar_token}"}
    r = await http.get(cfg.traccar_api_url + "/users", headers=h, timeout=20)
    items = r.json() if r.status_code == 200 else None
    if isinstance(items, list):
        _users.update(at=_t.monotonic(), items=[u for u in items if isinstance(u, dict)])
    else:
        log.warning("traccar: список пользователей не получен (HTTP %s)", r.status_code)
    return _users["items"]


def match_traccar_users(users: list[dict], wanted: list[str]) -> set[int]:
    """Номера пользователей Traccar по почте или логину (без учёта регистра)."""
    keys = {w.strip().lower() for w in wanted if w and w.strip()}
    out = set()
    for u in users:
        for k in ("email", "login", "name"):
            v = str(u.get(k) or "").strip().lower()
            if v and v in keys:
                out.add(int(u["id"]))
                break
    return out


async def link_device(http, cfg, conn, unique_id: str, wanted: list[str]) -> None:
    """Устройство — на карту пользователей Traccar из wanted (почта или логин): выдать права
    тем, у кого их нет, и забрать выданные FamilyTime у тех, кого в списке больше нет
    (права, выданные вручную, не трогаются). Раз на набор за запуск сервера."""
    if not (cfg.traccar_api_url and cfg.traccar_token):
        return
    did = _device_ids.get(unique_id)
    if not did:
        return
    try:
        users = await traccar_users(http, cfg) if wanted else []
    except Exception as e:  # noqa: BLE001
        log.warning("traccar: пользователи: %s", e)
        return
    if wanted and not users:
        return                  # список не получен — ничего не менять, особенно не забирать права
    want_ids = match_traccar_users(users, wanted)
    key = frozenset(want_ids)
    if _linked.get(unique_id) == key:
        return
    h = {"Authorization": f"Bearer {cfg.traccar_token}"}
    have = {r["user_id"] for r in await conn.fetch(
        "SELECT user_id FROM ft_traccar_links WHERE unique_id = $1", unique_id)}
    ok = True
    for uid in want_ids - have:
        r = await http.post(cfg.traccar_api_url + "/permissions",
                            json={"userId": uid, "deviceId": did}, headers=h, timeout=10)
        # 400 — право уже есть (выдано вручную или раньше)
        if r.status_code < 300 or r.status_code == 400:
            await conn.execute("INSERT INTO ft_traccar_links (unique_id, user_id) VALUES ($1, $2) "
                               "ON CONFLICT DO NOTHING", unique_id, uid)
            log.info("traccar: %s → на карту пользователя %s", unique_id, uid)
        else:
            ok = False
            log.warning("traccar: %s не выдан пользователю %s: HTTP %s", unique_id, uid, r.status_code)
    for uid in have - want_ids:
        r = await http.request("DELETE", cfg.traccar_api_url + "/permissions",
                               json={"userId": uid, "deviceId": did}, headers=h, timeout=10)
        if r.status_code < 300 or r.status_code == 404:
            await conn.execute("DELETE FROM ft_traccar_links WHERE unique_id = $1 AND user_id = $2",
                               unique_id, uid)
            log.info("traccar: %s убран с карты пользователя %s", unique_id, uid)
        else:
            ok = False
    if ok:
        _linked[unique_id] = key


async def family_viewers(conn, family_id) -> list[str]:
    """Кому из Traccar показывать устройства семьи: список из настроек семьи, иначе почта и
    логины её родителей (почта запоминается при входе в портал через Keycloak)."""
    if not family_id:
        return []
    fam = await conn.fetchrow("SELECT traccar_users FROM ft_families WHERE id = $1", family_id)
    if fam and fam["traccar_users"]:
        return list(fam["traccar_users"])
    rows = await conn.fetch(
        """SELECT p.username, COALESCE(pe.email, '') AS email FROM ft_family_parents p
           LEFT JOIN ft_people pe ON pe.username = p.username WHERE p.family_id = $1""", family_id)
    out = []
    for r in rows:
        out.append(r["username"])
        if r["email"]:
            out.append(r["email"])
    return out


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
        "accuracy": f"{traccar_accuracy(fix.source, fix.accuracy, fix.place):.0f}",
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
_all_devices: dict = {"at": float("-inf"), "by_uid": {}}
_device_ids: dict[str, int] = {}         # uniqueId → id устройства в Traccar
_linked: dict[str, frozenset] = {}       # uniqueId → кому уже выданы права в этом процессе
_users: dict = {"at": float("-inf"), "items": []}
ALL_DEVICES_TTL = 300                    # с: как часто перечитывать полный список устройств


async def all_traccar_devices(http, cfg, fresh: bool = False) -> dict:
    """Все устройства Traccar (?all=true, нужен администратор): uniqueId → устройство, кеш 5 минут."""
    import time as _t
    if fresh or _t.monotonic() - _all_devices["at"] > ALL_DEVICES_TTL:
        h = {"Authorization": f"Bearer {cfg.traccar_token}"}
        r = await http.get(cfg.traccar_api_url + "/devices", params={"all": "true"},
                           headers=h, timeout=30)
        items = r.json() if r.status_code == 200 else None
        if isinstance(items, list):
            _all_devices["by_uid"] = {d.get("uniqueId"): d for d in items if isinstance(d, dict)}
            _all_devices["at"] = _t.monotonic()
        else:
            log.warning("traccar: полный список устройств не получен (HTTP %s) — нужен токен "
                        "администратора", r.status_code)
    return _all_devices["by_uid"]


async def find_traccar_device(http, cfg, unique_id: str, fresh: bool = False) -> dict | None:
    """Устройство Traccar по uniqueId. Запрос ?uniqueId= Traccar фильтрует по правам владельца
    токена — устройства, не привязанные к нему (заведённые другими, vpngeo, вручную), так не
    находятся даже у администратора. Поэтому при промахе — полный список ?all=true
    (администратор видит все), он хранится 5 минут."""
    h = {"Authorization": f"Bearer {cfg.traccar_token}"}
    r = await http.get(cfg.traccar_api_url + "/devices", params={"uniqueId": unique_id},
                       headers=h, timeout=10)
    found = r.json() if r.status_code == 200 else []
    for d in found if isinstance(found, list) else []:
        if isinstance(d, dict) and d.get("uniqueId") == unique_id:
            return d
    d = (await all_traccar_devices(http, cfg, fresh)).get(unique_id)
    return dict(d) if d else None


async def traccar_group(http, cfg, name: str) -> int | None:
    """Номер группы Traccar по имени — только среди групп владельца токена (GET /groups без
    all: на общем Traccar у других пользователей бывают свои «PC» и «mobile», и устройство
    уезжало в чужую группу). Нет такой — создаётся. Число вместо имени — номер группы."""
    name = (name or "").strip()
    if not name:
        return None
    if name.isdigit():
        return int(name)
    if name in _group_ids:
        return _group_ids[name]
    h = {"Authorization": f"Bearer {cfg.traccar_token}"}
    r = await http.get(cfg.traccar_api_url + "/groups", headers=h, timeout=10)
    groups = r.json() if r.status_code == 200 else []
    same = [g for g in (groups if isinstance(groups, list) else [])
            if isinstance(g, dict) and str(g.get("name", "")).strip().lower() == name.lower()]
    if same:
        exact = [g for g in same if str(g.get("name", "")).strip() == name]
        g = (exact or same)[0]
        _group_ids[name] = int(g["id"])
        log.info("traccar: группа %s — id %s%s", name, g["id"],
                 f" (одноимённых у владельца токена: {len(same)})" if len(same) > 1 else "")
        return _group_ids[name]
    r = await http.post(cfg.traccar_api_url + "/groups", json={"name": name}, headers=h, timeout=10)
    if r.status_code >= 400:
        log.warning("traccar: не создал группу %s: HTTP %s %s", name, r.status_code, r.text[:200])
        return None
    _group_ids[name] = int(r.json()["id"])
    log.info("traccar: создана группа %s — id %s", name, _group_ids[name])
    return _group_ids[name]


async def ensure_traccar_device(http, cfg, unique_id: str, user: str = "", group: str = "",
                                name: str = "", category: str = "", conn=None) -> bool:
    """Компьютер с агентом в Traccar: создаётся, если его нет. Группа group назначается один
    раз — при первом обращении (см. assign_group_once); потом FamilyTime её не трогает, и
    ручной перенос в Traccar сохраняется. Нужны TRACCAR_API_URL и TRACCAR_TOKEN."""
    if not (cfg.traccar_api_url and cfg.traccar_token):
        return True        # регистрация вручную или registerUnknown в Traccar
    if unique_id not in _ensured:
        h = {"Authorization": f"Bearer {cfg.traccar_token}"}
        try:
            d = await find_traccar_device(http, cfg, unique_id)
            if not d:
                if not name:
                    name = unique_id.split(".")[0] if "." in unique_id and not unique_id[0].isdigit() \
                        else unique_id
                    if user:
                        name = f"{name} ({user.split(chr(92))[-1]})"
                data = {"name": name[:120], "uniqueId": unique_id}
                if category:
                    data["category"] = category
                r = await http.post(cfg.traccar_api_url + "/devices", json=data, headers=h, timeout=10)
                if r.status_code >= 400:
                    d = await find_traccar_device(http, cfg, unique_id, fresh=True)
                    if not d:
                        log.warning("traccar: не создал устройство %s: HTTP %s %s", unique_id,
                                    r.status_code, r.text[:200])
                        return False
                else:
                    d = r.json()
                    log.info("traccar: создано устройство %s", unique_id)
            _device_ids[unique_id] = int(d["id"])
            _ensured[unique_id] = "ok"
        except Exception as e:  # noqa: BLE001 — точка важнее устройства в Traccar
            log.warning("traccar api: %s", e)
            return False
    if group and conn is not None:
        await assign_group_once(http, cfg, conn, unique_id, group)
    return True


async def assign_group_once(http, cfg, conn, unique_id: str, group: str) -> None:
    """Положить существующее устройство в группу — только при первом обращении: запомнив
    назначение (ft_traccar_assigned), FamilyTime больше группу этого устройства не меняет.
    Пустое имя группы — ничего не делать (и не запоминать: назначится, когда группа появится)."""
    if not group or not (cfg.traccar_api_url and cfg.traccar_token):
        return
    if await conn.fetchval("SELECT 1 FROM ft_traccar_assigned WHERE unique_id = $1", unique_id):
        return
    try:
        gid = await traccar_group(http, cfg, group)
        if not gid:
            return
        d = await find_traccar_device(http, cfg, unique_id)
        if not d:
            return                                   # устройства ещё нет — назначим, когда появится
        if d.get("groupId") != gid:
            d["groupId"] = gid
            h = {"Authorization": f"Bearer {cfg.traccar_token}"}
            r = await http.put(f"{cfg.traccar_api_url}/devices/{d['id']}", json=d, headers=h, timeout=10)
            if r.status_code >= 400:
                log.warning("traccar: %s не перенесён в группу %s: HTTP %s", unique_id, group,
                            r.status_code)
                return
            if unique_id in _all_devices["by_uid"]:
                _all_devices["by_uid"][unique_id] = d
            log.info("traccar: %s → группа %s (id %s), один раз", unique_id, group, gid)
        _device_ids[unique_id] = int(d["id"])
        await conn.execute("INSERT INTO ft_traccar_assigned (unique_id, group_id) VALUES ($1, $2) "
                           "ON CONFLICT DO NOTHING", unique_id, gid)
    except Exception as e:  # noqa: BLE001
        log.warning("traccar: группа для %s: %s", unique_id, e)


async def group_for(conn, settings: dict, family_id, kind: str) -> str:
    """Имя группы для устройства вида kind (pc | vpn | mobile): из семьи, иначе по умолчанию
    из общих настроек."""
    col = {"pc": "group_pc", "vpn": "group_vpn", "mobile": "group_mobile"}[kind]
    if family_id:
        v = await conn.fetchval(f"SELECT {col} FROM ft_families WHERE id = $1", family_id)
        if v:
            return v
    return str(settings.get({"pc": "traccar_group_pc", "vpn": "traccar_group_vpn",
                             "mobile": "traccar_group_phone"}[kind]) or "")


async def owner_groups(http, cfg, user_id: int | None = None) -> list[dict]:
    """Группы владельца токена или (для администратора Traccar) указанного пользователя."""
    if not (cfg.traccar_api_url and cfg.traccar_token):
        return []
    h = {"Authorization": f"Bearer {cfg.traccar_token}"}
    r = await http.get(cfg.traccar_api_url + "/groups",
                       params={"userId": user_id} if user_id else None, headers=h, timeout=20)
    items = r.json() if r.status_code == 200 else []
    return sorted([g for g in items if isinstance(g, dict) and "id" in g] if isinstance(items, list)
                  else [], key=lambda g: str(g.get("name", "")).lower())


async def user_traccar_ids(http, cfg, conn, username: str, email: str = "") -> set[int]:
    keys = {username.lower()} if username else set()
    if email:
        keys.add(email.lower())
    row = await conn.fetchrow("SELECT email FROM ft_people WHERE username = $1", username)
    if row and row["email"]:
        keys.add(row["email"].lower())
    return match_traccar_users(await traccar_users(http, cfg), list(keys)) if keys else set()


async def user_traccar_groups(http, cfg, conn, username: str, email: str = "") -> list[dict]:
    """Группы Traccar, доступные этому пользователю портала."""
    if not (cfg.traccar_api_url and cfg.traccar_token) or not username:
        return []
    out: dict[int, dict] = {}
    for uid in sorted(await user_traccar_ids(http, cfg, conn, username, email)):
        for g in await owner_groups(http, cfg, uid):
            out.setdefault(int(g["id"]), g)
    return sorted(out.values(), key=lambda g: str(g.get("name", "")).lower())


async def sync_family_groups(http, cfg, conn, family_id: int) -> None:
    """Права пользователей семьи на её группы устройств (/api/permissions userId+groupId):
    выдать недостающие, забрать выданные FamilyTime и больше не нужные — если ту же пару не
    держит другая семья. Выданные вручную не трогаются."""
    if not (cfg.traccar_api_url and cfg.traccar_token):
        return
    viewers = await family_viewers(conn, family_id)
    users = await traccar_users(http, cfg) if viewers else []
    if viewers and not users:
        return
    want_users = match_traccar_users(users, viewers)
    groups = {r["group_id"] for r in await conn.fetch(
        "SELECT group_id FROM ft_family_groups WHERE family_id = $1", family_id)}
    want = {(g, u) for g in groups for u in want_users}
    have = {(r["group_id"], r["user_id"]) for r in await conn.fetch(
        "SELECT group_id, user_id FROM ft_traccar_group_links WHERE family_id = $1", family_id)}
    h = {"Authorization": f"Bearer {cfg.traccar_token}"}
    for g, u in want - have:
        r = await http.post(cfg.traccar_api_url + "/permissions", json={"userId": u, "groupId": g},
                            headers=h, timeout=10)
        if r.status_code < 300 or r.status_code == 400:
            await conn.execute("INSERT INTO ft_traccar_group_links VALUES ($1, $2, $3) "
                               "ON CONFLICT DO NOTHING", family_id, g, u)
            log.info("traccar: группа %s → пользователю %s (семья %s)", g, u, family_id)
    for g, u in have - want:
        await conn.execute("DELETE FROM ft_traccar_group_links WHERE family_id = $1 AND group_id = $2 "
                           "AND user_id = $3", family_id, g, u)
        if await conn.fetchval("SELECT 1 FROM ft_traccar_group_links WHERE group_id = $1 AND user_id = $2",
                               g, u):
            continue                                  # ту же группу этому человеку даёт другая семья
        await http.request("DELETE", cfg.traccar_api_url + "/permissions",
                           json={"userId": u, "groupId": g}, headers=h, timeout=10)
        log.info("traccar: группа %s забрана у пользователя %s", g, u)
