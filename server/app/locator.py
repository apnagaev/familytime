"""Определение места по Wi-Fi и IP через Яндекс Локатор и отправка точки в Traccar (OsmAnd)."""
from __future__ import annotations

import ipaddress
import logging
import random
import re
from dataclasses import dataclass
from datetime import datetime

import httpx

log = logging.getLogger("familytime.locator")

_BSSID = re.compile(r"^[0-9a-f]{12}$")


@dataclass
class Fix:
    lat: float
    lon: float
    accuracy: float
    source: str


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
        src = "wifi" if "wifi" in body else "ip"
        return Fix(float(loc["point"]["lat"]), float(loc["point"]["lon"]),
                   float(loc.get("accuracy") or 0), src)
    return None


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
        "source": f"yandex-{fix.source}",
        "wifiCount": len(body.wifi),
        "session": body.session,
        "channel": "familytime",
    }
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
