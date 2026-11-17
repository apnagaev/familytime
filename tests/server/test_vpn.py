"""Точки устройств VPN (vpngeo) через /osmand и автоматическое создание устройств в Traccar."""
import asyncio
import json
import math
import os
import re

import asyncpg
import httpx
import pytest
from fastapi.testclient import TestClient

from app import lists, locator
from app.config import Config
from app.main import create_app

DSN = os.environ["TEST_DATABASE_URL"]


def run_sql(sql, *args, fetch=False):
    async def go():
        conn = await asyncpg.connect(DSN)
        try:
            return await (conn.fetch(sql, *args) if fetch else conn.execute(sql, *args))
        finally:
            await conn.close()
    return asyncio.run(go())


@pytest.fixture()
def env():
    run_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    lists._cache.clear()
    locator._group_ids.clear()
    locator._ensured.clear()
    locator._all_devices.update(at=float("-inf"), by_uid={})
    locator._device_ids.clear()
    locator._linked.clear()
    locator._users.update(at=float("-inf"), items=[])
    calls = []
    api = {"groups": [], "devices": {}, "next": 100, "perms": set(),
           "users": [{"id": 11, "email": "mom@example.com", "name": "Мама"},
                     {"id": 12, "login": "dad", "email": "dad@other.example"}]}

    def handler(req: httpx.Request):
        calls.append(req)
        h = req.url.host
        if h == "traccar":
            return httpx.Response(200, text="ok")
        if h == "locator.api.maps.yandex.ru":
            return httpx.Response(200, json={"location": {"point": {"lat": 59.9, "lon": 30.3},
                                                          "accuracy": 3000}})
        if h == "ip-api.com":
            return httpx.Response(200, json={"status": "success", "isp": "VPN ISP"})
        if h == "tapi":
            assert req.headers["authorization"] == "Bearer tok"
            path = req.url.path
            if path == "/api/groups" and req.method == "GET":
                # без all — только группы владельца токена; с all — и чужие
                return httpx.Response(200, json=[g for g in api["groups"]
                                                 if req.url.params.get("all") == "true"
                                                 or g.get("_own", True)])
            if path == "/api/groups" and req.method == "POST":
                g = {"id": api["next"], **json.loads(req.content)}
                api["next"] += 1
                api["groups"].append(g)
                return httpx.Response(200, json=g)
            if path == "/api/devices" and req.method == "GET":
                if req.url.params.get("all") == "true":
                    return httpx.Response(200, json=list(api["devices"].values()))
                # как Traccar: по uniqueId — только устройства, привязанные к владельцу токена
                d = api["devices"].get(req.url.params["uniqueId"])
                return httpx.Response(200, json=[d] if d and d.get("_linked", True) else [])
            if path == "/api/devices" and req.method == "POST":
                if json.loads(req.content)["uniqueId"] in api["devices"]:
                    return httpx.Response(400, text="Duplicate entry")
                d = {"id": api["next"], **json.loads(req.content)}
                api["next"] += 1
                api["devices"][d["uniqueId"]] = d
                return httpx.Response(200, json=d)
            if path == "/api/users" and req.method == "GET":
                return httpx.Response(200, json=api["users"])
            if path == "/api/permissions":
                b = json.loads(req.content)
                key = (b["userId"], b["deviceId"])
                if req.method == "POST":
                    if key in api["perms"]:
                        return httpx.Response(400, text="Duplicate")
                    api["perms"].add(key)
                    return httpx.Response(204)
                if req.method == "DELETE":
                    api["perms"].discard(key)
                    return httpx.Response(204)
            m = re.fullmatch(r"/api/devices/(\d+)", path)
            if m and req.method == "PUT":
                d = json.loads(req.content)
                api["devices"][d["uniqueId"]] = d
                return httpx.Response(200, json=d)
        return httpx.Response(404)

    cfg = Config(database_url=DSN, public_url="https://kids.example.com", session_secret="s" * 32,
                 enroll_secret="enroll", dev_login=True, oidc_issuer="https://sso.example.com/r",
                 traccar_osmand_url="http://traccar:5055", traccar_api_url="http://tapi/api",
                 traccar_token="tok", yandex_locator_keys=["k"], geoip_url="")
    app = create_app(cfg)
    with TestClient(app, base_url="https://kids.example.com") as c:
        app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        yield c, calls, api


def login(c):
    c.cookies.clear()
    c.get("/dev-login?u=root&parent=1&admin=1", follow_redirects=False)
    page = c.get("/settings").text
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


def login_as(c, user, email=""):
    c.cookies.clear()
    c.get(f"/dev-login?u={user}&parent=1&email={email}", follow_redirects=False)
    return re.search(r'name="csrf" value="([^"]+)"', c.get("/dashboard").text).group(1)


def save_settings(c, t, **extra):
    data = {"csrf": t, "interval_minutes": "15", "lost_interval_minutes": "2", "jitter": "",
            "phone_ids": "", "vpn_prefixes": "wg-\nvpn_", "traccar_group_pc": "PC",
            "traccar_group_vpn": "VPN", "traccar_group_phone": "",
            "ip_locations": "10.20.30.64/26 55.75 37.61 5 home-lan\n"
                            "95.31.7.19/32 55.75 37.61 5 home-wan\n"
                            "10.20.40.0/24 55.70 37.50 5 dc"}
    data.update(extra)
    assert "Сохранено" in c.post("/settings", data=data).text


def osm(calls):
    return [x for x in calls if x.url.host == "traccar"][-1]


def test_vpn_points_by_extip_localip(env):
    c, calls, api = env
    t = login(c)
    save_settings(c, t)
    page = c.get("/settings").text
    assert "vpn_" in page and 'value="VPN"' in page
    wg = {"X-Real-IP": "10.20.40.5"}        # сервер WireGuard — в «dc», но это не место пира
    # внутренний адрес в туннеле из известной подсети; смещение и место vpngeo игнорируются
    c.get("/osmand?id=wg-ap_ph&lat=55.0&lon=37.0&accuracy=500&extip=95.31.1.20"
          "&localip=10.20.30.70&source=known-net&place=old&timestamp=1", headers=wg)
    q = osm(calls).url.params
    assert (q["lat"], q["lon"], q["accuracy"], q["source"], q["place"]) == \
        ("55.750000", "37.610000", "5", "known-ip", "home-lan")
    assert q["ip"] == "95.31.1.20" and q["operator"] == "VPN ISP"
    assert q.get_list("source") == ["known-ip"] and q.get_list("place") == ["home-lan"]
    # внешний адрес точнее? — самая узкая подсеть из обоих (/32 home-wan шире /26? нет: /32 уже)
    c.get("/osmand?id=wg-ap_ph&lat=1&lon=1&extip=95.31.7.19&localip=10.20.30.70", headers=wg)
    assert osm(calls).url.params["place"] == "home-wan"
    # нет в таблице — Яндекс по extip, месяц из кеша
    n = len([x for x in calls if x.url.host == "locator.api.maps.yandex.ru"])
    for _ in range(2):
        c.get("/osmand?id=vpn_laptop&lat=1&lon=1&extip=8.8.8.8&localip=10.9.9.9", headers=wg)
    q = osm(calls).url.params
    assert (q["lat"], q["lon"], q["source"]) == ("59.900000", "30.300000", "yandex-ip")
    assert q["accuracy"] == "1"                     # город по IP — 1 м, без синего круга
    assert len([x for x in calls if x.url.host == "locator.api.maps.yandex.ru"]) == n + 1
    row = run_sql("SELECT fetched_at FROM ft_geoip WHERE ip = '8.8.8.8'", fetch=True)
    assert row and locator.GEOIP_TTL.days == 30
    # разброс как у компьютеров FamilyTime — в круге точности
    save_settings(c, t, jitter="1")
    c.get("/osmand?id=wg-ap_ph&lat=1&lon=1&extip=95.31.7.19", headers=wg)
    q = osm(calls).url.params
    d = math.hypot((float(q["lat"]) - 55.75) * 111320,
                   (float(q["lon"]) - 37.61) * 111320 * math.cos(math.radians(55.75)))
    assert d <= 5.5
    # без префикса — обычный телефон: адрес соединения, без подмены
    c.get("/osmand?id=phone1&lat=1&lon=2&extip=95.31.7.19", headers=wg)
    q = osm(calls).url.params
    assert q["lat"] == "1" and q["ip"] == "10.20.40.5"


def test_traccar_devices_created_in_groups(env):
    c, calls, api = env
    t = login(c)
    save_settings(c, t)
    wg = {"X-Real-IP": "10.20.40.5"}
    c.get("/osmand?id=wg-ap_ph&lat=1&lon=1&extip=95.31.7.19", headers=wg)
    c.get("/osmand?id=wg-ap_ph&lat=1&lon=1&extip=95.31.7.19", headers=wg)
    c.get("/osmand?id=82750699&lat=1&lon=1", headers={"X-Real-IP": "95.31.1.20"})
    groups = {g["name"]: g["id"] for g in api["groups"]}
    assert set(groups) == {"VPN"}
    assert api["devices"]["wg-ap_ph"]["groupId"] == groups["VPN"]
    assert "groupId" not in api["devices"]["82750699"]
    # повторная точка — без запросов к API (проверено один раз за запуск)
    dev_calls = [x for x in calls if x.url.host == "tapi" and x.url.path == "/api/devices"]
    assert len([x for x in dev_calls if x.method == "POST"]) == 2
    # компьютер с агентом — в группу PC; уже существующий в другой группе — переносится
    api["devices"]["pc.example.local"] = {"id": 5, "uniqueId": "pc.example.local", "name": "pc",
                                          "groupId": 99}
    tok = c.post("/api/agent/enroll", json={"hostname": "pc.example.local", "secret": "enroll"}).json()["token"]
    c.post("/api/agent/location", headers={"Authorization": f"Bearer {tok}", "X-Real-IP": "10.20.30.70"},
           json={"wifi": [], "session": "active"})
    groups = {g["name"]: g["id"] for g in api["groups"]}
    assert api["devices"]["pc.example.local"]["groupId"] == groups["PC"]
    assert any(x.method == "PUT" for x in calls if x.url.host == "tapi")


def test_unlinked_device_moved_to_group(env):
    """Устройство заведено не владельцем токена (vpngeo, вручную) — по ?uniqueId= не видно,
    находится через ?all=true и переносится в группу."""
    c, calls, api = env
    t = login(c)
    save_settings(c, t)
    api["devices"]["wg-test"] = {"id": 7, "uniqueId": "wg-test", "name": "test", "groupId": 55,
                                 "_linked": False}
    c.get("/osmand?id=wg-test&lat=1&lon=1&extip=95.31.7.19", headers={"X-Real-IP": "10.20.40.5"})
    groups = {g["name"]: g["id"] for g in api["groups"]}
    assert api["devices"]["wg-test"]["groupId"] == groups["VPN"]
    assert not any(x.method == "POST" and x.url.path == "/api/devices" for x in calls
                   if x.url.host == "tapi")


def test_foreign_group_with_same_name_ignored(env):
    """На общем Traccar у другого пользователя своя группа «VPN» — устройство в неё не уходит."""
    c, calls, api = env
    t = login(c)
    save_settings(c, t)
    api["groups"].append({"id": 900, "name": "VPN", "_own": False})
    c.get("/osmand?id=wg-x&lat=1&lon=1&extip=95.31.7.19", headers={"X-Real-IP": "10.20.40.5"})
    own = [g for g in api["groups"] if g["name"] == "VPN" and g.get("_own", True)]
    assert len(own) == 1 and api["devices"]["wg-x"]["groupId"] == own[0]["id"] != 900
    # номер группы вместо имени
    locator._ensured.clear()
    save_settings(c, t, traccar_group_vpn="900")
    c.get("/osmand?id=wg-x&lat=1&lon=1&extip=95.31.7.19", headers={"X-Real-IP": "10.20.40.5"})
    assert api["devices"]["wg-x"]["groupId"] == 900


def test_family_devices_on_family_users_map(env):
    """Компьютеры и телефоны семьи — на карту её пользователей Traccar (права на устройство)."""
    c, calls, api = env
    t = login(c)
    save_settings(c, t)
    # мама входила через Keycloak с подтверждённой почтой — её найдём в Traccar по почте
    c.cookies.clear()
    c.get("/dev-login?u=mom&parent=1&email=mom@example.com", follow_redirects=False)
    tm = re.search(r'name="csrf" value="([^"]+)"', c.get("/dashboard").text).group(1)
    c.post("/children", data={"username": "ivan", "display_name": "Ваня", "csrf": tm})
    fid = run_sql("SELECT id FROM ft_families", fetch=True)[0]["id"]
    tok = c.post("/api/agent/enroll", json={"hostname": "kid.example.local", "secret": "enroll"}).json()["token"]
    run_sql("UPDATE ft_devices SET family_id = $1", fid)
    h = {"Authorization": f"Bearer {tok}", "X-Real-IP": "10.20.30.70"}
    c.post("/api/agent/location", headers=h, json={"wifi": [], "session": "active"})
    did = api["devices"]["kid.example.local"]["id"]
    assert api["perms"] == {(11, did)}
    # явный список в семье: папа по логину; маме права забираются
    r = c.post(f"/family/{fid}", data={"csrf": tm, "section": "traccar", "traccar_users": "dad"})
    assert "Сохранено" in r.text and "Карта Traccar" in r.text
    c.post("/api/agent/location", headers=h, json={"wifi": [], "session": "active"})
    assert api["perms"] == {(12, did)}
    # родитель не может привязать готовый (чужой) идентификатор — только получить новый
    r = c.post(f"/family/{fid}", data={"csrf": tm, "section": "device_bind", "unique_id": "99999"})
    assert r.status_code == 403
    r = c.post(f"/family/{fid}", data={"csrf": tm, "section": "device_new", "name": "Телефон Вани"})
    phone = re.search(r"Идентификатор для «Телефон Вани»: (\d{12})", r.text).group(1)
    assert phone in c.get("/family").text
    # администратор привязывает существующее устройство VPN
    ta = login(c)
    c.post(f"/family/{fid}", data={"csrf": ta, "section": "device_bind", "unique_id": "wg-ivan_ph",
                                   "name": "VPN Вани"})
    c.get(f"/osmand?id={phone}&lat=1&lon=1", headers={"X-Real-IP": "95.31.1.20"})
    c.get("/osmand?id=wg-ivan_ph&lat=1&lon=1&extip=95.31.7.19", headers={"X-Real-IP": "10.20.40.5"})
    c.get("/osmand?id=99999&lat=1&lon=1", headers={"X-Real-IP": "95.31.1.20"})
    ph, vpn, other = (api["devices"][k]["id"] for k in (phone, "wg-ivan_ph", "99999"))
    assert api["devices"][phone]["name"] == "Телефон Вани"
    assert {(12, ph), (12, vpn)} <= api["perms"] and not any(d == other for _, d in api["perms"])
    # убрать из семьи — права забираются при следующей точке
    tm2 = login_as(c, "mom", "mom@example.com")
    c.post(f"/family/{fid}", data={"csrf": tm2, "section": "device_remove", "unique_id": "wg-ivan_ph"})
    c.get("/osmand?id=wg-ivan_ph&lat=1&lon=1&extip=95.31.7.19", headers={"X-Real-IP": "10.20.40.5"})
    assert (12, vpn) not in api["perms"]
    # телефон семьи получает место из «Известных адресов», как телефоны из общих настроек
    c.get(f"/osmand?id={phone}&lat=1&lon=1", headers={"X-Real-IP": "10.20.30.70"})
    assert osm(calls).url.params["source"] == "known-ip"
