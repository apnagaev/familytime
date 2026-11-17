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
    api = {"groups": [], "devices": {}, "next": 100, "perms": set(), "owners": {},
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
                if "userId" in req.url.params:          # группы пользователя
                    ids = api.get("user_groups", {}).get(int(req.url.params["userId"]), [])
                    return httpx.Response(200, json=[g for g in api["groups"] if g["id"] in ids])
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
                if "userId" in req.url.params:          # устройства пользователя
                    u = int(req.url.params["userId"])
                    return httpx.Response(200, json=[d for k, d in api["devices"].items()
                                                     if u in api["owners"].get(k, set())])
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
                key = (b["userId"], b["deviceId"]) if "deviceId" in b else (b["userId"], ("g", b["groupId"]))
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
            "vpn_prefixes": "wg-\nvpn_", "traccar_group_pc": "PC",
            "ip_locations": "10.20.30.64/26 55.75 37.61 5 home-lan\n"
                            "95.31.7.19/32 55.75 37.61 5 home-wan\n"
                            "10.20.40.0/24 55.70 37.50 5 dc"}
    data.update(extra)
    assert "Сохранено" in c.post("/settings", data=data).text


def osm(calls):
    return [x for x in calls if x.url.host == "traccar"][-1]


def family_device(uid, fid=None):
    if fid is None:
        fid = run_sql("INSERT INTO ft_families (name) VALUES ('Семья') RETURNING id", fetch=True)[0]["id"]
    run_sql("INSERT INTO ft_family_traccar (unique_id, family_id) VALUES ($1, $2)", uid, fid)
    return fid


def test_vpn_points_by_extip_localip(env):
    c, calls, api = env
    t = login(c)
    save_settings(c, t)
    page = c.get("/settings").text
    assert "vpn_" in page and 'value="PC"' in page
    fid = family_device("wg-ap_ph")
    family_device("vpn_laptop", fid)
    wg = {"X-Real-IP": "10.20.40.5"}        # сервер WireGuard — в «dc», но это не место пира
    c.get("/osmand?id=wg-ap_ph&lat=55.0&lon=37.0&accuracy=500&extip=95.31.1.20"
          "&localip=10.20.30.70&source=known-net&place=old&timestamp=1", headers=wg)
    q = osm(calls).url.params
    assert (q["lat"], q["lon"], q["accuracy"], q["source"], q["place"]) == \
        ("55.750000", "37.610000", "5", "known-ip", "home-lan")
    assert q["ip"] == "95.31.1.20" and q["operator"] == "VPN ISP"
    assert q.get_list("source") == ["known-ip"] and q.get_list("place") == ["home-lan"]
    # самая узкая подсеть из обоих адресов
    c.get("/osmand?id=wg-ap_ph&lat=1&lon=1&extip=95.31.7.19&localip=10.20.30.70", headers=wg)
    assert osm(calls).url.params["place"] == "home-wan"
    # нет в таблице — Яндекс по extip, месяц из кеша; точность в Traccar — 1 м
    n = len([x for x in calls if x.url.host == "locator.api.maps.yandex.ru"])
    for _ in range(2):
        c.get("/osmand?id=vpn_laptop&lat=1&lon=1&extip=8.8.8.8&localip=10.9.9.9", headers=wg)
    q = osm(calls).url.params
    assert (q["lat"], q["lon"], q["source"], q["accuracy"]) == ("59.900000", "30.300000", "yandex-ip", "1")
    assert len([x for x in calls if x.url.host == "locator.api.maps.yandex.ru"]) == n + 1
    assert locator.GEOIP_TTL.days == 30
    # разброс как у компьютеров FamilyTime
    save_settings(c, t, jitter="1")
    c.get("/osmand?id=wg-ap_ph&lat=1&lon=1&extip=95.31.7.19", headers=wg)
    q = osm(calls).url.params
    d = math.hypot((float(q["lat"]) - 55.75) * 111320,
                   (float(q["lon"]) - 37.61) * 111320 * math.cos(math.radians(55.75)))
    assert d <= 5.5
    # телефоны и VPN FamilyTime в Traccar не создаёт
    assert not any(x.method == "POST" and x.url.path == "/api/devices" for x in calls
                   if x.url.host == "tapi")


def test_computers_created_and_grouped(env):
    """Компьютеры с агентом — создаются в группе PC; существующий (и не привязанный к владельцу
    токена) переносится; одноимённая чужая группа не берётся; номер группы вместо имени."""
    c, calls, api = env
    t = login(c)
    save_settings(c, t)
    api["groups"].append({"id": 900, "name": "PC", "_own": False})
    api["devices"]["old.example.local"] = {"id": 5, "uniqueId": "old.example.local", "name": "old",
                                           "groupId": 99, "_linked": False}

    def locate(host):
        tok = c.post("/api/agent/enroll", json={"hostname": host, "secret": "enroll"}).json()["token"]
        c.post("/api/agent/location", headers={"Authorization": f"Bearer {tok}",
                                               "X-Real-IP": "10.20.30.70"},
               json={"wifi": [], "session": "active"})
    locate("new.example.local")
    locate("old.example.local")
    own = [g for g in api["groups"] if g["name"] == "PC" and g.get("_own", True)]
    assert len(own) == 1 and own[0]["id"] != 900
    assert api["devices"]["new.example.local"]["groupId"] == own[0]["id"]
    assert api["devices"]["new.example.local"]["name"] == "new"
    assert api["devices"]["old.example.local"]["groupId"] == own[0]["id"]
    assert len([x for x in calls if x.url.host == "tapi" and x.method == "POST"
                and x.url.path == "/api/devices"]) == 1
    # группа назначается один раз: смена настройки старые устройства не трогает,
    # новые идут в новую группу (номер группы вместо имени)
    locator._ensured.clear()
    save_settings(c, t, traccar_group_pc="900")
    locate("new.example.local")
    assert api["devices"]["new.example.local"]["groupId"] == own[0]["id"]
    locate("third.example.local")
    assert api["devices"]["third.example.local"]["groupId"] == 900


def test_family_devices_only_from_parents(env):
    """В семью — только устройство Traccar кого-то из родителей; оно — на карту пользователей
    семьи и обогащается; остальные личные."""
    c, calls, api = env
    t = login(c)
    save_settings(c, t)
    tm = login_as(c, "mom", "mom@example.com")        # мама входила через Keycloak с почтой
    c.post("/children", data={"username": "ivan", "display_name": "Ваня", "csrf": tm})
    fid = run_sql("SELECT id FROM ft_families", fetch=True)[0]["id"]
    # папа — второй родитель семьи
    run_sql("INSERT INTO ft_family_parents VALUES ($1, 'dad')", fid)
    # в Traccar: телефон мамы, телефон папы, телефон чужого человека
    api["devices"]["82750699"] = {"id": 41, "uniqueId": "82750699", "name": "Телефон мамы"}
    api["devices"]["77777"] = {"id": 43, "uniqueId": "77777", "name": "Телефон папы"}
    api["devices"]["99999"] = {"id": 42, "uniqueId": "99999", "name": "Чужой"}
    api["owners"] = {"82750699": {11}, "77777": {12}, "99999": {77}}
    page = c.get("/family").text
    assert "Телефон мамы (82750699)" in page and "77777" not in page and "99999" not in page
    # ни чужое, ни папино мама не добавит, даже подставив идентификатор
    for other in ("99999", "77777"):
        r = c.post(f"/family/{fid}", data={"csrf": tm, "section": "device_add", "unique_id": other})
        assert "нет среди ваших устройств" in r.text
    # папа добавляет своё сам
    td = login_as(c, "dad", "dad@other.example")
    assert "Телефон папы (77777)" in c.get("/family").text
    r = c.post(f"/family/{fid}", data={"csrf": td, "section": "device_add", "unique_id": "77777"})
    assert "<code>77777</code>" in r.text
    tm = login_as(c, "mom", "mom@example.com")
    r = c.post(f"/family/{fid}", data={"csrf": tm, "section": "device_add", "unique_id": "82750699"})
    assert "Сохранено" in r.text and "<code>82750699</code>" in r.text
    # кому показывать: папа по логину — его права выдаются при точке; телефон обогащается
    c.post(f"/family/{fid}", data={"csrf": tm, "section": "traccar", "traccar_users": "dad"})
    c.get("/osmand?id=82750699&lat=1&lon=1", headers={"X-Real-IP": "10.20.30.70"})
    q = osm(calls).url.params
    assert q["source"] == "known-ip" and (12, 41) in api["perms"]
    # чужое — тоже обогащается, но на карту семьи не попадает
    c.get("/osmand?id=99999&lat=1&lon=1", headers={"X-Real-IP": "10.20.30.70"})
    assert osm(calls).url.params["source"] == "known-ip" and not any(d == 42 for _, d in api["perms"])
    # компьютер семьи — тоже на карту папы
    tok = c.post("/api/agent/enroll", json={"hostname": "kid.example.local", "secret": "enroll"}).json()["token"]
    run_sql("UPDATE ft_devices SET family_id = $1", fid)
    c.post("/api/agent/location", headers={"Authorization": f"Bearer {tok}", "X-Real-IP": "10.20.30.70"},
           json={"wifi": [], "session": "active"})
    assert (12, api["devices"]["kid.example.local"]["id"]) in api["perms"]
    # убрать из семьи — снова личное: права забираются
    c.post(f"/family/{fid}", data={"csrf": tm, "section": "device_remove", "unique_id": "82750699"})
    c.get("/osmand?id=82750699&lat=1&lon=1", headers={"X-Real-IP": "10.20.30.70"})
    assert (12, 41) not in api["perms"]
    # «добавить все мои»
    r = c.post(f"/family/{fid}", data={"csrf": tm, "section": "device_add_all"})
    assert "Добавлено ваших устройств: 1" in r.text
    # администратор: выбор семьи списком на вкладке «Семьи»; VPN из Traccar тоже в списке
    api["devices"]["wg-peer"] = {"id": 50, "uniqueId": "wg-peer", "name": "Пир VPN", "_linked": False}
    locator._all_devices.update(at=float("-inf"), by_uid={})
    ta = login(c)
    assert "Устройства Traccar всех семей" in c.get("/family").text and "Добавить в семью" not in c.get("/family").text
    page = c.get("/traccar").text
    assert "Компьютеры с агентом" in page and "<code>99999</code>" in page
    assert "<code>wg-peer</code> Пир VPN" in page and "<option value=\"%d\"" % fid in page
    agents, others = page.split("Остальные устройства Traccar")
    assert "<code>kid.example.local</code>" in agents and "kid.example.local" not in others
    r = c.post("/devices/osmand", data={"csrf": ta, "unique_id": "99999", "family_id": str(fid)})
    assert "Сохранено" in r.text
    assert run_sql("SELECT family_id FROM ft_family_traccar WHERE unique_id='99999'", fetch=True)
    c.post("/devices/osmand", data={"csrf": ta, "unique_id": "99999", "family_id": str(fid),
                                    "action": "remove"})
    assert not run_sql("SELECT 1 FROM ft_family_traccar WHERE unique_id='99999'", fetch=True)
    # одно устройство может быть в нескольких семьях
    fid2 = run_sql("INSERT INTO ft_families (name) VALUES ('Другая') RETURNING id", fetch=True)[0]["id"]
    for f in (fid, fid2):
        c.post("/devices/osmand", data={"csrf": ta, "unique_id": "99999", "family_id": str(f)})
    assert len(run_sql("SELECT 1 FROM ft_family_traccar WHERE unique_id='99999'", fetch=True)) == 2
    # компьютер с агентом — ещё и на карту другой семьи
    run_sql("INSERT INTO ft_family_parents VALUES ($1, 'stranger')", fid2)
    api["users"].append({"id": 77, "login": "stranger", "email": ""})
    locator._users.update(at=float("-inf"), items=[])
    c.post("/devices/osmand", data={"csrf": ta, "unique_id": "kid.example.local", "family_id": str(fid2)})
    c.post("/api/agent/location", headers={"Authorization": f"Bearer {tok}", "X-Real-IP": "10.20.30.70"},
           json={"wifi": [], "session": "active"})
    kid = api["devices"]["kid.example.local"]["id"]
    assert (12, kid) in api["perms"]
    assert (77, kid) in api["perms"]
    # выбор семьи на странице «Семьи»: показывается одна семья
    page = c.get(f"/family?f={fid2}").text
    assert 'name="f"' in page and f'action="/family/{fid2}"' in page and f'action="/family/{fid}"' not in page
    r = c.post(f"/family/{fid2}", data={"csrf": ta, "section": "name", "name": "Другая"})
    assert str(r.url).endswith(f"f={fid2}&ok=%D0%A1%D0%BE%D1%85%D1%80%D0%B0%D0%BD%D0%B5%D0%BD%D0%BE")


def test_groups_once_and_family_groups(env):
    """Группы vpn/pc/mobile — из семьи, назначаются один раз; группы устройств семьи —
    права пользователей семьи на группу; «добавить все» у администратора."""
    c, calls, api = env
    t = login(c)
    save_settings(c, t, traccar_group_pc="PC", traccar_group_vpn="VPN", traccar_group_phone="mobile")
    fid = run_sql("INSERT INTO ft_families (name) VALUES ('Ивановы') RETURNING id", fetch=True)[0]["id"]
    run_sql("INSERT INTO ft_family_parents VALUES ($1, 'mom')", fid)
    run_sql("INSERT INTO ft_people (username, email) VALUES ('mom', 'mom@example.com')")
    r = c.post(f"/family/{fid}", data={"csrf": t, "section": "group_names", "group_pc": "Ивановы PC",
                                       "group_vpn": "", "group_mobile": "Ивановы mobile"})
    assert "Сохранено" in r.text
    api["devices"]["555"] = {"id": 60, "uniqueId": "555", "name": "Телефон", "groupId": None}
    api["devices"]["wg-a"] = {"id": 61, "uniqueId": "wg-a", "name": "VPN", "groupId": None}
    run_sql("INSERT INTO ft_family_traccar (unique_id, family_id) VALUES ('555', $1)", fid)
    c.get("/osmand?id=555&lat=1&lon=1", headers={"X-Real-IP": "95.31.1.20"})
    c.get("/osmand?id=wg-a&lat=1&lon=1&extip=95.31.1.20", headers={"X-Real-IP": "10.20.40.5"})
    c.get("/osmand?id=nobody&lat=1&lon=1", headers={"X-Real-IP": "95.31.1.20"})   # нет в Traccar
    groups = {g["name"]: g["id"] for g in api["groups"]}
    assert api["devices"]["555"]["groupId"] == groups["Ивановы mobile"]   # из семьи
    assert api["devices"]["wg-a"]["groupId"] == groups["VPN"]             # не в семье — по умолчанию
    assert "nobody" not in api["devices"]                                 # телефоны не создаются
    # перенесли в Traccar вручную — FamilyTime больше не трогает (только первое обращение)
    api["devices"]["555"]["groupId"] = 999
    locator._ensured.clear()
    c.get("/osmand?id=555&lat=1&lon=1", headers={"X-Real-IP": "95.31.1.20"})
    assert api["devices"]["555"]["groupId"] == 999
    # компьютер семьи — в её группу PC, тоже один раз
    tok = c.post("/api/agent/enroll", json={"hostname": "pc1.example.local", "secret": "enroll"}).json()["token"]
    run_sql("UPDATE ft_devices SET family_id = $1", fid)
    c.post("/api/agent/location", headers={"Authorization": f"Bearer {tok}", "X-Real-IP": "10.20.30.70"},
           json={"wifi": [], "session": "active"})
    groups = {g["name"]: g["id"] for g in api["groups"]}
    assert api["devices"]["pc1.example.local"]["groupId"] == groups["Ивановы PC"]
    # группа устройств в семье: администратор выбирает из своих групп; права — маме на группу
    api["groups"].append({"id": 700, "name": "Дача"})
    r = c.post(f"/family/{fid}", data={"csrf": t, "section": "group_add", "group_id": "700"})
    assert "Сохранено" in r.text and "Дача" in c.get("/family").text
    assert (11, ("g", 700)) in api["perms"]
    # родитель — только свои группы
    api["user_groups"] = {11: [701]}
    api["groups"].append({"id": 701, "name": "Мамина", "_own": False})
    api["groups"].append({"id": 702, "name": "Чужая", "_own": False})
    tm = login_as(c, "mom", "mom@example.com")
    page = c.get("/family").text
    assert "Мамина (#701)" in page and "Чужая" not in page
    r = c.post(f"/family/{fid}", data={"csrf": tm, "section": "group_add", "group_id": "702"})
    assert "нет среди ваших групп" in r.text
    # убрать группу — права забираются
    c.post(f"/family/{fid}", data={"csrf": tm, "section": "group_remove", "group_id": "700"})
    assert (11, ("g", 700)) not in api["perms"]
    # администратор: «добавить все» только VPN
    ta = login(c)
    r = c.post("/devices/osmand/all", data={"csrf": ta, "family_id": str(fid), "only": "vpn"})
    assert "Добавлено устройств:" in r.text
    ids = {r["unique_id"] for r in run_sql("SELECT unique_id FROM ft_family_traccar WHERE family_id = $1",
                                           fid, fetch=True)}
    assert "wg-a" in ids and "nobody" not in ids
