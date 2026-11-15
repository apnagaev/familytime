"""1.3: время блокировки, extip/localIP, разброс точек, Traccar Client, семья/компания."""
import asyncio
import json
import math
import os
import random
import re
from datetime import datetime, timezone

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
    calls = []

    def handler(req: httpx.Request):
        calls.append(req)
        if req.url.host == "traccar":
            return httpx.Response(200, text="ok")
        return httpx.Response(404)

    cfg = Config(database_url=DSN, public_url="https://kids.example.com", session_secret="s" * 32,
                 enroll_secret="enroll", dev_login=True, oidc_issuer="https://sso.example.com/r",
                 traccar_osmand_url="http://traccar:5055", company_hosts=["work.example.com"],
                 geoip_url="")
    app = create_app(cfg)
    with TestClient(app, base_url="https://kids.example.com") as c:
        app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        yield c, calls


def login(c, user, admin=False, parent=True, host="kids.example.com"):
    c.cookies.clear()
    c.get(f"/dev-login?u={user}&parent={'1' if parent else ''}&admin={'1' if admin else ''}",
          headers={"host": host}, follow_redirects=False)
    page = c.get("/dashboard", headers={"host": host}).text
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


def enroll(c, name="pc.example.local"):
    tok = c.post("/api/agent/enroll", json={"hostname": name, "secret": "enroll"}).json()["token"]
    return {"Authorization": f"Bearer {tok}"}


def test_block_time(env):
    c, _ = env
    t = login(c, "root", admin=True)
    c.post("/children", data={"username": "ivan", "display_name": "Ваня", "csrf": t})
    now = datetime.now(timezone.utc).astimezone(c.app.state.cfg.tz)
    a = (now.replace(second=0, microsecond=0)).strftime("%H:%M")
    b = f"{(now.hour + 1) % 24:02d}:{now.minute:02d}"
    form = {"csrf": t}
    for d in range(7):
        form.update({f"limit{d}": "600", f"from{d}": "", f"to{d}": "",
                     f"bfrom{d}": a if d == now.weekday() else "",
                     f"bto{d}": b if d == now.weekday() else ""})
    assert "Правила сохранены" in c.post("/child/ivan/rules", data=form).text
    form["bto0"] = ""
    form["bfrom0"] = "22:00"
    assert "укажите оба времени" in c.post("/child/ivan/rules", data=form).text
    p = c.post("/api/agent/heartbeat", headers=enroll(c), json={
        "seq": 1, "caps": ["userlists"], "user": "ivan"}).json()["users"]["ivan"]
    assert p["mode"] == "blocked" and p["reason"] == "block"
    assert p["messages"]["block"] == f"Ваня, сейчас компьютером пользоваться нельзя (до {b})."
    assert p["rules"][str(now.weekday())]["block_from"] == a
    assert "компьютер заблокирован" in c.get("/child/ivan").text


def test_location_ext_ip_and_jitter(env):
    c, calls = env
    t = login(c, "root", admin=True)
    c.post("/settings", data={"csrf": t, "interval_minutes": "15", "lost_interval_minutes": "2",
                              "jitter": "1", "ip_locations": "95.31.1.0/24 55.75 37.61 300 Дом"})
    h = enroll(c)
    # дома: агент пришёл с внутреннего адреса, внешний узнал сам
    r = c.post("/api/agent/location", headers={**h, "X-Real-IP": "10.20.30.88"}, json={
        "wifi": [], "session": "active", "ext_ip": "95.31.1.20",
        "ext_geo": {"lat": 1, "lon": 2, "city": "X"}}).json()
    assert r["source"] == "known-ip"                 # известный адрес — по внешнему
    osm = [x for x in calls if x.url.host == "traccar"][-1].url.params
    assert osm["extip"] == "95.31.1.20" and osm["localIP"] == "10.20.30.88"
    lat, lon = float(osm["lat"]), float(osm["lon"])
    d = math.hypot((lat - 55.75) * 111320, (lon - 37.61) * 111320 * math.cos(math.radians(55.75)))
    assert 0 < d <= 300.5                             # разбросано внутри круга точности
    # без Wi-Fi и вне известных адресов: место, которое агент получил вместе с адресом
    n = len(calls)
    r = c.post("/api/agent/location", headers={**h, "X-Real-IP": "10.1.1.1"}, json={
        "wifi": [], "session": "active", "ext_ip": "203.0.113.9",
        "ext_geo": {"lat": 56.8, "lon": 60.6, "city": "Екатеринбург"}}).json()
    assert r["source"] == "geoip" and r["lat"] == 56.8
    assert [x.url.host for x in calls[n:]] == ["traccar"]      # ни Яндекса, ни GeoIP
    # разброс можно выключить
    c.post("/settings", data={"csrf": t, "interval_minutes": "15", "lost_interval_minutes": "2",
                              "ip_locations": "95.31.1.0/24 55.75 37.61 300 Дом"})
    c.post("/api/agent/location", headers={**h, "X-Real-IP": "10.20.30.88"}, json={
        "wifi": [], "session": "active", "ext_ip": "95.31.1.20"})
    osm = [x for x in calls if x.url.host == "traccar"][-1].url.params
    assert osm["lat"] == "55.750000" and osm["lon"] == "37.610000"


def test_jitter_is_uniform_in_disc():
    rnd = random.Random(1)
    pts = [locator.jitter(55.0, 37.0, 20, rnd) for _ in range(2000)]
    ds = [math.hypot((a - 55) * 111320, (b - 37) * 111320 * math.cos(math.radians(55)))
          for a, b in pts]
    assert max(ds) <= 20.01
    inner = sum(1 for x in ds if x <= 10) / len(ds)
    assert 0.2 < inner < 0.3                          # равномерно по площади: четверть в r/2
    assert locator.jitter(55, 37, 0) == (55, 37)
    far = [locator.jitter(55, 37, 50000, rnd) for _ in range(200)]
    assert max(abs(a - 55) for a, _ in far) * 111320 <= locator.JITTER_MAX + 1


def test_traccar_client_points(env):
    c, calls = env
    t = login(c, "root", admin=True)
    c.post("/settings", data={"csrf": t, "interval_minutes": "15", "lost_interval_minutes": "2",
                              "phone_ids": "my-phone", "jitter": "1"})
    # GET с параметрами — пересылается в Traccar как есть, точка запоминается
    r = c.get("/osmand?id=my-phone&lat=55.7520&lon=37.6175&accuracy=8&timestamp=1",
              headers={"X-Real-IP": "10.20.30.50"})
    assert r.status_code == 200 and r.text == "ok"
    fwd = [x for x in calls if x.url.host == "traccar"][-1]
    assert fwd.method == "GET" and fwd.url.params["id"] == "my-phone"
    assert fwd.headers["x-real-ip"] == "10.20.30.50"
    # JSON (новый Traccar Client) — POST с телом, пересылается тело
    body = {"device_id": "my-phone", "location": {"timestamp": "2026-11-15T10:00:00Z",
            "coords": {"latitude": 55.75, "longitude": 37.61, "accuracy": 12}}}
    r = c.post("/osmand", json=body, headers={"X-Real-IP": "95.31.1.20"})
    fwd = [x for x in calls if x.url.host == "traccar"][-1]
    assert fwd.method == "POST" and json.loads(fwd.content) == body
    # чужой телефон — пересылается, но не запоминается; mirror — без пересылки
    n = len(calls)
    c.get("/osmand?id=stranger&lat=1&lon=1&accuracy=5", headers={"X-Real-IP": "95.31.1.20"})
    c.get("/osmand/mirror?id=my-phone&lat=55.8&lon=37.4&accuracy=500",
          headers={"X-Real-IP": "95.31.1.20"})
    assert len([x for x in calls[n:] if x.url.host == "traccar"]) == 1
    rows = run_sql("SELECT net, device, accuracy FROM ft_phone_fixes ORDER BY id", fetch=True)
    assert [(r["net"], r["accuracy"]) for r in rows] == [
        ("10.20.30.0/24", 8), ("95.31.1.20", 12), ("95.31.1.20", 500)]
    assert "my-phone" in c.get("/settings").text

    h = enroll(c)
    # компьютер в той же домашней сети (другой внутренний адрес) — место телефона
    r = c.post("/api/agent/location", headers={**h, "X-Real-IP": "10.20.30.88"}, json={
        "wifi": [{"bssid": "aa:bb:cc:00:00:01", "rssi": -40}], "session": "active"}).json()
    assert r["source"] == "phone-gps" and r["lat"] == 55.7520 and r["accuracy"] == 8
    # по внешнему адресу; неточная точка (500 м) не используется
    r = c.post("/api/agent/location", headers={**h, "X-Real-IP": "10.9.9.9"}, json={
        "wifi": [], "session": "active", "ext_ip": "95.31.1.20"}).json()
    assert r["source"] == "phone-gps" and r["accuracy"] == 12
    # устаревшая точка не используется
    run_sql("UPDATE ft_phone_fixes SET at = now() - interval '2 hours'")
    r = c.post("/api/agent/location", headers={**h, "X-Real-IP": "10.20.30.88"}, json={
        "wifi": [], "session": "active"}).json()
    assert r["ok"] is False
    # нет координат — пересылается, но не сохраняется
    n = len(run_sql("SELECT 1 FROM ft_phone_fixes", fetch=True))
    c.get("/osmand?id=my-phone&batt=50", headers={"X-Real-IP": "95.31.1.20"})
    assert len(run_sql("SELECT 1 FROM ft_phone_fixes", fetch=True)) == n


def test_company_wording(env):
    c, _ = env
    # по имени сайта
    t = login(c, "boss", admin=True, host="work.example.com")
    page = c.get("/dashboard", headers={"host": "work.example.com"}).text
    assert "Добавить сотрудника" in page and "ребёнка" not in page
    page = c.get("/dashboard", headers={"host": "kids.example.com"}).text
    assert "Добавить ребёнка" in page
    # тип семьи → тексты на компьютерах
    c.post("/children", data={"username": "petrov", "display_name": "Пётр", "csrf": t})
    fid = run_sql("SELECT id FROM ft_families", fetch=True)[0]["id"]
    c.post(f"/family/{fid}", data={"section": "kind", "kind": "company", "csrf": t})
    p = c.post("/api/agent/heartbeat", headers=enroll(c), json={
        "seq": 1, "caps": ["userlists"], "user": "petrov"}).json()["users"]["petrov"]
    assert "личное время" in p["messages"]["limit"].lower()
    assert p["messages"]["restricted"] == "Сейчас работают только рабочие программы и сайты."
    fam = c.get("/family", headers={"host": "work.example.com"}).text
    assert "Компания" in fam or "компания" in fam


def test_company_wording_switch_without_hosts(env):
    c, _ = env
    c.app.state.cfg.company_hosts = []
    t = login(c, "boss", admin=True)
    assert "Добавить ребёнка" in c.get("/dashboard").text
    c.post("/settings", data={"csrf": t, "interval_minutes": "15", "lost_interval_minutes": "2",
                              "portal_terms": "company"})
    page = c.get("/dashboard").text
    assert "Добавить сотрудника" in page and "Сотрудники" in page
    assert "Руководители" in c.get("/family").text or "руководител" in c.get("/family").text
