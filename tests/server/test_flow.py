"""Сценарий целиком на настоящей PostgreSQL: агент, учёт, лимит, портал, запрос времени, локация."""
import json
import os
import re
import time as _time
from datetime import datetime, timezone

import asyncpg
import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Config
from app.main import create_app

DSN = os.environ["TEST_DATABASE_URL"]


async def _reset():
    conn = await asyncpg.connect(DSN)
    await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    await conn.close()


@pytest.fixture()
def calls():
    return []


@pytest.fixture()
def client(calls):
    import asyncio
    asyncio.run(_reset())
    cfg = Config(
        database_url=DSN, public_url="https://kids.example.com", session_secret="s" * 32,
        enroll_secret="enroll", dev_login=True, oidc_issuer="https://sso.example.com/realms/home",
        yandex_locator_keys=["bad", "good"], traccar_osmand_url="http://traccar:5055",
        traccar_api_url="http://traccar:8082/api", traccar_token="tok",
        telegram_token="T", telegram_chat_ids=["100"],
    )

    def handler(req: httpx.Request):
        calls.append(req)
        if req.url.host == "locator.api.maps.yandex.ru":
            if req.url.params["apikey"] == "bad":
                return httpx.Response(403, text="Access denied")
            return httpx.Response(200, json={"location": {"point": {"lat": 55.89, "lon": 37.41},
                                                          "accuracy": 35}})
        if req.url.host == "traccar" and req.url.path == "/api/devices" and req.method == "GET":
            return httpx.Response(200, json=[])
        if req.url.host == "traccar":
            return httpx.Response(200, json={"id": 1})
        if req.url.host == "api.telegram.org" and req.url.path.endswith("getUpdates"):
            return httpx.Response(200, json={"ok": True, "result": []})
        if req.url.host == "api.telegram.org":
            return httpx.Response(200, json={"ok": True, "result": {"message_id": 7}})
        return httpx.Response(404)

    app = create_app(cfg)
    with TestClient(app, base_url="https://kids.example.com") as c:
        app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        app.state.tg.http = app.state.http
        yield c


def login(c, user, parent=False):
    c.cookies.clear()
    r = c.get(f"/dev-login?u={user}&parent={'1' if parent else ''}", follow_redirects=False)
    assert r.status_code == 302


def csrf(c, path):
    html = c.get(path).text
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_full_flow(client, calls):
    c = client
    # регистрация агента
    assert c.post("/api/agent/enroll", json={"hostname": "x", "secret": "nope"}).status_code == 403
    r = c.post("/api/agent/enroll", json={"hostname": "KIDLAP.example.local", "secret": "enroll",
                                          "os": "Windows 11 Pro", "agent_version": "1.0.0"})
    tok = r.json()["token"]
    h = {"Authorization": f"Bearer {tok}"}

    # родитель добавляет ребёнка, лимит 30 минут сегодня
    login(c, "parent", parent=True)
    t = csrf(c, "/dashboard")
    r = c.post("/children", data={"username": "EXAMPLE\\Ivan", "display_name": "Ваня", "csrf": t},
               follow_redirects=False)
    assert r.headers["location"].startswith("/child/ivan")
    wd = datetime.now(timezone.utc).astimezone(Config().tz).weekday()
    form = {"csrf": t}
    for d in range(7):
        form[f"limit{d}"] = "30" if d == wd else "60"
        form[f"from{d}"] = ""
        form[f"to{d}"] = ""
    assert "Правила сохранены" in c.post("/child/ivan/rules", data=form).text

    # пульс: 20 мин игры + 40 мин на учебном сайте
    now = int(_time.time())
    body = {"seq": 1, "session": "active", "user": "EXAMPLE\\ivan",
            "current": {"exe": "chrome.exe", "domain": "uchi.ru"},
            "samples": [
                {"t": now - 3600, "user": "EXAMPLE\\ivan", "sec": 1200, "exe": "game.exe"},
                {"t": now - 1800, "user": "EXAMPLE\\ivan", "sec": 2400, "exe": "chrome.exe",
                 "domain": "www.uchi.ru"},
                {"t": now - 60, "user": "EXAMPLE\\parent", "sec": 60, "exe": "game.exe"},  # взрослый
            ]}
    r = c.post("/api/agent/heartbeat", json=body, headers=h).json()
    assert r["accepted"] == 2
    p = r["users"]["ivan"]
    assert p["mode"] == "normal" and p["counted_seconds"] == 1200
    assert p["remaining_seconds"] == 600
    assert "{left}" in p["messages"]["warn"] and "Ваня" in p["messages"]["warn"]
    assert r["users"]["parent"] == {"child": False, "mode": "none"}
    assert "kids.example.com" in r["device"]["restricted_domains"]
    assert "sso.example.com" in r["device"]["restricted_domains"]

    # повтор того же пакета не считается
    r = c.post("/api/agent/heartbeat", json=body, headers=h).json()
    assert r["accepted"] == 0 and r["users"]["ivan"]["counted_seconds"] == 1200

    # ещё 10 минут игры — лимит
    body = {"seq": 2, "session": "active", "user": "ivan",
            "samples": [{"t": now - 10, "user": "ivan", "sec": 600, "exe": "game.exe"}]}
    p = c.post("/api/agent/heartbeat", json=body, headers=h).json()["users"]["ivan"]
    assert p["mode"] == "restricted" and p["reason"] == "limit"
    assert "закончилось" in p["messages"]["limit"]

    # ребёнок видит статистику и просит время
    login(c, "ivan")
    page = c.get("/me").text
    assert "Привет, Ваня" in page and "uchi.ru" in page and "game.exe" in page
    assert c.get("/dashboard").status_code == 403
    t = csrf(c, "/me")
    r = c.post("/me/request", data={"minutes": "30", "reason": "доделать проект", "csrf": t})
    assert "Запрос отправлен" in r.text
    tg = [x for x in calls if x.url.host == "api.telegram.org"]
    assert tg and "sendMessage" in str(tg[-1].url)
    assert "доделать проект" in json.loads(tg[-1].content)["text"]
    r = c.post("/me/request", data={"minutes": "30", "csrf": t})
    assert "уже отправлен" in r.text

    # родитель даёт время в портале
    login(c, "parent", parent=True)
    t = csrf(c, "/requests")
    rid = re.search(r'action="/requests/(\d+)"', c.get("/requests").text).group(1)
    assert "дано" in c.post(f"/requests/{rid}", data={"action": "approve", "csrf": t}).text
    body = {"seq": 3, "session": "active", "user": "ivan", "samples": []}
    p = c.post("/api/agent/heartbeat", json=body, headers=h).json()["users"]["ivan"]
    assert p["mode"] == "normal" and p["remaining_seconds"] == 1800

    # «хватит на сегодня» и отмена
    c.post("/child/ivan/bonus", data={"minutes": "0", "csrf": t})
    body["seq"] = 4
    p = c.post("/api/agent/heartbeat", json=body, headers=h).json()["users"]["ivan"]
    assert p["mode"] == "restricted"
    dash = c.get("/dashboard").text
    assert "Вернуть время (30 мин)" in dash and "Хватит на сегодня" not in dash
    stop_id = re.search(r'action="/child/ivan/bonus/(\d+)/delete"', dash).group(1)
    r = c.post(f"/child/ivan/bonus/{stop_id}/delete", data={"csrf": t, "ret": "/dashboard"})
    assert "Отменено: -30 мин" in r.text and "Хватит на сегодня" in r.text
    body["seq"] = 41
    p = c.post("/api/agent/heartbeat", json=body, headers=h).json()["users"]["ivan"]
    assert p["mode"] == "normal" and p["remaining_seconds"] == 1800
    assert "не найдена" in c.post(f"/child/ivan/bonus/{stop_id}/delete", data={"csrf": t}).text
    c.post("/child/ivan/bonus", data={"minutes": "0", "csrf": t})
    body["seq"] = 42
    p = c.post("/api/agent/heartbeat", json=body, headers=h).json()["users"]["ivan"]
    assert p["mode"] == "restricted"

    # CSRF: токен обязателен; Origin null / другой порт пропускаются, чужой сайт — нет
    assert c.post("/child/ivan/bonus", data={"minutes": "10", "csrf": "bad"}).status_code == 403
    for origin, code in (("null", 200), ("https://kids.example.com:443", 200),
                         ("http://kids.example.com", 200), ("https://evil.example.org", 403)):
        r = c.post("/child/ivan/bonus", data={"minutes": "1", "csrf": t},
                   headers={"Origin": origin})
        assert r.status_code == code, origin
    c.post("/child/ivan/bonus", data={"minutes": "-3", "csrf": t})

    # настройки сообщений
    c.post("/settings", data={"section": "messages", "csrf": t, "warn": "Осталось {left}!",
                              "limit": "Стоп, {name}. Лимит {limit}.", "window": "", "lost": ""})
    body["seq"] = 5
    p = c.post("/api/agent/heartbeat", json=body, headers=h).json()["users"]["ivan"]
    assert p["messages"]["limit"] == "Стоп, Ваня. Лимит 30 мин."
    assert p["messages"]["warn"] == "Осталось {left}!"

    # локация: Яндекс (первый ключ отклонён) → Traccar, устройство создаётся
    r = c.post("/api/agent/location", headers={**h, "X-Real-IP": "95.31.1.2"}, json={
        "wifi": [{"bssid": "AA-BB-CC-DD-EE-FF", "rssi": -50}, {"bssid": "bad", "rssi": -60}],
        "battery": 77, "on_ac": False, "session": "active", "user": "ivan"}).json()
    assert r["ok"] and r["sent"] and r["lat"] == 55.89
    loc = [x for x in calls if x.url.host == "locator.api.maps.yandex.ru"][-1]
    sent = json.loads(loc.content)
    assert sent["wifi"] == [{"bssid": "aa:bb:cc:dd:ee:ff", "signal_strength": -50}]
    assert sent["ip"] == [{"address": "95.31.1.2"}]
    created = [x for x in calls if x.url.path == "/api/devices" and x.method == "POST"]
    assert json.loads(created[0].content)["uniqueId"] == "kidlap.example.local"
    osm = [x for x in calls if x.url.host == "traccar" and x.url.port == 5055][-1]
    assert osm.url.params["id"] == "kidlap.example.local"
    assert osm.url.params["batt"] == "77" and osm.url.params["ignition"] == "true"
    assert "ip" not in osm.url.params and "wifi" not in osm.url.params
    assert "status" not in osm.url.params
    assert osm.url.params["extip"] == "95.31.1.2" and osm.url.params["wifiCount"] == "2"

    # режим «потерян»
    page = c.get("/devices").text
    dev_id = re.search(r'action="/devices/([0-9a-f-]{36})"', page).group(1)
    c.post(f"/devices/{dev_id}", data={"mode": "track", "lost": "1", "lost_lock": "1",
                                       "lost_message": "Верните, пожалуйста", "csrf": t})
    r = c.post("/api/agent/heartbeat", json={"seq": 6, "user": "ivan"}, headers=h).json()
    assert r["device"]["lost"] == {"on": True, "lock": True, "message": "Верните, пожалуйста"}
    assert r["device"]["mode"] == "track" and r["users"] == {}
    assert r["device"]["location_interval"] == 120

    # все страницы родителя открываются
    for path in ("/dashboard", "/child/ivan", "/settings", "/devices", "/requests"):
        assert c.get(path).status_code == 200, path
    assert "Вернуть время" in c.get("/dashboard").text

    # решение из Telegram: чужой чат не может, свой может
    import asyncio
    app = c.app
    login(c, "ivan")
    t2 = csrf(c, "/me")
    c.post("/me/request", data={"minutes": "15", "csrf": t2})
    async def _rid():
        conn = await asyncpg.connect(DSN)
        v = await conn.fetchval("SELECT max(id) FROM ft_requests")
        await conn.close()
        return v
    rid2 = asyncio.run(_rid())
    tgobj = app.state.tg
    c.portal.call(tgobj._handle_callback, {"id": "1", "data": f"ft:ok:{rid2}",
                  "message": {"chat": {"id": 999}}, "from": {"username": "x"}})
    c.portal.call(tgobj._handle_callback, {"id": "2", "data": f"ft:ok:{rid2}",
                  "message": {"chat": {"id": 100}}, "from": {"username": "papa"}})
    async def _st():
        conn = await asyncpg.connect(DSN)
        v = await conn.fetchrow("SELECT status, decided_by FROM ft_requests WHERE id = $1", rid2)
        await conn.close()
        return v
    st = asyncio.run(_st())
    assert st["status"] == "approved" and st["decided_by"] == "telegram:papa"
    edits = [x for x in calls if str(x.url).endswith("editMessageText")]
    assert edits

    # неизвестный токен
    assert c.post("/api/agent/heartbeat", json={"seq": 1},
                  headers={"Authorization": "Bearer x"}).status_code == 401
    assert c.get("/health").json()["ok"]
