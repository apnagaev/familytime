"""Место компьютера: известные адреса, повторное использование Wi-Fi, GeoIP без Wi-Fi."""
import asyncio
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
WIFI_A = [{"bssid": "aa:bb:cc:00:00:01", "rssi": -40}, {"bssid": "aa:bb:cc:00:00:02", "rssi": -60}]
WIFI_B = [{"bssid": "aa:bb:cc:00:00:09", "rssi": -45}]


def test_parse_known_addresses():
    items, errors = locator.parse_ip_locations(
        "203.0.113.5 55.75 37.61 30 Дом\n"
        "10.0.0.0/8, 55.75, 37.61   # локальная сеть\n"
        "\n"
        "not-an-ip 1 2\n"
        "198.51.100.0/24 95 10\n")
    assert [i["net"] for i in items] == ["203.0.113.5/32", "10.0.0.0/8"]
    assert items[0]["accuracy"] == 30 and items[0]["name"] == "Дом" and items[1]["accuracy"] == 50
    assert len(errors) == 2 and "строка 4" in errors[0]
    # самая узкая подсеть выигрывает
    items, _ = locator.parse_ip_locations("10.0.0.0/8 1 1 50 Сеть\n10.1.2.0/24 2 2 20 Комната")
    assert locator.match_known(items, "10.1.2.7").place == "Комната"
    assert locator.match_known(items, "10.9.9.9").place == "Сеть"
    assert locator.match_known(items, "192.168.1.1") is None
    assert locator.parse_ip_locations(locator.format_ip_locations(items))[0] == items


@pytest.fixture()
def env():
    async def reset():
        conn = await asyncpg.connect(DSN)
        await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        await conn.close()
    asyncio.run(reset())
    lists._cache.clear()
    calls = []
    state = {"yandex_ip": True}

    def handler(req: httpx.Request):
        calls.append(req)
        if req.url.host == "locator.api.maps.yandex.ru":
            import json
            body = json.loads(req.content)
            if "wifi" in body:
                return httpx.Response(200, json={"location": {"point": {"lat": 55.9, "lon": 37.4},
                                                              "accuracy": 25}})
            if state["yandex_ip"]:
                return httpx.Response(200, json={"location": {"point": {"lat": 59.9, "lon": 30.3},
                                                              "accuracy": 0}})
            return httpx.Response(200, json={})
        if req.url.host == "geoip.example":
            return httpx.Response(200, json={"status": "success", "lat": 56.8, "lon": 60.6,
                                             "city": "Екатеринбург"})
        if req.url.host == "traccar":
            return httpx.Response(200)
        return httpx.Response(404)

    cfg = Config(database_url=DSN, public_url="https://kids.example.com", session_secret="s" * 32,
                 enroll_secret="enroll", dev_login=True, oidc_issuer="https://sso.example.com/r",
                 yandex_locator_keys=["k"], traccar_osmand_url="http://traccar:5055",
                 geoip_url="http://geoip.example/json/{ip}", operator_url="")
    app = create_app(cfg)
    with TestClient(app, base_url="https://kids.example.com") as c:
        app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        yield c, calls, state


def hosts(calls, start=0):
    return [x.url.host for x in calls[start:] if x.url.host != "traccar"]


def test_location_sources(env):
    c, calls, state = env
    c.get("/dev-login?u=root&admin=1")
    t = re.search(r'name="csrf" value="([^"]+)"', c.get("/settings").text).group(1)
    r = c.post("/settings", data={"csrf": t, "interval_minutes": "15", "lost_interval_minutes": "2",
                                  "ip_locations": "203.0.113.5 55.75 37.61 30 Дом\n"
                                                  "10.0.0.0/8 55.75 37.61 40 Дом, локальная сеть"})
    assert "Сохранено" in r.text and "203.0.113.5/32 55.75 37.61 30 Дом" in r.text
    assert "не разобрано" in c.post("/settings", data={"csrf": t, "ip_locations": "мусор 1 2"}).text

    tok = c.post("/api/agent/enroll", json={"hostname": "desk.example.local",
                                            "secret": "enroll"}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}

    def loc(ip, wifi):
        return c.post("/api/agent/location", headers={**h, "X-Real-IP": ip},
                      json={"wifi": wifi, "session": "active"}).json()

    # 1. известный адрес (внешний и внутренний): без запросов наружу, даже если Wi-Fi есть
    n = len(calls)
    r = loc("203.0.113.5", WIFI_A)
    assert r["source"] == "known-ip" and r["lat"] == 55.75 and r["accuracy"] == 30 and r["sent"]
    r = loc("10.20.30.40", [])
    assert r["source"] == "known-ip" and r["accuracy"] == 40
    assert hosts(calls, n) == []
    osm = [x for x in calls if x.url.host == "traccar"][-1]
    assert osm.url.params["source"] == "known-ip"
    assert osm.url.params["place"] == "Дом, локальная сеть"
    assert "известный адрес: Дом, локальная сеть" in c.get("/devices").text

    # 2. Wi-Fi: первый раз — Яндекс, потом те же точки и IP — без запроса; в Traccar уходит каждый раз
    n = len(calls)
    r = loc("198.51.100.7", WIFI_A)
    assert r["source"] == "yandex-wifi" and r["lat"] == 55.9
    r = loc("198.51.100.7", list(reversed(WIFI_A)))
    assert r["source"] == "yandex-wifi" and r["lat"] == 55.9 and r["sent"]
    assert hosts(calls, n) == ["locator.api.maps.yandex.ru"]
    assert len([x for x in calls[n:] if x.url.host == "traccar"]) == 2
    # другие точки или другой IP — новый запрос
    r = loc("198.51.100.7", WIFI_B)
    r = loc("198.51.100.8", WIFI_B)
    assert hosts(calls, n).count("locator.api.maps.yandex.ru") == 3

    # 3. без Wi-Fi: по внешнему IP через Яндекс, второй раз — из кеша
    n = len(calls)
    r = loc("95.31.1.10", [])
    assert r["source"] == "yandex-ip" and r["lat"] == 59.9 and r["accuracy"] == locator.GEOIP_ACCURACY
    r = loc("95.31.1.10", [])
    assert r["source"] == "yandex-ip" and r["sent"]
    assert hosts(calls, n) == ["locator.api.maps.yandex.ru"]

    # 4. Яндекс по IP ничего не знает — служба GeoIP, город; тоже кешируется
    state["yandex_ip"] = False
    n = len(calls)
    r = loc("95.31.1.77", [])
    assert r["source"] == "geoip" and r["lat"] == 56.8
    r = loc("95.31.1.77", [])
    assert r["source"] == "geoip"
    assert hosts(calls, n) == ["locator.api.maps.yandex.ru", "geoip.example"]
    assert "по IP, город: Екатеринбург" in c.get("/devices").text
    osm = [x for x in calls if x.url.host == "traccar"][-1]
    assert osm.url.params["accuracy"] == "1" and osm.url.params["place"] == "Екатеринбург"

    # 5. внутренний адрес без Wi-Fi и не из таблицы — места нет, наружу не ходим
    n = len(calls)
    r = loc("192.168.50.3", [])
    assert r["ok"] is False and hosts(calls, n) == []


def test_locator_quota_and_refresh():
    """Учёт запросов к Локатору по ключам, обход исчерпанных и отклонённых, обновление
    самых старых мест по IP перед концом суток с резервом."""
    import json
    from datetime import datetime, timedelta, timezone
    from app import quota

    async def reset():
        conn = await asyncpg.connect(DSN)
        await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        await conn.close()
    asyncio.run(reset())
    calls = []

    def handler(req: httpx.Request):
        if req.url.host == "locator.api.maps.yandex.ru":
            calls.append(req)
            if req.url.params["apikey"] == "dead-key-000":
                return httpx.Response(403)
            ip = json.loads(req.content)["ip"][0]["address"]
            return httpx.Response(200, json={"location": {"point": {"lat": 50.0, "lon": float(ip.split(".")[-1])},
                                                          "accuracy": 0}})
        return httpx.Response(200)

    cfg = Config(database_url=DSN, public_url="https://kids.example.com", session_secret="s" * 32,
                 enroll_secret="enroll", dev_login=True, oidc_issuer="https://sso.example.com/r",
                 yandex_locator_keys=["key-one-0001", "dead-key-000", "key-two-0002"],
                 locator_daily_limit=5, locator_reserve=2, geoip_url="", operator_url="")
    app = create_app(cfg)
    with TestClient(app, base_url="https://kids.example.com") as c:
        app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        now = datetime.now(timezone.utc)
        day = quota.quota_day(cfg, now)

        async def prep():
            async with app.state.pool.acquire() as conn:
                for i in range(10):
                    await conn.execute(
                        "INSERT INTO ft_geoip VALUES ($1, 1, 1, 50000, 'geoip', '', $2)",
                        f"95.31.7.{i + 1}", now - timedelta(days=20 - i))
                await conn.execute("INSERT INTO ft_locator_usage (key_id, day, requests) VALUES ($1, $2, 1)",
                                   quota.key_id("key-one-0001"), day)
        c.portal.call(prep)

        # обычный запрос: наименее израсходованный ключ (не key-one), отклонённый пропускается
        async def one():
            async with app.state.pool.acquire() as conn:
                return await locator.locate(app.state.http, cfg, [], "95.31.8.1", conn)
        fix = c.portal.call(one)
        assert fix and fix.source == "yandex-ip"
        used = [r.url.params["apikey"] for r in calls]
        assert used[0] != "key-one-0001" and used[-1] == "key-two-0002"
        calls.clear()

        # не время — ничего; за 5 минут до конца суток — обновление
        assert c.portal.call(quota.refresh_due, app.state.pool, app.state.http, cfg,
                             quota.day_end(cfg, day) - timedelta(minutes=30)) is None
        n = c.portal.call(quota.refresh_due, app.state.pool, app.state.http, cfg,
                          quota.day_end(cfg, day) - timedelta(minutes=5))

        async def check():
            async with app.state.pool.acquire() as conn:
                use = {r["key_id"]: r for r in await conn.fetch(
                    "SELECT * FROM ft_locator_usage WHERE day = $1", day)}
                geo = await conn.fetch("SELECT ip, source FROM ft_geoip ORDER BY fetched_at")
                return use, geo
        use, geo = c.portal.call(check)
        k1, k2 = use[quota.key_id("key-one-0001")], use[quota.key_id("key-two-0002")]
        # остаток до резерва: key-one 5-2-1 = 2, key-two 5-2-1(обычный запрос) = 2
        assert k1["requests"] == 3 and k1["refresh"] == 2
        assert k2["requests"] == 3 and k2["refresh"] == 2
        assert use[quota.key_id("dead-key-000")]["rejected"] >= 1
        assert n == 4 and sum(r["source"] == "yandex-ip" for r in geo) == 4
        # повторно в те же сутки — нет
        assert c.portal.call(quota.refresh_due, app.state.pool, app.state.http, cfg,
                             quota.day_end(cfg, day) - timedelta(minutes=2)) is None
        # исчерпанные и отклонённые ключи не выбираются
        async def keys():
            async with app.state.pool.acquire() as conn:
                await conn.execute("UPDATE ft_locator_usage SET requests = 5 WHERE key_id = $1",
                                   quota.key_id("key-one-0001"))
                return await quota.pick_keys(conn, cfg)
        assert c.portal.call(keys) == ["key-two-0002"]
        # статистика на странице настроек
        c.get("/dev-login?u=root&admin=1")
        page = c.get("/settings").text
        assert "Яндекс Локатор" in page and "key-…0001" in page and "отклонён" in page
