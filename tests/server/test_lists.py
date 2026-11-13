"""Списки: разбор форматов, подписки с обновлением, выдача агентам, названия программ."""
import asyncio
import os
import re
import time as _time

import asyncpg
import httpx
import pytest
from fastapi.testclient import TestClient

from app import lists
from app.config import Config
from app.main import create_app

DSN = os.environ["TEST_DATABASE_URL"]

HOSTS = """# hosts
127.0.0.1 localhost
0.0.0.0 ads.example.com tracker.example.net
0.0.0.0 0.0.0.0
::1 ip6-localhost
"""
ADBLOCK = """! AdGuard
[Adblock Plus 2.0]
||casino.example.org^
||Games.Example.com^$important
@@||allowed.example.com^
||example.com/path^
||*.wild.com^
||client.example^$client=192.168.1.5
/regex/
"""
PLAIN = """# plain
youtube.com
www.tiktok.com   # видео
not a domain
1.2.3.4
"""


def test_parse_formats():
    assert lists.parse(HOSTS, "domain") == ["ads.example.com", "tracker.example.net"]
    assert lists.parse(ADBLOCK, "domain") == ["casino.example.org", "games.example.com"]
    assert lists.parse(PLAIN, "domain") == ["youtube.com", "tiktok.com"]
    assert lists.parse("steam.exe\nC:\\Games\\Roblox.EXE\nnot-exe\n# x\n", "exe") == [
        "steam.exe", "roblox.exe"]


@pytest.fixture()
def env():
    async def reset():
        conn = await asyncpg.connect(DSN)
        await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        await conn.close()
    asyncio.run(reset())
    lists._cache.update(version=None, data=None)
    served = {"blocked": "||casino.example.org^\n0.0.0.0 games.example.com\n",
              "edu": "uchi.ru\ncasino.example.org\nnew-edu.example\n"}
    calls = []

    def handler(req: httpx.Request):
        calls.append(req)
        key = req.url.path.strip("/")
        if req.headers.get("if-none-match") == '"v1"' and key == "blocked":
            return httpx.Response(304)
        if key in served:
            return httpx.Response(200, text=served[key], headers={"ETag": '"v1"'})
        return httpx.Response(404)

    cfg = Config(database_url=DSN, public_url="https://kids.example.com", session_secret="s" * 32,
                 enroll_secret="enroll", dev_login=True, oidc_issuer="https://sso.example.com/r")
    app = create_app(cfg)
    with TestClient(app, base_url="https://kids.example.com") as c:
        app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        yield c, served, calls


def test_subscriptions_and_agent_lists(env):
    c, served, calls = env
    c.get("/dev-login?u=parent&parent=1")
    t = re.search(r'name="csrf" value="([^"]+)"', c.get("/settings").text).group(1)

    # ручной запрещённый сайт
    r = c.post("/settings", data={"section": "lists", "csrf": t, "blocked_domains": "vk.com",
                                  "edu_schemes": "telemost://https//telemost.yandex.ru\nhttps\nZoommtg:",
                                  "edu_domains": "uchi.ru", "edu_apps": "winword.exe",
                                  "blocked_apps": "steam.exe", "restricted_kill": ""})
    assert "Сохранено" in r.text

    # подписки
    r = c.post("/lists", data={"category": "blocked_domains", "csrf": t, "name": "Казино",
                               "url": "https://lists.example/blocked", "interval_hours": "12"})
    assert "Обновлено: 2 записей" in r.text
    r = c.post("/lists", data={"category": "edu_domains", "csrf": t,
                               "url": "https://lists.example/edu"})
    assert "Обновлено: 3 записей" in r.text
    r = c.post("/lists", data={"category": "blocked_domains", "csrf": t,
                               "url": "https://lists.example/missing"})
    assert "не загрузился" in r.text and "HTTP 404" in r.text
    assert c.post("/lists", data={"category": "edu_apps", "csrf": t,
                                  "url": "file:///etc/passwd"}).text.count("http://") >= 1
    page = c.get("/settings").text
    assert "Казино" in page and "HTTP 404" in page and "всего 3" in page   # vk + 2 из подписки

    # агент 1.1: версия в пульсе, полные списки отдельным запросом
    tok = c.post("/api/agent/enroll", json={"hostname": "pc.example.local",
                                            "secret": "enroll"}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    hb = c.post("/api/agent/heartbeat", json={"seq": 1, "caps": ["lists"]}, headers=h).json()
    ver = hb["device"]["lists_version"]
    assert ver and "blocked_domains" not in hb["device"]
    L = c.post("/api/agent/lists", headers=h).json()
    assert L["version"] == ver
    assert L["blocked_domains"] == ["vk.com", "casino.example.org", "games.example.com"]
    # казино из учебной подписки выкинуто: запрещённое не бывает учебным
    assert L["edu_domains"] == ["uchi.ru", "new-edu.example"]
    assert L["restricted_domains"][:4] == ["telemost:*", "zoommtg:*", "kids.example.com",
                                           "sso.example.com"]

    # агент 1.0: списки в каждом пульсе, как раньше
    old = c.post("/api/agent/heartbeat", json={"seq": 2}, headers=h).json()["device"]
    assert "lists_version" not in old and "new-edu.example" in old["edu_domains"]

    # 304 — без изменений; выключение подписки меняет версию
    sub_id = re.search(r'action="/lists/(\d+)"', page).group(1)
    r = c.post(f"/lists/{sub_id}", data={"action": "disable", "csrf": t})
    assert "Выключена" in r.text
    hb = c.post("/api/agent/heartbeat", json={"seq": 3, "caps": ["lists"]}, headers=h).json()
    assert hb["device"]["lists_version"] != ver
    assert c.post("/api/agent/lists", headers=h).json()["blocked_domains"] == ["vk.com"]
    r = c.post(f"/lists/{sub_id}", data={"action": "enable", "csrf": t})
    n = len(calls)
    c.portal.call(lists.update_due, c.app.state.pool, c.app.state.http)   # ничего не к сроку
    assert len(calls) == n

    async def make_due(conn_pool):
        async with conn_pool.acquire() as conn:
            await conn.execute("UPDATE ft_lists SET last_fetch = now() - interval '2 days'")
    c.portal.call(make_due, c.app.state.pool)
    c.portal.call(lists.update_due, c.app.state.pool, c.app.state.http)
    cond = [x for x in calls[n:] if x.url.path == "/blocked"]
    assert cond and cond[0].headers.get("if-none-match") == '"v1"'          # 304, не качаем заново
    r = c.post(f"/lists/{sub_id}", data={"action": "refresh", "csrf": t})
    assert "Обновлено: 2 записей" in r.text                                 # ↻ — без условий

    # учёт: время на сайте из учебной подписки — учёба; понятное название программы
    c.post("/children", data={"username": "ivan", "display_name": "Ваня", "csrf": t})
    now = int(_time.time())
    c.post("/api/agent/heartbeat", headers=h, json={
        "seq": 4, "caps": ["lists"], "user": "ivan", "session": "active",
        "current": {"exe": "snippingtool.exe", "app": "Ножницы"},
        "samples": [
            {"t": now - 300, "user": "ivan", "sec": 120, "exe": "chrome.exe",
             "domain": "a.new-edu.example", "app": "Google Chrome"},
            {"t": now - 100, "user": "ivan", "sec": 60, "exe": "SnippingTool.exe",
             "app": "Ножницы"}]})
    child = c.get("/child/ivan").text
    assert "Ножницы" in child and 'title="snippingtool.exe"' in child
    assert "a.new-edu.example" in child

    async def usage():
        conn = await asyncpg.connect(DSN)
        v = await conn.fetchrow("SELECT counted_seconds, free_seconds FROM ft_usage")
        await conn.close()
        return v
    u = asyncio.run(usage())
    assert u["free_seconds"] == 120 and u["counted_seconds"] == 60

    # удаление
    r = c.post(f"/lists/{sub_id}", data={"action": "delete", "csrf": t})
    assert "удалена" in r.text
