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
    lists._cache.clear()
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
    t = re.search(r'name="csrf" value="([^"]+)"', c.get("/dashboard").text).group(1)
    c.post("/children", data={"username": "ivan", "display_name": "Ваня", "csrf": t})
    c.post("/children", data={"username": "masha", "display_name": "Маша", "csrf": t})
    K = "/child/ivan"

    # ручные списки ребёнка
    r = c.post(K + "/lists", data={"csrf": t, "blocked_domains": "vk.com",
                                   "edu_schemes": "telemost://https//telemost.yandex.ru\nhttps\nZoommtg:",
                                   "edu_domains": "uchi.ru", "edu_apps": "winword.exe",
                                   "blocked_apps": "steam.exe", "restricted_kill": "",
                                   "idle_minutes": "7", "warn_minutes": "3 1"})
    assert "Сохранено" in r.text

    # подписки ребёнка
    r = c.post(K + "/subs", data={"category": "blocked_domains", "csrf": t, "name": "Казино",
                                  "url": "https://lists.example/blocked", "interval_hours": "12"})
    assert "Обновлено: 2 записей" in r.text
    r = c.post(K + "/subs", data={"category": "edu_domains", "csrf": t,
                                  "url": "https://lists.example/edu"})
    assert "Обновлено: 3 записей" in r.text
    r = c.post(K + "/subs", data={"category": "blocked_domains", "csrf": t,
                                  "url": "https://lists.example/missing"})
    assert "не загрузился" in r.text and "HTTP 404" in r.text
    assert "http://" in c.post(K + "/subs", data={"category": "edu_apps", "csrf": t,
                                                  "url": "file:///etc/passwd"}).text
    page = c.get(K).text
    assert "Казино" in page and "HTTP 404" in page and "всего 3" in page   # vk + 2 из подписки
    assert "Казино" not in c.get("/child/masha").text                       # у Маши своих нет

    # агент 1.2: версия списков — в политике ребёнка, списки — по логину
    tok = c.post("/api/agent/enroll", json={"hostname": "pc.example.local",
                                            "secret": "enroll"}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    hb = c.post("/api/agent/heartbeat", headers=h, json={
        "seq": 1, "caps": ["lists", "userlists"], "user": "EXAMPLE\\Ivan", "session": "active"}).json()
    pol = hb["users"]["ivan"]
    ver = pol["lists_version"]
    assert ver and pol["idle_minutes"] == 7 and pol["warn_minutes"] == [3, 1]
    assert "lists_version" not in hb["device"] and "blocked_domains" not in hb["device"]
    L = c.post("/api/agent/lists", headers=h, json={"user": "ivan"}).json()
    assert L["version"] == ver
    assert L["blocked_domains"] == ["vk.com", "casino.example.org", "games.example.com"]
    # казино из учебной подписки выкинуто: запрещённое не бывает учебным
    assert L["edu_domains"] == ["uchi.ru", "new-edu.example"]
    assert L["restricted_domains"][:4] == ["telemost:*", "zoommtg:*", "kids.example.com",
                                           "sso.example.com"]
    # у Маши — свои списки (по умолчанию), без vk.com
    M = c.post("/api/agent/lists", headers=h, json={"user": "masha"}).json()
    assert "vk.com" not in M["blocked_domains"] and M["version"] != ver
    assert c.post("/api/agent/lists", headers=h, json={"user": "stranger"}).status_code == 404

    # агент 1.1: один набор на компьютер — объединение по детям семьи компьютера
    hb11 = c.post("/api/agent/heartbeat", json={"seq": 2, "caps": ["lists"]}, headers=h).json()
    assert hb11["device"]["lists_version"]
    U = c.post("/api/agent/lists", headers=h).json()
    assert "vk.com" in U["blocked_domains"] and "uchi.ru" in U["edu_domains"]
    # агент 1.0: списки в каждом пульсе
    old = c.post("/api/agent/heartbeat", json={"seq": 3}, headers=h).json()["device"]
    assert "lists_version" not in old and "new-edu.example" in old["edu_domains"]

    # выключение подписки меняет версию; 304 — без повторной загрузки; ↻ — без условий
    sub_id = re.search(r'action="/child/ivan/subs/(\d+)"', page).group(1)
    assert "Выключена" in c.post(f"{K}/subs/{sub_id}", data={"action": "disable", "csrf": t}).text
    pol = c.post("/api/agent/heartbeat", headers=h, json={
        "seq": 4, "caps": ["userlists"], "user": "ivan"}).json()["users"]["ivan"]
    assert pol["lists_version"] != ver
    assert c.post("/api/agent/lists", headers=h, json={"user": "ivan"}).json()[
        "blocked_domains"] == ["vk.com"]
    c.post(f"{K}/subs/{sub_id}", data={"action": "enable", "csrf": t})
    n = len(calls)
    c.portal.call(lists.update_due, c.app.state.pool, c.app.state.http)   # ничего не к сроку
    assert len(calls) == n

    async def make_due(conn_pool):
        async with conn_pool.acquire() as conn:
            await conn.execute("UPDATE ft_lists SET last_fetch = now() - interval '2 days'")
    c.portal.call(make_due, c.app.state.pool)
    c.portal.call(lists.update_due, c.app.state.pool, c.app.state.http)
    cond = [x for x in calls[n:] if x.url.path == "/blocked"]
    assert cond and cond[0].headers.get("if-none-match") == '"v1"'
    assert "Обновлено: 2 записей" in c.post(f"{K}/subs/{sub_id}",
                                            data={"action": "refresh", "csrf": t}).text
    # чужую подписку через свой адрес не тронуть
    assert "не найдена" in c.post(f"/child/masha/subs/{sub_id}",
                                  data={"action": "delete", "csrf": t}).text

    # учёт: сайт из учебной подписки Ивана — учёба; понятное название программы
    now = int(_time.time())
    c.post("/api/agent/heartbeat", headers=h, json={
        "seq": 5, "caps": ["userlists"], "user": "ivan", "session": "active",
        "current": {"exe": "snippingtool.exe", "app": "Ножницы"},
        "samples": [
            {"t": now - 300, "user": "ivan", "sec": 120, "exe": "chrome.exe",
             "domain": "a.new-edu.example", "app": "Google Chrome"},
            {"t": now - 200, "user": "masha", "sec": 30, "exe": "chrome.exe",
             "domain": "a.new-edu.example"},                 # у Маши этот сайт не учебный
            {"t": now - 100, "user": "ivan", "sec": 60, "exe": "SnippingTool.exe",
             "app": "Ножницы"}]})
    child = c.get(K).text
    assert "Ножницы" in child and 'title="snippingtool.exe"' in child
    assert "a.new-edu.example" in child

    async def usage():
        conn = await asyncpg.connect(DSN)
        v = {r["username"]: (r["counted_seconds"], r["free_seconds"])
             for r in await conn.fetch("SELECT * FROM ft_usage")}
        await conn.close()
        return v
    u = asyncio.run(usage())
    assert u["ivan"] == (60, 120) and u["masha"] == (30, 0)

    # копирование настроек Ивана Маше: списки, простой и подписки
    r = c.post(K + "/copy", data={"csrf": t, "target": "masha"})
    assert "скопированы: Маша" in r.text
    mp = c.get("/child/masha").text
    assert "Казино" in mp and "vk.com" in mp and 'name="idle_minutes" value="7"' in mp
    M2 = c.post("/api/agent/lists", headers=h, json={"user": "masha"}).json()
    assert M2["blocked_domains"] == L["blocked_domains"]
    assert "Отметьте" in c.post(K + "/copy", data={"csrf": t}).text

    assert "удалена" in c.post(f"{K}/subs/{sub_id}", data={"action": "delete", "csrf": t}).text
