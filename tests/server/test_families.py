"""Многосемейный режим: родитель видит только свои семьи, компьютеры и запросы; перенос с 1.1."""
import asyncio
import json
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


def run_sql(sql, *args, fetch=False):
    async def go():
        conn = await asyncpg.connect(DSN)
        try:
            return await (conn.fetch(sql, *args) if fetch else conn.execute(sql, *args))
        finally:
            await conn.close()
    return asyncio.run(go())


def make_client(calls):
    def handler(req: httpx.Request):
        calls.append(req)
        if req.url.host == "api.telegram.org" and req.url.path.endswith("getUpdates"):
            return httpx.Response(200, json={"ok": True, "result": []})
        if req.url.host == "api.telegram.org":
            return httpx.Response(200, json={"ok": True, "result": {"message_id": len(calls)}})
        return httpx.Response(404)

    cfg = Config(database_url=DSN, public_url="https://kids.example.com", session_secret="s" * 32,
                 enroll_secret="enroll", dev_login=True, oidc_issuer="https://sso.example.com/r",
                 telegram_token="T")
    app = create_app(cfg)
    return app, handler


@pytest.fixture()
def env():
    run_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    lists._cache.clear()
    calls = []
    app, handler = make_client(calls)
    with TestClient(app, base_url="https://kids.example.com") as c:
        app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        app.state.tg.http = app.state.http
        yield c, calls


def login(c, user, parent=False, admin=False):
    c.cookies.clear()
    c.get(f"/dev-login?u={user}&parent={'1' if parent else ''}&admin={'1' if admin else ''}",
          follow_redirects=False)
    page = c.get("/dashboard" if (parent or admin) else "/me").text
    m = re.search(r'name="csrf" value="([^"]+)"', page)
    return m.group(1) if m else ""


def test_families_are_isolated(env):
    c, calls = env

    # админ создаёт две семьи с родителями
    t = login(c, "root", admin=True)
    c.post("/families", data={"name": "Ивановы", "parent": "ivanov", "csrf": t})
    c.post("/families", data={"name": "Петровы", "parent": "EXAMPLE\\Petrov", "csrf": t})
    fam = {r["name"]: r["id"] for r in run_sql("SELECT id, name FROM ft_families", fetch=True)}
    c.post(f"/family/{fam['Ивановы']}", data={"section": "telegram", "telegram_chats": "111", "csrf": t})
    c.post(f"/family/{fam['Петровы']}", data={"section": "telegram", "telegram_chats": "222", "csrf": t})

    # каждый родитель добавляет своего ребёнка — он попадает в его семью
    ti = login(c, "ivanov", parent=True)
    c.post("/children", data={"username": "vanya", "display_name": "Ваня", "csrf": ti})
    c.post("/child/vanya/lists", data={"csrf": ti, "blocked_domains": "vk.com", "idle_minutes": "3"})
    tp = login(c, "petrov", parent=True)
    c.post("/children", data={"username": "petya", "display_name": "Петя", "csrf": tp})

    # Петров не видит Ваню нигде и не может им управлять
    dash = c.get("/dashboard").text
    assert "/child/petya" in dash and "/child/vanya" not in dash
    assert c.get("/child/vanya").status_code == 404
    for path, data in (("/child/vanya/bonus", {"minutes": "60"}),
                       ("/child/vanya/lists", {"blocked_domains": ""}),
                       ("/child/vanya/rules", {}),
                       ("/child/vanya/settings", {"display_name": "X"}),
                       ("/child/vanya/subs", {"category": "edu_domains", "url": "https://x.example/l"}),
                       ("/child/vanya/delete", {})):
        assert c.post(path, data={**data, "csrf": tp}).status_code == 404, path
    assert c.post("/child/petya/copy", data={"target": "vanya", "csrf": tp}).status_code == 404
    assert "уже добавлен" in c.post("/children", data={"username": "vanya", "csrf": tp}).text
    assert c.post(f"/family/{fam['Ивановы']}", data={"section": "add_parent", "parent": "petrov",
                                                      "csrf": tp}).status_code == 404
    assert c.post("/families", data={"name": "Свои", "csrf": tp}).status_code == 403
    fam_page = c.get("/family").text
    assert "Петровы" in fam_page and "Ивановы" not in fam_page
    assert json.loads(run_sql(
        "SELECT settings->'blocked_domains' AS b FROM ft_children WHERE username='vanya'",
        fetch=True)[0]["b"]) == ["vk.com"]                      # ничего не изменилось

    # компьютеры: привязка к семье первого вошедшего ребёнка
    tok1 = c.post("/api/agent/enroll", json={"hostname": "vanya-pc", "secret": "enroll"}).json()["token"]
    tok2 = c.post("/api/agent/enroll", json={"hostname": "spare-pc", "secret": "enroll"}).json()["token"]
    h1, h2 = ({"Authorization": f"Bearer {x}"} for x in (tok1, tok2))
    now = int(_time.time())
    c.post("/api/agent/heartbeat", headers=h1, json={
        "seq": 1, "caps": ["userlists"], "user": "vanya", "session": "active",
        "samples": [{"t": now - 60, "user": "vanya", "sec": 60, "exe": "game.exe"}]})
    c.post("/api/agent/heartbeat", headers=h2, json={"seq": 1, "user": "someadult"})
    assert "vanya-pc" not in c.get("/devices").text and "spare-pc" not in c.get("/devices").text
    dev1 = run_sql("SELECT id FROM ft_devices WHERE hostname = 'vanya-pc'", fetch=True)[0]["id"]
    dev2 = run_sql("SELECT id FROM ft_devices WHERE hostname = 'spare-pc'", fetch=True)[0]["id"]
    assert c.post(f"/devices/{dev1}", data={"lost": "1", "csrf": tp}).status_code == 404
    assert c.post(f"/devices/{dev1}/delete", data={"csrf": tp}).status_code == 404
    ti = login(c, "ivanov", parent=True)
    d = c.get("/devices").text
    assert "vanya-pc" in d and "spare-pc" not in d
    # родитель не может сменить семью компьютера, админ — может
    c.post(f"/devices/{dev1}", data={"mode": "control", "family_id": str(fam["Петровы"]), "csrf": ti})
    assert run_sql("SELECT family_id FROM ft_devices WHERE id = $1", dev1, fetch=True)[0][
        "family_id"] == fam["Ивановы"]
    t = login(c, "root", admin=True)
    assert "spare-pc" in c.get("/devices").text and "vanya-pc" in c.get("/devices").text
    c.post(f"/devices/{dev2}", data={"mode": "control", "family_id": str(fam["Петровы"]), "csrf": t})
    tp = login(c, "petrov", parent=True)
    assert "spare-pc" in c.get("/devices").text

    # запрос времени: уходит только в чат семьи, решает только она
    tv = login(c, "vanya")
    assert "Запрос отправлен" in c.post("/me/request", data={"minutes": "30", "csrf": tv}).text
    sent = [json.loads(x.content) for x in calls if str(x.url).endswith("sendMessage")]
    assert [m["chat_id"] for m in sent] == ["111"]
    rid = run_sql("SELECT id FROM ft_requests", fetch=True)[0]["id"]
    tp = login(c, "petrov", parent=True)
    assert "Ваня" not in c.get("/requests").text
    assert c.post(f"/requests/{rid}", data={"action": "approve", "csrf": tp}).status_code == 404
    tg = c.app.state.tg
    c.portal.call(tg._handle_callback, {"id": "1", "data": f"ft:ok:{rid}",
                  "message": {"chat": {"id": 222}}, "from": {"username": "petrov"}})
    assert run_sql("SELECT status FROM ft_requests", fetch=True)[0]["status"] == "pending"
    c.portal.call(tg._handle_callback, {"id": "2", "data": f"ft:ok:{rid}",
                  "message": {"chat": {"id": 111}}, "from": {"username": "ivanov"}})
    assert run_sql("SELECT status FROM ft_requests", fetch=True)[0]["status"] == "approved"

    # второй родитель семьи видит то же; себя убрать нельзя
    ti = login(c, "ivanov", parent=True)
    c.post(f"/family/{fam['Ивановы']}", data={"section": "add_parent", "parent": "Mama", "csrf": ti})
    assert "Себя убрать нельзя" in c.post(
        f"/family/{fam['Ивановы']}", data={"section": "remove_parent", "parent": "ivanov", "csrf": ti}).text
    login(c, "mama", parent=True)
    assert "/child/vanya" in c.get("/dashboard").text and c.get("/child/vanya").status_code == 200
    # родитель без семьи ничего не видит
    login(c, "newbie", parent=True)
    assert "/child/" not in c.get("/dashboard").text

    # логины Windows вне домена: время идёт в лимит ребёнка, чужой логин занять нельзя
    ti = login(c, "ivanov", parent=True)
    assert "уже занят" in c.post("/child/vanya/settings", data={
        "display_name": "Ваня", "enabled": "1", "aliases": "petya", "csrf": ti}).text
    c.post("/child/vanya/settings", data={"display_name": "Ваня", "enabled": "1",
                                          "aliases": "Ваня-Дом", "csrf": ti})
    r = c.post("/api/agent/heartbeat", headers=h2, json={
        "seq": 2, "caps": ["userlists"], "user": "HOME-PC\\Ваня-Дом", "session": "active",
        "samples": [{"t": now - 30, "user": "HOME-PC\\Ваня-Дом", "sec": 40, "exe": "game.exe"}]}).json()
    assert r["accepted"] == 1
    pol = r["users"]["ваня-дом"]                       # политика — под логином, который знает агент
    assert pol["child"] and pol["counted_seconds"] == 100 and pol["idle_minutes"] == 3
    L = c.post("/api/agent/lists", headers=h2, json={"user": "HOME-PC\\Ваня-Дом"}).json()
    assert L["blocked_domains"] == ["vk.com"]

    # админ видит всех и переносит ребёнка в другую семью
    t = login(c, "root", admin=True)
    dash = c.get("/dashboard").text
    assert "/child/vanya" in dash and "/child/petya" in dash
    c.post("/child/vanya/settings", data={"display_name": "Ваня", "enabled": "1",
                                          "family_id": str(fam["Петровы"]), "csrf": t})
    tp = login(c, "petrov", parent=True)
    assert "/child/vanya" in c.get("/dashboard").text


def test_migration_from_single_family():
    """Данные версии 1.1 (общие настройки и подписки) переезжают в настройки детей и семью."""
    run_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    lists._cache.clear()
    app, handler = make_client([])
    with TestClient(app, base_url="https://kids.example.com"):
        pass                                           # создали схему
    # состояние «как в 1.1»
    for sql in (
        "DELETE FROM ft_kv WHERE key = 'schema_version'",
        "INSERT INTO ft_children (username, display_name) VALUES ('ivan', 'Ваня'), ('masha', 'Маша')",
        """INSERT INTO ft_settings (key, value) VALUES
           ('blocked_domains', '["vk.com"]'), ('idle_minutes', '9'),
           ('messages', '{"limit": "Стоп, {name}", "warn": "w", "window": "x", "lost": "l"}')""",
        """INSERT INTO ft_lists (category, name, url, entries, count)
           VALUES ('blocked_domains', 'Старый', 'https://l.example/a', '["bad.example"]', 1)""",
        "INSERT INTO ft_devices (hostname, token_hash) VALUES ('old-pc', 'x')",
    ):
        run_sql(sql)
    app, handler = make_client([])
    with TestClient(app, base_url="https://kids.example.com") as c:
        fams = run_sql("SELECT * FROM ft_families", fetch=True)
        assert len(fams) == 1 and fams[0]["name"] == "Семья"
        assert json.loads(fams[0]["messages"])["limit"] == "Стоп, {name}"
        kids = run_sql("SELECT username, family_id, settings FROM ft_children ORDER BY 1", fetch=True)
        for k in kids:
            st = json.loads(k["settings"])
            assert k["family_id"] == fams[0]["id"]
            assert st["blocked_domains"] == ["vk.com"] and st["idle_minutes"] == 9
            assert "uchi.ru" in st["edu_domains"]              # значения по умолчанию сохранены
        subs = run_sql("SELECT username, name, count FROM ft_lists ORDER BY 1", fetch=True)
        assert [(s["username"], s["name"]) for s in subs] == [("ivan", "Старый"), ("masha", "Старый")]
        assert run_sql("SELECT family_id FROM ft_devices", fetch=True)[0]["family_id"] == fams[0]["id"]
        # итог для агента: ручное + подписка
        tok = c.post("/api/agent/enroll", json={"hostname": "old-pc", "secret": "enroll"}).json()["token"]
        L = c.post("/api/agent/lists", headers={"Authorization": f"Bearer {tok}"},
                   json={"user": "masha"}).json()
        assert L["blocked_domains"] == ["vk.com", "bad.example"]
    # повторный запуск ничего не дублирует
    app, handler = make_client([])
    with TestClient(app, base_url="https://kids.example.com"):
        assert len(run_sql("SELECT 1 FROM ft_lists", fetch=True)) == 2
        assert len(run_sql("SELECT 1 FROM ft_families", fetch=True)) == 1
