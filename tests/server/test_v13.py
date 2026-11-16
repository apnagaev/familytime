"""1.3: время блокировки, extip/localIP, разброс точек, Traccar Client, семья/компания."""
import asyncio
import json
import math
import os
import random
import re
from datetime import datetime, timedelta, timezone

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
                              "phone_ids": "my-phone", "jitter": "",
                              "ip_locations": "10.20.30.0/24 55.75 37.61 40 Дом\n"
                                              "95.31.1.0/24 55.70 37.50 100 Дача"})

    def last():
        return [x for x in calls if x.url.host == "traccar"][-1]
    # телефон из списка во внутренней сети дома — место из таблицы, точность таблицы
    r = c.get("/osmand?id=my-phone&lat=55.7520&lon=37.6175&accuracy=8&timestamp=1&batt=50",
              headers={"X-Real-IP": "10.20.30.50"})
    assert r.status_code == 200 and r.text == "ok"
    f = last()
    assert f.method == "GET" and f.headers["x-real-ip"] == "10.20.30.50"
    q = f.url.params
    assert (q["id"], q["lat"], q["lon"], q["accuracy"], q["source"], q["place"], q["batt"],
            q["timestamp"]) == ("my-phone", "55.750000", "37.610000", "40", "known-ip", "Дом", "50", "1")
    assert q["ip"] == "10.20.30.50"
    # JSON (новый Traccar Client) с внешнего известного адреса
    body = {"device_id": "my-phone", "location": {"timestamp": "2026-11-15T10:00:00Z",
            "coords": {"latitude": 55.9, "longitude": 37.9, "accuracy": 12}}}
    c.post("/osmand", json=body, headers={"X-Real-IP": "95.31.1.20"})
    j = json.loads(last().content)
    assert j["location"]["coords"] == {"latitude": 55.7, "longitude": 37.5, "accuracy": 100}
    assert j["location"]["extras"] == {"source": "known-ip", "place": "Дача", "ip": "95.31.1.20"}
    # форма
    c.post("/osmand", data={"id": "my-phone", "lat": "1", "lon": "2", "accuracy": "5"},
           headers={"X-Real-IP": "10.20.30.7"})
    assert "lat=55.750000" in last().content.decode() and "ip=10.20.30.7" in last().content.decode()
    assert "ip" not in last().url.params
    # присланный телефоном ip заменяется настоящим, у чужих телефонов тоже
    c.get("/osmand?id=other&lat=1&lon=2&ip=1.1.1.1", headers={"X-Real-IP": "95.31.1.21"})
    assert last().url.params.get_list("ip") == ["95.31.1.21"]
    # неизвестный адрес или чужой телефон — как есть
    c.get("/osmand?id=my-phone&lat=55.9&lon=37.9&accuracy=7", headers={"X-Real-IP": "8.8.8.8"})
    assert last().url.params["lat"] == "55.9" and "source" not in last().url.params
    c.get("/osmand?id=stranger&lat=55.9&lon=37.9&accuracy=7", headers={"X-Real-IP": "10.20.30.50"})
    assert last().url.params["lat"] == "55.9"
    # разброс в пределах точности
    c.post("/settings", data={"csrf": t, "interval_minutes": "15", "lost_interval_minutes": "2",
                              "phone_ids": "my-phone", "jitter": "1",
                              "ip_locations": "10.20.30.0/24 55.75 37.61 40 Дом"})
    c.get("/osmand?id=my-phone&lat=55.9&lon=37.9", headers={"X-Real-IP": "10.20.30.50"})
    q = last().url.params
    d = math.hypot((float(q["lat"]) - 55.75) * 111320,
                   (float(q["lon"]) - 37.61) * 111320 * math.cos(math.radians(55.75)))
    assert d <= 41
    # журнал в настройках; компьютеры по телефонам не уточняются
    page = c.get("/settings").text
    assert "my-phone" in page and "stranger" not in page and "Дом" in page
    h = enroll(c)
    r = c.post("/api/agent/location", headers={**h, "X-Real-IP": "10.20.30.88"}, json={
        "wifi": [], "session": "active"}).json()
    assert r["source"] == "known-ip"
    run_sql("TRUNCATE ft_phone_fixes")
    r = c.post("/api/agent/location", headers={**h, "X-Real-IP": "172.16.5.5"}, json={
        "wifi": [], "session": "active"}).json()
    assert r["ok"] is False
    assert c.get("/osmand/mirror?id=my-phone&lat=1&lon=1").status_code == 404


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


def test_admin_tabs_split_families_and_companies(env):
    c, _ = env
    c.app.state.cfg.company_hosts = []
    t = login(c, "boss", admin=True)
    page = c.get("/dashboard").text
    assert 'href="/kind/company' in page and "Добавить ребёнка" in page
    c.post("/children", data={"username": "masha", "display_name": "Маша", "csrf": t})
    # вкладка «Компании»: своя группа, свои слова, чужих детей не видно
    r = c.get("/kind/company?back_to=/dashboard", follow_redirects=False)
    assert r.status_code in (302, 303) and r.headers["location"] == "/dashboard"
    page = c.get("/dashboard").text
    assert "Добавить сотрудника" in page and "Маша" not in page
    c.post("/children", data={"username": "ivanov", "display_name": "Иван", "csrf": t})
    kinds = {r["username"]: r["kind"] for r in run_sql(
        "SELECT c.username, f.kind FROM ft_children c JOIN ft_families f ON f.id=c.family_id", fetch=True)}
    assert kinds == {"masha": "family", "ivanov": "company"}
    assert "Иван" in page or "Иван" in c.get("/dashboard").text
    # сотруднику — рабочие умолчания
    rules = run_sql("SELECT limit_minutes FROM ft_rules WHERE username='ivanov'", fetch=True)
    assert len(rules) == 7 and all(r["limit_minutes"] == 60 for r in rules)
    edu = run_sql("SELECT settings FROM ft_children WHERE username='ivanov'", fetch=True)[0]["settings"]
    assert "outlook" in json.dumps(edu, ensure_ascii=False).lower()
    # назад на «Семьи»
    c.get("/kind/family?back_to=/dashboard")
    page = c.get("/dashboard").text
    assert "Маша" in page and "Иван" not in page
    # страницы ошибок у администратора рисуются с вкладками
    r = c.get("/no-such-page")
    assert r.status_code == 404 and 'href="/kind/company' in r.text
    # открытый путь /kind/ не даёт уйти на чужой сайт
    r = c.get("/kind/family?back_to=https://evil.example.org/", follow_redirects=False)
    assert r.headers["location"].startswith("/")


def test_kind_is_admin_only(env):
    c, _ = env
    c.app.state.cfg.company_hosts = []
    t = login(c, "mom")
    c.post("/children", data={"username": "masha", "display_name": "Маша", "csrf": t})
    fid = run_sql("SELECT id FROM ft_families", fetch=True)[0]["id"]
    fam = c.get("/family").text
    assert 'name="section" value="kind"' not in fam and 'href="/kind/' not in c.get("/dashboard").text
    r = c.post(f"/family/{fid}", data={"section": "kind", "kind": "company", "csrf": t})
    assert r.status_code == 403
    assert run_sql("SELECT kind FROM ft_families", fetch=True)[0]["kind"] == "family"
    assert c.get("/kind/company", follow_redirects=False).status_code == 403


def test_company_people_see_company_ui_on_any_host(env):
    c, _ = env
    c.app.state.cfg.company_hosts = ["work.example.com"]
    t = login(c, "boss", admin=True)
    c.get("/kind/company")
    c.post("/children", data={"username": "ivanov", "display_name": "Иван", "csrf": t})
    fid = run_sql("SELECT id FROM ft_families", fetch=True)[0]["id"]
    run_sql("INSERT INTO ft_family_parents(family_id, username) VALUES ($1, 'chief')", fid)
    # руководитель на «семейном» адресе — всё равно рабочие слова
    login(c, "chief")
    page = c.get("/dashboard").text
    assert "Добавить сотрудника" in page and "ребёнка" not in page
    # сотрудник
    c.cookies.clear()
    c.get("/dev-login?u=ivanov&parent=&admin=", follow_redirects=False)
    page = c.get("/", follow_redirects=True).text
    assert "ребён" not in page.lower()
    # агент получает адрес рабочего портала
    p = c.post("/api/agent/heartbeat", headers=enroll(c), json={
        "seq": 1, "caps": ["userlists"], "user": "ivanov"}).json()
    assert "work.example.com" in json.dumps(p)


def test_base_url_by_host():
    cfg = Config(database_url=DSN, public_url="https://kids.example.com", session_secret="s" * 32,
                 enroll_secret="e", company_hosts=["work.example.com"])
    assert cfg.base_url("work.example.com:443") == "https://work.example.com"
    assert cfg.base_url("kids.example.com") == "https://kids.example.com"
    assert cfg.base_url("evil.example.org") == "https://kids.example.com"
    assert cfg.company_url == "https://work.example.com"
    from app.config import norm_host
    for raw in ("https://Work.Example.com/", " work.example.com:443 ", '"work.example.com"',
                "work.example.com.", "https://work.example.com/oidc/callback"):
        assert norm_host(raw) == "work.example.com", raw
    import os
    os.environ["COMPANY_HOSTS"] = "https://Work.Example.com/, other.example.com"
    try:
        assert Config.from_env().company_hosts == ["work.example.com", "other.example.com"]
    finally:
        del os.environ["COMPANY_HOSTS"]


def test_login_returns_to_company_host(env):
    c, _ = env

    async def meta():
        return {"authorization_endpoint": "https://sso.example.com/auth"}
    c.app.state.oidc.meta = meta
    c.app.state.cfg.dev_login = False
    c.cookies.clear()
    for headers, want in (({"host": "work.example.com"}, "work.example.com"),
                          ({"host": "WORK.example.com:443"}, "work.example.com"),
                          ({"host": "backend:8000", "x-forwarded-host": "work.example.com"}, "work.example.com"),
                          ({"host": "kids.example.com"}, "kids.example.com"),
                          ({"host": "evil.example.org"}, "kids.example.com")):
        r = c.get("/login", headers=headers, follow_redirects=False)
        assert f"redirect_uri=https%3A%2F%2F{want}%2Foidc%2Fcallback" in r.headers["location"], headers



def _agent_rules():
    import importlib.util, pathlib
    path = pathlib.Path(__file__).resolve().parents[2] / "agent/familytime_agent/core/rules.py"
    spec = importlib.util.spec_from_file_location("agent_rules", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_lock_now_until_time(env):
    c, _ = env
    t = login(c, "mom")
    c.post("/children", data={"username": "ivan", "display_name": "Ваня", "csrf": t})
    assert "Заблокировать" in c.get("/dashboard").text
    r = c.post("/child/ivan/lock", data={"until": "60", "csrf": t, "ret": "/dashboard"})
    assert "Заблокировано до" in r.text and "заблокирован до" in r.text
    tz = c.app.state.cfg.tz
    now = datetime.now(timezone.utc).astimezone(tz)
    h = enroll(c)
    p = c.post("/api/agent/heartbeat", headers=h, json={
        "seq": 1, "caps": ["userlists"], "user": "ivan"}).json()["users"]["ivan"]
    assert p["mode"] == "blocked" and p["reason"] == "manual"
    rule = p["rules"][str(now.weekday())] if (now + timedelta(minutes=61)).date() == now.date() \
        else p["rules"][str(now.weekday())]
    assert rule["block_from"] and rule["block_to"]
    end = rule["block_to"] if rule["block_to"] != "00:00" else p["rules"][
        str((now.weekday() + 1) % 7)]["block_to"]
    assert end in p["messages"]["block"]
    # агент (и старый 1.3.0) сам считает «заблокирован» по правилам, в том числе без связи
    ar = _agent_rules()
    pol = dict(p)
    assert ar.evaluate(pol, now.replace(tzinfo=None), 0)["mode"] == "blocked"
    later = (now + timedelta(minutes=62)).replace(tzinfo=None)
    pol_later = dict(p, day=later.date().isoformat())
    assert ar.evaluate(pol_later, later, 0)["mode"] != "blocked"
    # своё сообщение и «до ЧЧ:ММ»
    c.post("/child/ivan/lock", data={"at": "07:00", "message": "Ужинать! До {block_to}", "csrf": t})
    p = c.post("/api/agent/heartbeat", headers=h, json={
        "seq": 2, "caps": ["userlists"], "user": "ivan"}).json()["users"]["ivan"]
    assert p["messages"]["block"] == "Ужинать! До 07:00"
    # снять
    assert "Блокировка снята" in c.post("/child/ivan/unlock", data={"csrf": t}).text
    p = c.post("/api/agent/heartbeat", headers=h, json={
        "seq": 3, "caps": ["userlists"], "user": "ivan"}).json()["users"]["ivan"]
    assert p["mode"] != "blocked"
    # истёкшая блокировка не действует
    run_sql("UPDATE ft_children SET lock_until = now() - interval '1 minute'")
    assert "заблокирован до" not in c.get("/dashboard").text
    # чужой родитель
    t2 = login(c, "stranger")
    r = c.post("/child/ivan/lock", data={"until": "60", "csrf": t2})
    assert r.status_code in (403, 404)


def test_lock_rules_across_midnight():
    from datetime import timedelta as td
    from app.agent_api import lock_rules
    import zoneinfo
    tz = zoneinfo.ZoneInfo("Europe/Moscow")
    now = datetime(2026, 11, 16, 22, 30, 20, tzinfo=tz)        # понедельник
    rules = {str(d): {"block_from": None, "block_to": None} for d in range(7)}
    lock_rules(rules, now, now.replace(hour=7, minute=0, second=0) + td(days=1))
    assert rules["0"] == {"block_from": "22:29", "block_to": "00:00"}
    assert rules["1"] == {"block_from": "00:00", "block_to": "07:00"}
    ar = _agent_rules()
    from datetime import time as t_
    assert ar.in_block(rules["0"], t_(23, 59)) and ar.in_block(rules["1"], t_(6, 59))
    assert not ar.in_block(rules["1"], t_(7, 0)) and not ar.in_block(rules["0"], t_(22, 0))


def _package(version="1.4.0", sep="/"):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("install.ps1", "# install")
        z.writestr("uninstall.ps1", "# uninstall")
        z.writestr(f"FamilyTime{sep}familytime-agent.exe", b"MZ" + b"0" * 1000)
        z.writestr(f"FamilyTime{sep}version.txt", "\ufeff" + version + "\r\n")
    return buf.getvalue()


def test_package_from_windows_powershell(env):
    """Compress-Archive в Windows PowerShell 5.1 пишет пути через обратную косую черту."""
    c, _ = env
    ta = login(c, "root", admin=True)
    r = c.post("/settings/agent", data={"csrf": ta},
               files={"package": ("FamilyTime-1.4.0.zip", _package("1.4.0", "\\"), "application/zip")})
    assert r.status_code == 200 and "Агент 1.4.0 загружен" in r.text


def test_install_outside_domain(env):
    import hashlib
    c, _ = env
    t = login(c, "mom")
    c.post("/children", data={"username": "ivan", "display_name": "Ваня", "csrf": t})
    # пакета ещё нет
    page = c.get("/devices").text
    assert "Администратор ещё не загрузил" in page
    assert c.get("/agent/latest").json() == {"version": ""}
    # администратор загружает пакет; мусор не принимается
    ta = login(c, "root", admin=True)
    r = c.post("/settings/agent", data={"csrf": ta}, files={"package": ("x.zip", b"nope", "application/zip")})
    assert "это не zip-архив" in r.text
    pkg = _package("1.4.0")
    r = c.post("/settings/agent", data={"csrf": ta}, files={"package": ("FamilyTime-1.4.0.zip", pkg, "application/zip")})
    assert "Агент 1.4.0 загружен" in r.text and "1.4.0" in c.get("/settings").text
    meta = c.get("/agent/latest").json()
    assert meta["version"] == "1.4.0" and meta["sha256"] == hashlib.sha256(pkg).hexdigest()
    r = c.get("/agent/package.zip")
    assert r.content == pkg and r.headers["x-agent-version"] == "1.4.0"
    assert "Install-FamilyTime" in c.get("/agent/setup.ps1").text
    # родитель скачивает установщик с кодом
    t = login(c, "mom")
    page = c.get("/devices").text
    assert "Скачать установщик" in page and "FamilyTime-setup.cmd" in page
    r = c.post("/devices/installer", data={"csrf": t, "mode": "control"})
    assert r.headers["content-disposition"].endswith('filename="FamilyTime-setup.cmd"')
    cmd = r.content.decode("ascii")
    assert "\r\n" in cmd and 'set "FT_URL=https://kids.example.com"' in cmd
    code = re.search(r'set "FT_CODE=([A-Z0-9-]+)"', cmd).group(1)
    assert re.fullmatch(r"[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}", code)
    info = c.get(f"/agent/latest?code={code}").json()
    assert info["code_ok"] is True and info["mode"] == "control"
    assert c.get("/agent/latest?code=AAAA-BBBB-CCCC").json()["code_ok"] is False
    # регистрация по коду: сразу в семье мамы
    r = c.post("/api/agent/enroll", json={"hostname": "home-pc", "secret": code.lower().replace("-", " ")})
    assert r.status_code == 200
    fam = run_sql("SELECT family_id FROM ft_children WHERE username='ivan'", fetch=True)[0]["family_id"]
    dev = run_sql("SELECT family_id, mode FROM ft_devices WHERE hostname='home-pc'", fetch=True)[0]
    assert dev["family_id"] == fam and dev["mode"] == "control"
    assert "home-pc" in c.get("/devices").text
    assert run_sql("SELECT uses FROM ft_install_codes", fetch=True)[0]["uses"] == 1
    # неверный код и чужая семья
    assert c.post("/api/agent/enroll", json={"hostname": "x", "secret": "ZZZZ-ZZZZ-ZZZZ"}).status_code == 403
    t2 = login(c, "stranger")
    assert c.post("/devices/installer", data={"csrf": t2, "family_id": str(fam)}).status_code in (303, 403)
    # отозванный код не работает
    t = login(c, "mom")
    cid = run_sql("SELECT id FROM ft_install_codes", fetch=True)[0]["id"]
    assert "Код отозван" in c.post(f"/devices/codes/{cid}/revoke", data={"csrf": t}).text
    assert c.post("/api/agent/enroll", json={"hostname": "y", "secret": code}).status_code == 403
    # общий секрет (GPO) по-прежнему работает
    assert c.post("/api/agent/enroll", json={"hostname": "dom-pc", "secret": "enroll"}).status_code == 200


def test_agent_auto_update_offer(env):
    c, _ = env
    ta = login(c, "root", admin=True)
    c.post("/settings/agent", data={"csrf": ta}, files={"package": ("p.zip", _package("1.4.1"), "application/zip")})
    h = enroll(c)
    hb = lambda ver, caps: c.post("/api/agent/heartbeat", headers=h, json={  # noqa: E731
        "seq": 1, "caps": caps, "agent_version": ver}).json()
    up = hb("1.4.0", ["lists", "userlists", "update"])["update"]
    assert up["version"] == "1.4.1" and up["url"] == "/agent/package.zip" and len(up["sha256"]) == 64
    assert "update" not in hb("1.4.1", ["lists", "userlists", "update"])
    assert "update" not in hb("1.5.0", ["lists", "userlists", "update"])
    assert "update" not in hb("1.3.0", ["lists", "userlists"])       # старый агент не умеет
    # выключено в настройках
    c.post("/settings", data={"csrf": ta, "only": "auto_update", "auto_update": ""})
    assert "update" not in hb("1.4.0", ["lists", "userlists", "update"])
    # хранятся три последние версии
    for v in ("1.4.2", "1.4.10", "1.5.0"):
        c.post("/settings/agent", data={"csrf": ta}, files={"package": ("p.zip", _package(v), "application/zip")})
    vers = sorted(r["version"] for r in run_sql("SELECT version FROM ft_agent_packages", fetch=True))
    assert vers == ["1.4.10", "1.4.2", "1.5.0"]
    assert c.get("/agent/latest").json()["version"] == "1.5.0"
