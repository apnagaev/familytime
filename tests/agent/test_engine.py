import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent"))

from familytime_agent.core import rules, wifi  # noqa: E402
from familytime_agent.core.client import ApiError  # noqa: E402
from familytime_agent.core.engine import Engine, Session  # noqa: E402
from familytime_agent.core.state import Store  # noqa: E402

DAY0 = 1762851600.0     # 2025-11-11 09:00 UTC = 12:00 МСК, вторник


class Clock:
    def __init__(self):
        self.t = DAY0
        self.m = 1000.0

    def wall(self):
        return self.t

    def mono(self):
        return self.m

    def adv(self, s):
        self.t += s
        self.m += s


class FakePlatform:
    def __init__(self):
        self.session = Session(1, "ivan", "EXAMPLE", False)
        self.report = {"idle": 0, "fullscreen": False, "fg": {"exe": "game.exe", "domain": ""},
                       "windows": [{"pid": 50, "exe": "game.exe"}, {"pid": 51, "exe": "winword.exe"},
                                   {"pid": 52, "exe": "explorer.exe"}]}
        self.procs = [(60, "Steam.exe"), (61, "firefox.exe"), (62, "svchost.exe")]
        self.killed, self.logoffs, self.launched = [], [], []
        self.policy_calls = []
        self.blocked_calls = []
        self.cleared = []
        self.directive = None

    def hostname(self): return "kidlap.example.local"
    def os_version(self): return "Windows 11 Pro"
    def local_ip(self): return "10.0.0.5"
    def console_session(self): return self.session
    def helper_report(self, sid): return self.report
    def launch_helper(self, sid): self.launched.append(sid)
    def set_directive(self, sid, d): self.directive = d
    def session_processes(self, sid): return self.procs
    def kill(self, pid): self.killed.append(pid)
    def logoff(self, sid): self.logoffs.append(sid)
    def clear_browser_policy(self, sid, user, domain): self.cleared.append(user)
    def set_browser_policy(self, sid, user, domain, allowed, blocked=None):
        self.policy_calls.append(allowed)
        self.blocked_calls.append(list(blocked or []))
    def wifi_scan(self): return [{"bssid": "aa:bb:cc:dd:ee:ff", "rssi": -50}]
    def battery(self): return 80, True


def policy(counted, limit=1800, rules_=None):
    return {"child": True, "name": "Ваня", "day": "2025-11-11", "mode": "normal",
            "limit_seconds": limit, "counted_seconds": counted,
            "remaining_seconds": max(0, limit - counted),
            "messages": {"warn": "Осталось {left}", "limit": "Всё, лимит", "window": "Не время"},
            "rules": rules_ or {str(i): {"limit": 30, "from": "07:00", "to": "21:30"} for i in range(7)}}


DEVICE = {"mode": "control", "edu_apps": ["winword.exe"], "edu_domains": ["uchi.ru"],
          "restricted_domains": ["uchi.ru", "kids.example.com"],
          "browsers": ["chrome.exe", "msedge.exe", "browser.exe"], "blocked_apps": ["firefox.exe"],
          "restricted_kill": ["steam.exe"], "idle_minutes": 15, "warn_minutes": [10, 5],
          "location_interval": 900, "portal_url": "https://kids.example.com",
          "lost": {"on": False, "lock": False, "message": ""}}


class FakeClient:
    def __init__(self):
        self.calls = []
        self.server_counted = 0
        self.fail = False
        self.limit = 1800
        self.clock = lambda: DAY0
        self.lists_version = None
        self.lists = {}
        self.lists_calls = 0

    def post(self, path, body, token=""):
        self.calls.append((path, body))
        if self.fail:
            raise OSError("offline")
        if path.endswith("/enroll"):
            return {"token": "tok", "hostname": body["hostname"]}
        if path.endswith("/heartbeat"):
            self.server_counted += sum(s["sec"] for s in body["samples"]
                                       if s["exe"] != "winword.exe"
                                       and not s["domain"].endswith("uchi.ru"))
            device = DEVICE
            if self.lists_version:                     # сервер 1.1: списки отдельно
                device = {k: v for k, v in DEVICE.items()
                          if k not in ("edu_apps", "edu_domains", "blocked_apps",
                                       "restricted_domains")}
                device["lists_version"] = self.lists_version
            assert body.get("caps") == ["lists"]
            return {"server_time": self.clock(), "utc_offset": 10800, "device": device,
                    "users": {"ivan": policy(self.server_counted, self.limit)}}
        if path.endswith("/lists"):
            self.lists_calls += 1
            return {"version": self.lists_version, **self.lists}
        if path.endswith("/location"):
            return {"ok": True, "next_interval": 900}
        raise AssertionError(path)


def make(tmp_path):
    clk, plat, cli = Clock(), FakePlatform(), FakeClient()
    cli.clock = clk.wall
    eng = Engine({"server_url": "https://x", "enroll_secret": "e"}, Store(str(tmp_path / "s.json")),
                 plat, cli, clock=clk.wall, mono=clk.mono)
    return eng, clk, plat, cli


def run(eng, clk, seconds):
    for _ in range(int(seconds / 5)):
        clk.adv(5)
        eng.step()


def test_counting_limit_and_restricted(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    eng.step()                                  # регистрация, первый пульс, политика
    assert eng.st.token == "tok" and eng.st.users["ivan"]["child"]
    run(eng, clk, 20 * 60)                      # 20 минут игры
    assert 1150 <= cli.server_counted <= 1250
    run(eng, clk, 5 * 60)                       # предупреждение за 10 минут
    assert plat.directive["mode"] == "normal"
    assert any(c is None for c in plat.policy_calls)
    for _ in range(100):                        # до лимита
        run(eng, clk, 5)
        if plat.directive["mode"] == "restricted":
            break
    d = plat.directive
    assert d["mode"] == "restricted" and d["notify"]["text"] == "Всё, лимит" and d["notify"]["modal"]
    assert d["close_browsers"]
    assert plat.policy_calls[-1] == ["uchi.ru", "kids.example.com"]
    assert 61 in plat.killed and 60 in plat.killed and 62 not in plat.killed
    assert d["close"] == [50]                   # игра закрывается, Word и проводник — нет
    run(eng, clk, 15)
    assert 50 in plat.killed                    # не закрылась сама — принудительно


def test_edu_time_is_free(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    plat.report["fg"] = {"exe": "chrome.exe", "domain": "school.uchi.ru"}
    eng.step()
    run(eng, clk, 60 * 60)
    assert plat.directive["mode"] == "normal"
    assert all(s.get("free") for s in eng.st.pending + (eng.st.inflight or {}).get("samples", []))


def test_idle_not_counted_unless_fullscreen(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    eng.step()
    plat.report["idle"] = 20 * 60
    run(eng, clk, 10 * 60)
    assert cli.server_counted == 0
    plat.report["fullscreen"] = True
    run(eng, clk, 10 * 60)
    assert cli.server_counted >= 9 * 60


def test_offline_keeps_counting_and_no_double_count(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    eng.step()
    cli.fail = True
    run(eng, clk, 35 * 60)                     # без связи лимит всё равно наступает
    assert plat.directive["mode"] == "restricted"
    cli.fail = False
    run(eng, clk, 65)
    # всё неотправленное дошло ровно один раз
    assert 34 * 60 <= cli.server_counted <= 36 * 60 + 70
    seqs = [b["seq"] for p, b in cli.calls if p.endswith("/heartbeat")]
    assert seqs == sorted(seqs)


def test_window_outside_hours(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    clk.t = DAY0 + 10 * 3600                    # 22:00 МСК
    eng.step()
    run(eng, clk, 5)
    assert plat.directive["mode"] == "restricted" and plat.directive["reason"] == "window"


def test_lost_lock_logs_off(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    eng.step()
    eng.st.device = {**DEVICE, "lost": {"on": True, "lock": True, "message": "Верните"}}
    run(eng, clk, 5)
    assert plat.logoffs == [1] and plat.directive["lost"]["message"] == "Верните"


def test_helper_missing_in_restricted_logs_off(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    cli.limit = 0
    eng.step()
    run(eng, clk, 10)
    plat.report = None
    run(eng, clk, 50)
    assert not plat.logoffs and not plat.launched      # пара пропущенных отчётов — не повод
    run(eng, clk, 70)
    assert plat.logoffs and plat.launched == [1]          # перезапуск не чаще раза в минуту


def test_adult_not_tracked(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    plat.session = Session(2, "parent", "EXAMPLE", False)
    cli_post = cli.post

    def post(path, body, token=""):
        r = cli_post(path, body, token)
        if path.endswith("/heartbeat"):
            r["users"] = {"parent": {"child": False, "mode": "none"}}
        return r
    cli.post = post
    eng.step()
    run(eng, clk, 600)
    hb = [b for p, b in cli.calls if p.endswith("/heartbeat")]
    assert all(not b["samples"] for b in hb)
    assert plat.killed == []


def test_unauthorized_reenrolls(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    eng.step()
    orig = cli.post

    def post(path, body, token=""):
        if path.endswith("/heartbeat") and token == "tok" and not getattr(cli, "seen401", False):
            cli.seen401 = True
            raise ApiError(401, "unknown device")
        return orig(path, body, token)
    cli.post = post
    run(eng, clk, 130)
    assert cli.seen401 and eng.st.token == "tok"
    enrolls = [p for p, b in cli.calls if p.endswith("/enroll")]
    assert len(enrolls) == 2


def test_rules_offline_new_day():
    pol = policy(1700)
    ev = rules.evaluate(pol, rules.local_now(0, 10800, DAY0 + 86400), 120)   # следующий день
    assert ev["mode"] == "normal" and ev["remaining"] == 1800 - 120


def test_netsh_parse():
    text = """
SSID 1 : home
    Тип сети                : Инфраструктура
    BSSID 1                 : 1c:61:b4:aa:bb:cc
         Сигнал             : 92%
         Тип радио          : 802.11ax
    BSSID 2                 : 1c:61:b4:aa:bb:cd
         Signal             : 40%
"""
    aps = wifi.parse_netsh(text)
    assert aps == [{"bssid": "1c:61:b4:aa:bb:cc", "rssi": -54},
                   {"bssid": "1c:61:b4:aa:bb:cd", "rssi": -80}]


def test_lists_by_version_and_blocked_sites(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    big = [f"site{i}.example" for i in range(3000)]
    cli.lists_version = "v1"
    cli.lists = {"edu_apps": ["winword.exe"], "edu_domains": ["uchi.ru"],
                 "blocked_apps": ["firefox.exe"], "blocked_domains": ["vk.com"] + big,
                 "restricted_domains": ["kids.example.com", "uchi.ru"]}
    plat.report["fg"] = {"exe": "chrome.exe", "domain": "m.vk.com/feed", "hwnd": 777,
                         "app": "Google Chrome"}
    eng.step()
    assert cli.lists_calls == 1 and eng.lists["version"] == "v1"
    assert (tmp_path / "lists.json").exists()
    run(eng, clk, 5)
    # обычный режим: в политике первые 1000 запрещённых, ручной vk.com — первым
    assert plat.policy_calls[-1] is None
    assert len(plat.blocked_calls[-1]) == 1000 and plat.blocked_calls[-1][0] == "vk.com"
    # вкладка с запрещённым сайтом закрывается, в том числе сверх 1000
    ct = plat.directive.get("close_tab")
    assert ct and ct["domain"] == "m.vk.com" and ct["hwnd"] == 777
    plat.report["fg"]["domain"] = "a.site2999.example"
    run(eng, clk, 5)
    assert plat.directive["close_tab"]["domain"] == "a.site2999.example"
    plat.report["fg"]["domain"] = "uchi.ru"
    run(eng, clk, 5)
    assert "close_tab" not in plat.directive
    # та же версия — повторно не качаем; новая — качаем
    run(eng, clk, 65)
    assert cli.lists_calls == 1
    cli.lists_version = "v2"
    cli.lists["blocked_domains"] = []
    run(eng, clk, 65)
    assert cli.lists_calls == 2 and plat.blocked_calls[-1] == []
    # название программы уходит на сервер
    hb = [b for p, b in cli.calls if p.endswith("/heartbeat") and b["samples"]]
    assert hb[-1]["samples"][0]["app"] == "Google Chrome"
    # после перезапуска списки берутся с диска
    eng2 = Engine({"server_url": "https://x", "enroll_secret": "e"},
                  Store(str(tmp_path / "s.json")), plat, cli, clock=clk.wall, mono=clk.mono)
    assert eng2.lists["version"] == "v2"


def test_restricted_allowlist_excludes_blocked(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    cli.limit = 0
    cli.lists_version = "v1"
    cli.lists = {"edu_apps": [], "edu_domains": ["uchi.ru", "bad.uchi.ru"],
                 "blocked_apps": [], "blocked_domains": ["bad.uchi.ru"],
                 "restricted_domains": ["kids.example.com", "uchi.ru", "bad.uchi.ru"]}
    eng.step()
    run(eng, clk, 10)
    assert plat.directive["mode"] == "restricted"
    assert plat.policy_calls[-1] == ["kids.example.com", "uchi.ru"]


def test_policies_cleared_for_non_child(tmp_path):
    eng, clk, plat, cli = make(tmp_path)
    eng.step()
    run(eng, clk, 10)
    assert plat.policy_calls and not plat.cleared           # ребёнок: политики стоят
    # учётку убрали из детей — политики снимаются (один раз)
    orig = cli.post

    def post(path, body, token=""):
        r = orig(path, body, token)
        if path.endswith("/heartbeat"):
            r["users"] = {u: {"child": False, "mode": "none"} for u in ("ivan", "parent")}
        return r
    cli.post = post
    run(eng, clk, 70)
    assert plat.cleared == ["ivan"]
    # взрослый вошёл: его политики чистятся один раз
    plat.session = Session(2, "parent", "EXAMPLE", False)
    run(eng, clk, 5)
    assert plat.cleared == ["ivan", "parent"]
    run(eng, clk, 120)
    assert plat.cleared == ["ivan", "parent"]
    # пока сервер не ответил, кто вошёл, ничего не трогаем (ребёнку не открываем инкогнито)
    plat.session = Session(3, "petya", "EXAMPLE", False)
    cli.fail = True
    run(eng, clk, 30)
    assert plat.cleared == ["ivan", "parent"]
