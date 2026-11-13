from datetime import datetime, time

from app import policy
from app.policy import Rule


def test_norm_domain():
    assert policy.norm_domain("https://www.Uchi.ru/path?q=1") == "uchi.ru"
    assert policy.norm_domain("school.mos.ru/diary") == "school.mos.ru"
    assert policy.norm_domain("") == ""
    assert policy.norm_domain("not a url") == ""


def test_domain_matches_subdomains_only():
    assert policy.domain_matches("school.mos.ru", ["mos.ru"])
    assert not policy.domain_matches("evilmos.ru", ["mos.ru"])


def test_is_free():
    s = policy.merge_settings({})
    assert policy.is_free("C:\\Program Files\\Office\\WINWORD.EXE", "", s)
    assert policy.is_free("chrome.exe", "uchi.ru", s)
    assert not policy.is_free("chrome.exe", "youtube.com", s)
    assert not policy.is_free("game.exe", "uchi.ru", s)      # домен только у браузеров


def test_window_and_status():
    r = Rule(60, time(7), time(21, 30))
    now = datetime(2026, 11, 11, 12, 0)
    st = policy.compute_status(r, 0, 30 * 60, now)
    assert st["mode"] == "normal" and st["remaining_seconds"] == 30 * 60
    st = policy.compute_status(r, 15, 75 * 60, now)
    assert st["mode"] == "restricted" and st["reason"] == "limit"
    st = policy.compute_status(r, 0, 0, datetime(2026, 11, 11, 22, 0))
    assert st["reason"] == "window"
    assert st["window_change_in"] == 9 * 3600
    st = policy.compute_status(Rule(None, None, None), 0, 10 ** 6, now)
    assert st["mode"] == "normal" and st["remaining_seconds"] is None


def test_window_over_midnight():
    r = Rule(None, time(20), time(2))
    assert policy.in_window(r, time(23))
    assert policy.in_window(r, time(1))
    assert not policy.in_window(r, time(12))


def test_render_keeps_unknown():
    s = policy.render("{name}, осталось {left}", {"name": "Ваня"})
    assert s == "Ваня, осталось {left}"


def test_fmt():
    assert policy.fmt_minutes(80 * 60) == "1 ч 20 мин"
    assert policy.fmt_minutes(3600) == "1 ч"
    assert policy.fmt_minutes(None) == "без ограничений"


def test_clean_list():
    assert policy.clean_list("www.uchi.ru\nhttps://resh.edu.ru/x, uchi.ru", "domain") == [
        "uchi.ru", "resh.edu.ru"]
    assert policy.clean_list("C:\\x\\Steam.exe steam.exe", "exe") == ["steam.exe"]


def test_norm_scheme():
    assert policy.norm_scheme("telemost://https//telemost.yandex.ru") == "telemost"
    assert policy.norm_scheme("Zoommtg:") == "zoommtg"
    assert policy.norm_scheme("https") == "" and policy.norm_scheme("javascript:") == ""
