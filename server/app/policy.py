"""Чистая логика: правила дня, остаток, окна, учебные приложения и сайты, тексты сообщений."""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from urllib.parse import urlsplit

WEEKDAYS = ["Понедельник", "Вторник", "Среда", "Четверг", "Пятница", "Суббота", "Воскресенье"]
WEEKDAYS_SHORT = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]

DEFAULT_SETTINGS: dict = {
    # время в этих приложениях не списывается и они работают в режиме «только учёба»
    "edu_apps": [
        "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "notepad.exe",
        "acrord32.exe", "acrobat.exe", "sumatrapdf.exe", "geogebra.exe", "code.exe",
        "pycharm64.exe", "idle.exe", "python.exe", "pythonw.exe", "calc.exe",
        "calculatorapp.exe", "mspaint.exe",
    ],
    # время на этих сайтах (и их поддоменах) не списывается
    "edu_domains": [
        "uchi.ru", "resh.edu.ru", "dnevnik.ru", "school.mos.ru", "mos.ru", "yaklass.ru",
        "foxford.ru", "skysmart.ru", "education.yandex.ru", "ru.wikipedia.org",
        "gramota.ru", "mathway.com", "khanacademy.org", "duolingo.com", "geogebra.org",
    ],
    # запрещены всегда (другие браузеры и т. п.)
    "blocked_apps": [
        "firefox.exe", "opera.exe", "brave.exe", "vivaldi.exe", "tor.exe", "waterfox.exe",
        "librewolf.exe", "iexplore.exe", "palemoon.exe", "maxthon.exe", "chromium.exe",
    ],
    # запрещены всегда, в любом режиме (и их поддомены)
    "blocked_domains": [],
    # ссылки-протоколы, которые браузер может открывать в режиме «только учёба»
    # (telemost://… — кнопка «Открыть в приложении» Яндекс Телемоста)
    "edu_schemes": ["telemost", "zoommtg", "msteams"],
    # браузеры, которым агент выставляет политики: chrome, edge, Яндекс
    "browsers": ["chrome.exe", "msedge.exe", "browser.exe"],
    # в режиме «только учёба» закрываются и эти процессы, даже без окна
    "restricted_kill": ["steam.exe", "epicgameslauncher.exe", "discord.exe", "telegram.exe"],
    "idle_minutes": 15,        # простой дольше — время не идёт (0 — не учитывать простой)
    "warn_minutes": [10, 5],
    "messages": {
        "warn": "{name}, осталось {left}. Сохрани то, что делаешь.",
        "limit": "{name}, время за компьютером на сегодня закончилось ({limit}). "
                 "Можно заниматься учёбой: учебные сайты и программы работают. "
                 "Попросить ещё время можно на портале.",
        "window": "{name}, сейчас компьютер работает только для учёбы. "
                  "Свободное время — с {from} до {to}.",
        "lost": "Этот компьютер потерян. Если вы его нашли, пожалуйста, свяжитесь с владельцем.",
    },
    "location": {"interval_minutes": 15, "lost_interval_minutes": 2},
    # известные адреса: [{"net": "203.0.113.5/32", "lat": .., "lon": .., "accuracy": 50, "name": "Дом"}]
    "ip_locations": [],
}

# что настраивается у каждого ребёнка (копируется между детьми вместе с подписками)
CHILD_LIST_KEYS = {
    "edu_domains": "domain", "blocked_domains": "domain", "edu_apps": "exe",
    "blocked_apps": "exe", "edu_schemes": "scheme", "restricted_kill": "exe",
}
CHILD_KEYS = (*CHILD_LIST_KEYS, "idle_minutes", "warn_minutes")
FAMILY_MESSAGE_KEYS = ("warn", "limit", "window")


def child_settings(stored: dict | None) -> dict:
    """Настройки ребёнка поверх значений по умолчанию."""
    out = {k: copy.deepcopy(DEFAULT_SETTINGS[k]) for k in CHILD_KEYS}
    for k, v in (stored or {}).items():
        if k in out:
            out[k] = v
    return out


def family_messages(stored: dict | None) -> dict:
    out = {k: DEFAULT_SETTINGS["messages"][k] for k in FAMILY_MESSAGE_KEYS}
    out.update({k: v for k, v in (stored or {}).items() if k in out and v})
    return out


DEFAULT_RULES = [
    # (лимит, с, до) по дням Пн..Вс
    (90, time(7, 0), time(21, 30)),
    (90, time(7, 0), time(21, 30)),
    (90, time(7, 0), time(21, 30)),
    (90, time(7, 0), time(21, 30)),
    (120, time(7, 0), time(22, 0)),
    (180, time(8, 0), time(22, 0)),
    (180, time(8, 0), time(21, 30)),
]


def merge_settings(stored: dict) -> dict:
    out = copy.deepcopy(DEFAULT_SETTINGS)
    for k, v in (stored or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k].update(v)
        else:
            out[k] = v
    return out


# ---------- нормализация ----------

def norm_exe(name: str | None) -> str:
    if not name:
        return ""
    name = name.strip().replace("/", "\\").split("\\")[-1].lower()
    return name


def norm_domain(value: str | None) -> str:
    """'https://www.Uchi.ru/path' / 'uchi.ru/x' / 'www.uchi.ru' -> 'uchi.ru'."""
    if not value:
        return ""
    v = value.strip().lower()
    if "://" not in v:
        v = "http://" + v
    try:
        host = urlsplit(v).hostname or ""
    except ValueError:
        return ""
    host = host.strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not re.fullmatch(r"[a-z0-9.\-Ѐ-ӿ]+", host or "-"):
        return ""
    return host


def norm_scheme(value: str | None) -> str:
    """'telemost://https//telemost.yandex.ru' / 'Telemost:' / 'telemost' -> 'telemost'."""
    v = (value or "").strip().lower().split(":", 1)[0]
    if v in ("http", "https", "file", "javascript", "data", "chrome", "edge", "about") \
            or not re.fullmatch(r"[a-z][a-z0-9+.\-]{1,30}", v):
        return ""
    return v


def clean_list(lines, kind: str) -> list[str]:
    """Текст из textarea или список -> уникальный нормализованный список."""
    if isinstance(lines, str):
        lines = re.split(r"[\s,;]+", lines)
    out: list[str] = []
    seen: set[str] = set()
    for x in lines or []:
        if kind == "scheme":
            x = norm_scheme(x)
        else:
            x = norm_domain(x) if kind == "domain" else norm_exe(x)
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def domain_matches(domain: str, patterns) -> bool:
    """Домен или его родитель есть в patterns (список или множество).

    Проверяются суффиксы по меткам: school.mos.ru → school.mos.ru, mos.ru, ru — поэтому для
    множества из сотен тысяч доменов это несколько поисков, а не перебор.
    """
    d = norm_domain(domain)
    if not d:
        return False
    while True:
        if d in patterns:
            return True
        if "." not in d:
            return False
        d = d.split(".", 1)[1]


def is_free(exe: str, domain: str, settings: dict) -> bool:
    """Не списывается: учебное приложение или учебный сайт в браузере."""
    exe = norm_exe(exe)
    if exe in settings["edu_apps"]:
        return True
    if domain and exe in settings["browsers"] and domain_matches(domain, settings["edu_domains"]):
        return True
    return False


# ---------- правила дня ----------

@dataclass
class Rule:
    limit_minutes: int | None        # None — без лимита
    window_from: time | None
    window_to: time | None


def in_window(rule: Rule, t: time) -> bool:
    if rule.window_from is None or rule.window_to is None:
        return True
    a, b = rule.window_from, rule.window_to
    if a == b:
        return True
    if a < b:
        return a <= t < b
    return t >= a or t < b           # через полночь


def seconds_to_window_change(rule: Rule, now: datetime) -> int | None:
    if rule.window_from is None or rule.window_to is None or rule.window_from == rule.window_to:
        return None
    target = rule.window_to if in_window(rule, now.time()) else rule.window_from
    cand = now.replace(hour=target.hour, minute=target.minute, second=0, microsecond=0)
    if cand <= now:
        cand += timedelta(days=1)
    return int((cand - now).total_seconds())


def fmt_minutes(seconds: int | float | None) -> str:
    if seconds is None:
        return "без ограничений"
    m = max(0, int(round(seconds / 60)))
    h, m = divmod(m, 60)
    if h and m:
        return f"{h} ч {m} мин"
    if h:
        return f"{h} ч"
    return f"{m} мин"


def fmt_time(t: time | None) -> str:
    return t.strftime("%H:%M") if t else ""


def compute_status(rule: Rule, bonus_minutes: int, counted_seconds: int, now_local: datetime) -> dict:
    limit_s = None if rule.limit_minutes is None else max(0, (rule.limit_minutes + bonus_minutes) * 60)
    remaining = None if limit_s is None else max(0, limit_s - counted_seconds)
    window_ok = in_window(rule, now_local.time())
    if not window_ok:
        mode, reason = "restricted", "window"
    elif remaining is not None and remaining <= 0:
        mode, reason = "restricted", "limit"
    else:
        mode, reason = "normal", None
    return {
        "mode": mode,
        "reason": reason,
        "limit_seconds": limit_s,
        "counted_seconds": counted_seconds,
        "remaining_seconds": remaining,
        "window_open": window_ok,
        "window_change_in": seconds_to_window_change(rule, now_local),
    }


_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def render(template: str, values: dict) -> str:
    """Подставляет известные {ключи}; неизвестные (например, {left}) оставляет как есть."""
    def sub(m):
        k = m.group(1)
        return str(values[k]) if k in values else m.group(0)
    return _PLACEHOLDER.sub(sub, template or "")
