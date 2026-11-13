"""Классификация и расчёт остатка — то же, что на сервере, для работы без связи."""
from __future__ import annotations

import re
from datetime import datetime, time, timedelta, timezone
from urllib.parse import urlsplit

# системные программы, которые не закрываются в режиме «только учёба»
SYSTEM_APPS = {
    "explorer.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe", "searchhost.exe",
    "searchapp.exe", "searchui.exe", "textinputhost.exe", "lockapp.exe", "applicationframehost.exe",
    "systemsettings.exe", "taskmgr.exe", "ctfmon.exe", "control.exe", "sndvol.exe", "osk.exe",
    "magnify.exe", "narrator.exe", "consent.exe", "credentialuibroker.exe", "werfault.exe",
    "msedgewebview2.exe", "rundll32.exe", "dllhost.exe", "openwith.exe", "pickerhost.exe",
    "familytime-helper.exe", "logonui.exe", "securityhealthsystray.exe", "smartscreen.exe",
    "useroobebroker.exe",
}


def norm_exe(name: str | None) -> str:
    if not name:
        return ""
    return name.strip().replace("/", "\\").split("\\")[-1].lower()


def norm_domain(value: str | None) -> str:
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
    if not re.fullmatch(r"[a-z0-9.\-Ѐ-ӿ]+", host or "-") or "." not in host:
        return ""
    return host


def domain_matches(domain: str, patterns) -> bool:
    """Домен или его родитель есть в patterns. Поиск по суффиксам меток: для множества из
    сотен тысяч доменов это несколько обращений, а не перебор."""
    d = norm_domain(domain)
    while d:
        if d in patterns:
            return True
        if "." not in d:
            return False
        d = d.split(".", 1)[1]
    return False


def is_free(exe: str, domain: str, dev: dict) -> bool:
    exe = norm_exe(exe)
    if exe in dev.get("edu_apps", []):
        return True
    return bool(domain) and exe in dev.get("browsers", []) and \
        domain_matches(domain, dev.get("edu_domains", []))


def allowed_in_restricted(exe: str, dev: dict) -> bool:
    exe = norm_exe(exe)
    return (exe in SYSTEM_APPS or exe in dev.get("edu_apps", [])
            or exe in dev.get("browsers", []))


def _t(v: str | None) -> time | None:
    if not v:
        return None
    h, m = v.split(":")[:2]
    return time(int(h), int(m))


def in_window(rule: dict, t: time) -> bool:
    a, b = _t(rule.get("from")), _t(rule.get("to"))
    if a is None or b is None or a == b:
        return True
    if a < b:
        return a <= t < b
    return t >= a or t < b


def fmt_minutes(seconds) -> str:
    if seconds is None:
        return "без ограничений"
    m = max(0, int(round(seconds / 60)))
    h, m = divmod(m, 60)
    if h and m:
        return f"{h} ч {m} мин"
    if h:
        return f"{h} ч"
    return f"{m} мин"


def evaluate(policy: dict, now_local: datetime, pending_counted_today: int) -> dict:
    """Режим ребёнка сейчас по последней политике сервера и неотправленному времени.

    Если политика за прошлый день (не было связи после полуночи) — берётся правило недели без бонусов.
    """
    today = now_local.date().isoformat()
    rule = policy.get("rules", {}).get(str(now_local.weekday()), {})
    if policy.get("day") == today:
        limit = policy.get("limit_seconds")
        counted = int(policy.get("counted_seconds") or 0) + pending_counted_today
    else:
        lim = rule.get("limit")
        limit = None if lim is None else int(lim) * 60
        counted = pending_counted_today
    remaining = None if limit is None else max(0, limit - counted)
    if not in_window(rule, now_local.time()):
        mode, reason = "restricted", "window"
    elif remaining is not None and remaining <= 0:
        mode, reason = "restricted", "limit"
    else:
        mode, reason = "normal", None
    return {"mode": mode, "reason": reason, "remaining": remaining, "limit": limit,
            "counted": counted}


def local_now(server_offset: float, utc_offset: int, wall: float) -> datetime:
    """Местное время по часам сервера (часы компьютера могут быть сбиты)."""
    ts = wall + server_offset
    return datetime.fromtimestamp(ts, timezone.utc).replace(tzinfo=None) + timedelta(seconds=utc_offset)
