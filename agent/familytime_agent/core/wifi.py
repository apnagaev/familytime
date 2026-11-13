"""Разбор вывода `netsh wlan show networks mode=bssid` (русский и английский Windows)."""
from __future__ import annotations

import re

_BSSID = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\s*$")
_SIGNAL = re.compile(r"^\s*(?:Signal|Сигнал)\s*:\s*(\d{1,3})\s*%")


def pct_to_dbm(pct: int) -> int:
    """Качество сигнала Windows (0–100 %) примерно в дБм: 100 % ≈ −50, 0 % ≈ −100."""
    pct = max(0, min(100, int(pct)))
    return int(pct / 2 - 100)


def parse_netsh(text: str) -> list[dict]:
    aps: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        m = _BSSID.match(line)
        if m:
            current = {"bssid": m.group(1).replace("-", ":").lower(), "rssi": -90}
            aps.append(current)
            continue
        m = _SIGNAL.match(line)
        if m and current is not None and current["rssi"] == -90:
            current["rssi"] = pct_to_dbm(int(m.group(1)))
    return aps
