"""Состояние агента на диске: токен, номер пакета, неотправленные отрезки, последняя политика."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field


@dataclass
class State:
    token: str = ""
    hostname: str = ""
    seq: int = 0                                   # последний подтверждённый сервером пакет
    inflight: dict | None = None                   # {"seq": n, "samples": [...]} — отправлен, ответа нет
    pending: list = field(default_factory=list)    # отрезки, ещё не вошедшие в пакет
    device: dict = field(default_factory=dict)     # политика устройства
    users: dict = field(default_factory=dict)      # политика по пользователям
    server_offset: float = 0.0                     # часы сервера минус часы компьютера, с
    utc_offset: int = 3 * 3600
    policy_wall: float = 0.0                       # когда получена политика (по часам компьютера)
    last_location: float = 0.0
    warned: dict = field(default_factory=dict)     # {user: {"day": d, "levels": [..]}}


class Store:
    def __init__(self, path: str):
        self.path = path

    def load(self) -> State:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return State()
        st = State()
        for k, v in data.items():
            if hasattr(st, k):
                setattr(st, k, v)
        return st

    def save(self, st: State) -> None:
        d = os.path.dirname(self.path) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".state-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(asdict(st), f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def load_config(path: str) -> dict:
    """config.json от установщика: server_url, enroll_secret, mode."""
    with open(path, encoding="utf-8-sig") as f:
        cfg = json.load(f)
    cfg["server_url"] = cfg["server_url"].rstrip("/")
    cfg.setdefault("mode", "control")
    return cfg
