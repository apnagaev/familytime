"""HTTP-клиент к серверу (только стандартная библиотека; сертификаты — из хранилища Windows)."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request


class ApiError(Exception):
    def __init__(self, status: int, text: str = ""):
        super().__init__(f"HTTP {status}: {text[:200]}")
        self.status = status


class Client:
    def __init__(self, base_url: str, user_agent: str, timeout: float = 20):
        self.base = base_url.rstrip("/")
        self.ua = user_agent
        self.timeout = timeout
        self.ctx = ssl.create_default_context()

    def trust(self, pems: list[str]) -> int:
        """Новый контекст TLS: хранилище Windows (с уже добавленными туда центрами) плюс
        дополнительные центры из политики. Возвращает, сколько из них принято."""
        ctx = ssl.create_default_context()
        ok = 0
        for pem in pems:
            try:
                ctx.load_verify_locations(cadata=pem)
                ok += 1
            except (ssl.SSLError, ValueError):
                pass
        self.ctx = ctx
        return ok

    def post(self, path: str, body: dict, token: str = "") -> dict:
        data = json.dumps(body, ensure_ascii=False).encode()
        req = urllib.request.Request(self.base + path, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", self.ua)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                return json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            raise ApiError(e.code, e.read().decode(errors="replace")) from None
