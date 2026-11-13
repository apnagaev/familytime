"""Настройки из переменных окружения."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from zoneinfo import ZoneInfo


def _list(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").replace(";", ",").split(",") if x.strip()]


def _bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    database_url: str = ""
    public_url: str = ""                  # https://kids.example.com
    timezone: str = "Europe/Moscow"
    session_secret: str = ""
    # Keycloak / OIDC
    oidc_issuer: str = ""                 # https://sso.example.com/realms/home
    oidc_client_id: str = "familytime"
    oidc_client_secret: str = ""
    oidc_parent_role: str = "familytime-parent"
    oidc_username_claim: str = "preferred_username"
    # агенты
    enroll_secret: str = ""
    # Яндекс Локатор
    yandex_locator_keys: list[str] = field(default_factory=list)
    yandex_locator_url: str = "https://locator.api.maps.yandex.ru/v1/locate"
    # Traccar
    traccar_osmand_url: str = ""          # http://10.0.0.1:15055
    traccar_api_url: str = ""             # http://10.0.0.1:82/api
    traccar_token: str = ""
    traccar_group_id: int | None = None
    traccar_web_url: str = ""             # для ссылок на карту
    # Telegram
    telegram_token: str = ""
    telegram_chat_ids: list[str] = field(default_factory=list)
    # прочее
    extra_allowed_domains: list[str] = field(default_factory=list)
    trusted_proxy_header: str = "x-real-ip"
    dev_login: bool = False               # только для тестов: вход без Keycloak

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    @classmethod
    def from_env(cls) -> "Config":
        gid = os.environ.get("TRACCAR_GROUP_ID", "").strip()
        return cls(
            database_url=os.environ.get("DATABASE_URL", ""),
            public_url=os.environ.get("PUBLIC_URL", "").rstrip("/"),
            timezone=os.environ.get("TIMEZONE", "Europe/Moscow"),
            session_secret=os.environ.get("SESSION_SECRET", ""),
            oidc_issuer=os.environ.get("OIDC_ISSUER", "").rstrip("/"),
            oidc_client_id=os.environ.get("OIDC_CLIENT_ID", "familytime"),
            oidc_client_secret=os.environ.get("OIDC_CLIENT_SECRET", ""),
            oidc_parent_role=os.environ.get("OIDC_PARENT_ROLE", "familytime-parent"),
            oidc_username_claim=os.environ.get("OIDC_USERNAME_CLAIM", "preferred_username"),
            enroll_secret=os.environ.get("ENROLL_SECRET", ""),
            yandex_locator_keys=_list("YANDEX_LOCATOR_KEYS"),
            yandex_locator_url=os.environ.get(
                "YANDEX_LOCATOR_URL", "https://locator.api.maps.yandex.ru/v1/locate"),
            traccar_osmand_url=os.environ.get("TRACCAR_OSMAND_URL", "").rstrip("/"),
            traccar_api_url=os.environ.get("TRACCAR_API_URL", "").rstrip("/"),
            traccar_token=os.environ.get("TRACCAR_TOKEN", ""),
            traccar_group_id=int(gid) if gid else None,
            traccar_web_url=os.environ.get("TRACCAR_WEB_URL", "").rstrip("/"),
            telegram_token=os.environ.get("TELEGRAM_TOKEN", ""),
            telegram_chat_ids=_list("TELEGRAM_CHAT_IDS"),
            extra_allowed_domains=_list("EXTRA_ALLOWED_DOMAINS"),
            trusted_proxy_header=os.environ.get("CLIENT_IP_HEADER", "X-Real-IP").lower(),
            dev_login=_bool("DEV_LOGIN"),
        )

    def check(self) -> list[str]:
        problems = []
        for name in ("database_url", "public_url", "session_secret", "enroll_secret"):
            if not getattr(self, name):
                problems.append(name.upper())
        if not self.dev_login and not (self.oidc_issuer and self.oidc_client_id):
            problems.append("OIDC_ISSUER/OIDC_CLIENT_ID")
        return problems
