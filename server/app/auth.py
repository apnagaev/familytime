"""Вход через Keycloak (OpenID Connect, code + PKCE) и сессия в подписанной cookie."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
import logging
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer

log = logging.getLogger("familytime.auth")

SESSION_COOKIE = "ft_session"
FLOW_COOKIE = "ft_flow"
SESSION_MAX_AGE = 12 * 3600


@dataclass
class User:
    username: str
    name: str
    parent: bool
    csrf: str


class OIDC:
    def __init__(self, cfg, http: httpx.AsyncClient):
        self.cfg = cfg
        self.http = http
        self._meta: dict | None = None
        self._jwks: jwt.PyJWKSet | None = None
        self._jwks_at = 0.0

    async def meta(self) -> dict:
        if self._meta is None:
            try:
                r = await self.http.get(self.cfg.oidc_issuer + "/.well-known/openid-configuration",
                                        timeout=10)
                r.raise_for_status()
            except httpx.HTTPError as e:
                raise HTTPException(503, f"Keycloak недоступен: {e}") from None
            self._meta = r.json()
        return self._meta

    async def _keys(self, force: bool = False) -> jwt.PyJWKSet:
        if force or self._jwks is None or time.time() - self._jwks_at > 3600:
            m = await self.meta()
            try:
                r = await self.http.get(m["jwks_uri"], timeout=10)
                r.raise_for_status()
            except httpx.HTTPError as e:
                raise HTTPException(503, f"Keycloak недоступен: {e}") from None
            self._jwks = jwt.PyJWKSet.from_dict(r.json())
            self._jwks_at = time.time()
        return self._jwks

    async def verify(self, token: str, audience: str | None) -> dict:
        kid = jwt.get_unverified_header(token).get("kid")
        for force in (False, True):
            keys = await self._keys(force)
            key = next((k for k in keys.keys if k.key_id == kid), None)
            if key:
                return jwt.decode(
                    token, key.key, algorithms=["RS256", "RS384", "RS512", "ES256", "PS256"],
                    audience=audience, issuer=self.cfg.oidc_issuer,
                    options={"verify_aud": audience is not None}, leeway=60)
        raise HTTPException(401, "unknown signing key")


def _serializer(cfg, salt: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(cfg.session_secret, salt=salt)


def _secure(cfg) -> bool:
    return cfg.public_url.startswith("https://")


def make_session(cfg, response, username: str, name: str, parent: bool) -> None:
    data = {"u": username, "n": name, "p": parent, "c": secrets.token_urlsafe(16)}
    response.set_cookie(SESSION_COOKIE, _serializer(cfg, "session").dumps(data),
                        max_age=SESSION_MAX_AGE, httponly=True, secure=_secure(cfg), samesite="lax")


def current_user(request: Request) -> User | None:
    cfg = request.app.state.cfg
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    try:
        d = _serializer(cfg, "session").loads(raw, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return None
    return User(d["u"], d["n"], bool(d["p"]), d["c"])


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def check_csrf(request: Request, user: User, token: str) -> None:
    """Главная защита — токен формы. Origin проверяется дополнительно и только по имени сайта:
    браузер шлёт `Origin: null` при Referrer-Policy: no-referrer, а схема и порт за прокси
    могут отличаться от PUBLIC_URL."""
    if not token or not hmac.compare_digest(token, user.csrf):
        log.warning("CSRF: неверный токен формы, %s", request.url.path)
        raise HTTPException(403, "Форма устарела: обновите страницу и повторите")
    cfg = request.app.state.cfg
    origin = (request.headers.get("origin") or "").strip()
    if not origin or origin == "null" or not cfg.public_url:
        return
    allowed = {_host(cfg.public_url), (request.headers.get("host") or "").split(":")[0].lower()}
    if _host(origin) not in allowed:
        log.warning("CSRF: чужой Origin %r (PUBLIC_URL %s), %s", origin, cfg.public_url,
                    request.url.path)
        raise HTTPException(403, "Запрос пришёл с другого сайта")


def _roles(claims: dict, client_id: str) -> set[str]:
    roles = set(claims.get("realm_access", {}).get("roles", []))
    for client, v in (claims.get("resource_access") or {}).items():
        for r in v.get("roles", []):
            roles.add(r)
            roles.add(f"{client}:{r}")
    for g in claims.get("groups", []) or []:
        roles.add(str(g).strip("/").split("/")[-1])
    return roles


async def login_redirect(request: Request, next_url: str = "/") -> RedirectResponse:
    cfg = request.app.state.cfg
    oidc: OIDC = request.app.state.oidc
    m = await oidc.meta()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    params = {
        "response_type": "code",
        "client_id": cfg.oidc_client_id,
        "redirect_uri": cfg.public_url + "/oidc/callback",
        "scope": "openid profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge.decode(),
        "code_challenge_method": "S256",
    }
    resp = RedirectResponse(m["authorization_endpoint"] + "?" + urlencode(params), 302)
    flow = {"s": state, "n": nonce, "v": verifier, "next": next_url if next_url.startswith("/") else "/"}
    resp.set_cookie(FLOW_COOKIE, _serializer(cfg, "flow").dumps(flow), max_age=600,
                    httponly=True, secure=_secure(cfg), samesite="lax")
    return resp


async def callback(request: Request, code: str, state: str) -> RedirectResponse:
    cfg = request.app.state.cfg
    oidc: OIDC = request.app.state.oidc
    try:
        flow = _serializer(cfg, "flow").loads(request.cookies.get(FLOW_COOKIE, ""), max_age=600)
    except BadSignature:
        raise HTTPException(400, "Сеанс входа устарел, откройте портал заново")
    if not hmac.compare_digest(flow["s"], state):
        raise HTTPException(400, "state")
    m = await oidc.meta()
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cfg.public_url + "/oidc/callback",
        "client_id": cfg.oidc_client_id,
        "code_verifier": flow["v"],
    }
    if cfg.oidc_client_secret:
        data["client_secret"] = cfg.oidc_client_secret
    try:
        r = await oidc.http.post(m["token_endpoint"], data=data, timeout=15)
    except httpx.HTTPError as e:
        raise HTTPException(503, f"Keycloak недоступен: {e}") from None
    if r.status_code != 200:
        raise HTTPException(401, "Keycloak отказал во входе")
    tok = r.json()
    idc = await oidc.verify(tok["id_token"], cfg.oidc_client_id)
    if idc.get("nonce") != flow["n"]:
        raise HTTPException(401, "nonce")
    acc = await oidc.verify(tok["access_token"], None)
    claims = {**acc, **idc}
    username = str(claims.get(cfg.oidc_username_claim) or claims.get("preferred_username") or "")
    username = username.lower().split("@")[0].split("\\")[-1]
    if not username:
        raise HTTPException(401, "в токене нет имени пользователя")
    name = claims.get("name") or username
    roles = _roles(acc, cfg.oidc_client_id) | _roles(idc, cfg.oidc_client_id)
    parent = cfg.oidc_parent_role in roles
    resp = RedirectResponse(flow.get("next", "/"), 302)
    resp.delete_cookie(FLOW_COOKIE)
    make_session(cfg, resp, username, name, parent)
    return resp


async def logout_redirect(request: Request) -> RedirectResponse:
    cfg = request.app.state.cfg
    target = cfg.public_url + "/"
    if not cfg.dev_login:
        try:
            m = await request.app.state.oidc.meta()
            if m.get("end_session_endpoint"):
                target = m["end_session_endpoint"] + "?" + urlencode(
                    {"client_id": cfg.oidc_client_id, "post_logout_redirect_uri": cfg.public_url + "/"})
        except (httpx.HTTPError, HTTPException):
            pass
    resp = RedirectResponse(target, 302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp
