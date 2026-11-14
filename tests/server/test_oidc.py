"""Вход через Keycloak с поддельным сервером: подпись, nonce, роль родителя, имя пользователя."""
import asyncio
import json
import re
from contextlib import contextmanager
import os
import time
from urllib.parse import parse_qs, urlsplit

import asyncpg
import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.config import Config
from app.main import create_app

DSN = os.environ["TEST_DATABASE_URL"]
ISS = "https://sso.example.com/realms/home"


def make_app(roles, username="parent", email=None, verified=True, realm_roles=()):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="k1", use="sig", alg="RS256")
    state = {}

    def token(claims):
        now = int(time.time())
        return jwt.encode({"iss": ISS, "iat": now, "exp": now + 300, **claims}, key,
                          algorithm="RS256", headers={"kid": "k1"})

    def handler(req: httpx.Request):
        if req.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={
                "authorization_endpoint": ISS + "/protocol/openid-connect/auth",
                "token_endpoint": ISS + "/protocol/openid-connect/token",
                "jwks_uri": ISS + "/protocol/openid-connect/certs",
                "end_session_endpoint": ISS + "/protocol/openid-connect/logout"})
        if req.url.path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [jwk]})
        if req.url.path.endswith("/token"):
            form = parse_qs(req.content.decode())
            assert form["code"] == ["CODE"] and form["code_verifier"][0]
            assert form["client_secret"] == ["sec"]
            return httpx.Response(200, json={
                "id_token": token({"aud": "familytime", "nonce": state["nonce"],
                                   "preferred_username": username, "name": "Папа",
                                   **({"email": email, "email_verified": verified} if email else {})}),
                "access_token": token({"aud": "account",
                                       "realm_access": {"roles": list(realm_roles)},
                                       "resource_access": {"familytime": {"roles": roles},
                                                           "other": {"roles": ["admin"]}}})})
        return httpx.Response(404)

    cfg = Config(database_url=DSN, public_url="https://kids.example.com", session_secret="s" * 32,
                 enroll_secret="e", oidc_issuer=ISS, oidc_client_id="familytime",
                 oidc_client_secret="sec")
    return create_app(cfg), handler, state


@contextmanager
def session(roles, username="parent", **kw):
    """Вход через поддельный Keycloak; внутри блока — клиент с действующей сессией."""
    app, handler, state = make_app(roles, username, **kw)
    with TestClient(app, base_url="https://kids.example.com") as c:
        mock = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        app.state.http = mock
        app.state.oidc.http = mock
        r = c.get("/login?next=/dashboard", follow_redirects=False)
        q = parse_qs(urlsplit(r.headers["location"]).query)
        assert q["code_challenge_method"] == ["S256"]
        state["nonce"] = q["nonce"][0]
        bad = c.get("/oidc/callback?code=CODE&state=wrong", follow_redirects=False)
        assert bad.status_code == 400
        c.login = c.get(f"/oidc/callback?code=CODE&state={q['state'][0]}", follow_redirects=False)
        yield c


def test_parent_login():
    with session(["parent"]) as c:
        assert c.login.status_code == 302 and c.login.headers["location"] == "/dashboard"
        dash = c.get("/dashboard")
        assert dash.status_code == 200 and "Папа" in dash.text
        assert c.get("/settings").status_code == 403           # не админ


def test_admin_login():
    with session(["admin"]) as c:
        assert c.get("/dashboard").status_code == 200 and c.get("/settings").status_code == 200


def test_realm_and_foreign_client_roles_do_not_count():
    # роль realm с тем же именем и роль admin другого клиента прав не дают
    with session([], realm_roles=["parent", "admin", "familytime-parent"]) as c:
        assert c.get("/dashboard").status_code == 403
        assert c.get("/settings").status_code == 403


def test_child_login_by_verified_email():
    async def prep():
        conn = await asyncpg.connect(DSN)
        await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        await conn.close()
    asyncio.run(prep())
    with session(["admin"]) as c:                              # админ заводит ребёнка с почтой
        t = re.search(r'name="csrf" value="([^"]+)"', c.get("/dashboard").text).group(1)
        c.post("/children", data={"username": "vanya-home", "display_name": "Ваня", "csrf": t})
        r = c.post("/child/vanya-home/settings", data={
            "display_name": "Ваня", "enabled": "1", "email": "Vanya@Example.com",
            "aliases": "ваня, ivan_home", "csrf": t})
        assert "Сохранено" in r.text and "ivan_home" in r.text
        assert "неверно" in c.post("/child/vanya-home/settings", data={
            "display_name": "Ваня", "email": "не почта", "csrf": t}).text
    # ребёнок входит учётной записью Keycloak с этой почтой (логин другой)
    with session([], username="vanya@example.com", email="vanya@example.com") as c:
        assert "Привет, Ваня" in c.get("/me").text
    # неподтверждённая почта не подходит
    with session([], username="someone", email="vanya@example.com", verified=False) as c:
        assert "ограничений нет" in c.get("/me").text
    # логин с @ не обрезается до имени ребёнка
    with session([], username="vanya-home@evil.example") as c:
        assert "ограничений нет" in c.get("/me").text
