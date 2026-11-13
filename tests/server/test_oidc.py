"""Вход через Keycloak с поддельным сервером: подпись, nonce, роль родителя, имя пользователя."""
import asyncio
import json
import os
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.config import Config
from app.main import create_app

DSN = os.environ["TEST_DATABASE_URL"]
ISS = "https://sso.example.com/realms/home"


def make_app(roles, username="parent"):
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
                                   "preferred_username": username, "name": "Папа"}),
                "access_token": token({"aud": "account", "realm_access": {"roles": roles}})})
        return httpx.Response(404)

    cfg = Config(database_url=DSN, public_url="https://kids.example.com", session_secret="s" * 32,
                 enroll_secret="e", oidc_issuer=ISS, oidc_client_id="familytime",
                 oidc_client_secret="sec")
    return create_app(cfg), handler, state


def login_flow(roles, username="parent"):
    app, handler, state = make_app(roles, username)
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
        r = c.get(f"/oidc/callback?code=CODE&state={q['state'][0]}", follow_redirects=False)
        return c, r, c.get("/dashboard")


def test_parent_login():
    c, r, dash = login_flow(["default-roles-home", "familytime-parent"])
    assert r.status_code == 302 and r.headers["location"] == "/dashboard"
    assert dash.status_code == 200 and "Папа" in dash.text


def test_non_parent_cannot_open_dashboard():
    c, r, dash = login_flow(["default-roles-home"], username="ivan@example.local")
    assert dash.status_code == 403
