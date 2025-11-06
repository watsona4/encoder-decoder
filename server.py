#!/usr/bin/env python3
import base64
import json
import os
import secrets
import time
from urllib.parse import urlencode

import redis
import requests
from flask import Flask, jsonify, redirect, request, send_from_directory

PORT = int(os.getenv("PORT", "8000"))
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_USERNAME = os.getenv("REDIS_USERNAME")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", f"http://localhost:{PORT}/oauth/callback")
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_DRIVE_UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise SystemExit("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in the environment.")

if not REDIS_HOST:
    raise SystemExit("Set REDIS_HOST in the environment.")

r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    username=REDIS_USERNAME or None,
    password=REDIS_PASSWORD or None,
    db=REDIS_DB,
)
app = Flask(__name__, static_folder=".", static_url_path="")


# ── Helpers ───────────────────────────────────────────────────────────────────
def get_session_id():
    sid = request.cookies.get("sid")
    if not sid:
        sid = secrets.token_urlsafe(32)
    return sid


def redis_key(sid, suffix):
    return f"b64drive:{sid}:{suffix}"


def save_tokens(sid, token_resp):
    now = int(time.time())
    expiry = now + int(token_resp.get("expires_in", 3600)) - 60
    data = {
        "access_token": token_resp["access_token"],
        "refresh_token": token_resp.get("refresh_token"),
        "expires_at": expiry,
        "scope": token_resp.get("scope", DRIVE_SCOPE),
        "token_type": token_resp.get("token_type", "Bearer"),
    }
    r.setex(redis_key(sid, "tokens"), 60 * 60 * 24 * 30, json.dumps(data))


def load_tokens(sid):
    raw = r.get(redis_key(sid, "tokens"))
    return json.loads(raw) if raw else None


def refresh_access_token(sid, tokens):
    if not tokens or not tokens.get("refresh_token"):
        return None
    payload = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"],
    }
    resp = requests.post(GOOGLE_OAUTH_TOKEN_URL, data=payload, timeout=20)
    if resp.status_code != 200:
        return None
    tr = resp.json()
    if "refresh_token" not in tr:
        tr["refresh_token"] = tokens.get("refresh_token")
    save_tokens(sid, tr)
    return load_tokens(sid)


def get_valid_access_token(sid):
    tokens = load_tokens(sid)
    if not tokens:
        return None
    if int(time.time()) >= int(tokens.get("expires_at", 0)):
        tokens = refresh_access_token(sid, tokens)
        if not tokens:
            return None
    return tokens["access_token"]


def make_sid_response(payload):
    sid = get_session_id()
    resp = jsonify(payload)
    resp.set_cookie("sid", sid, max_age=60 * 60 * 24 * 30, httponly=True, samesite="Lax")
    return resp, sid


# ── UI route ──────────────────────────────────────────────────────────────────
@app.get("/")
def index():
    # Serve local index.html from the container
    return send_from_directory(".", "index.html")


# ── API routes ────────────────────────────────────────────────────────────────
@app.get("/api/status")
def api_status():
    sid = get_session_id()
    tokens = load_tokens(sid)
    authed = bool(tokens and int(time.time()) < tokens.get("expires_at", 0))
    resp, sid = make_sid_response({"ok": True, "authed": authed})
    return resp


@app.get("/oauth/start")
def oauth_start():
    sid = get_session_id()
    state = secrets.token_urlsafe(24)
    r.setex(redis_key(sid, "state"), 600, state)
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": DRIVE_SCOPE,
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
        "state": state,
    }
    url = f"{GOOGLE_OAUTH_AUTH_URL}?{urlencode(params)}"
    resp = redirect(url, code=302)
    resp.set_cookie("sid", sid, max_age=60 * 60 * 24 * 30, httponly=True, samesite="Lax")
    return resp


@app.get("/oauth/callback")
def oauth_callback():
    sid = get_session_id()
    code = request.args.get("code")
    state = request.args.get("state")
    expected_state = r.get(redis_key(sid, "state"))
    if not code or not expected_state or expected_state.decode() != state:
        return "Invalid OAuth state.", 400
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    resp = requests.post(GOOGLE_OAUTH_TOKEN_URL, data=data, timeout=20)
    if resp.status_code != 200:
        return f"Token exchange failed: {resp.text}", 400
    save_tokens(sid, resp.json())
    return """<html><body><p>Authorized. You can close this tab.</p><script>setTimeout(()=>window.close(),700);</script></body></html>"""


@app.post("/api/drive/upload")
def drive_upload():
    sid = get_session_id()
    token = get_valid_access_token(sid)
    if not token:
        return jsonify({"ok": False, "error": "not_authed"}), 401

    try:
        payload = request.get_json(force=True)
        name = payload.get("name", "file.bin")
        mime = payload.get("mime", "application/octet-stream")
        b64 = payload.get("base64", "")
        if "," in b64 and b64.strip().startswith("data:"):
            b64 = b64.split("base64,", 1)[-1]
        b64 = "".join(b64.split())
        raw = base64.b64decode(b64, validate=False)
    except Exception as e:
        return jsonify({"ok": False, "error": f"bad_input: {e}"}), 400

    boundary = "bnd" + secrets.token_hex(8)
    meta = {"name": name}
    parts = []

    def enc(s):
        return s.encode("utf-8")

    parts.append(enc(f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"))
    parts.append(enc(json.dumps(meta)))
    parts.append(enc(f"\r\n--{boundary}\r\nContent-Type: {mime}\r\n\r\n"))
    parts.append(raw)
    parts.append(enc(f"\r\n--{boundary}--\r\n"))
    body = b"".join(parts)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": f"multipart/related; boundary={boundary}",
    }
    resp = requests.post(GOOGLE_DRIVE_UPLOAD_URL, headers=headers, data=body, timeout=120)

    if resp.status_code not in (200, 201):
        # quick refresh; one retry
        tokens = refresh_access_token(sid, load_tokens(sid) or {})
        if tokens:
            headers["Authorization"] = f"Bearer {tokens['access_token']}"
            resp = requests.post(GOOGLE_DRIVE_UPLOAD_URL, headers=headers, data=body, timeout=120)

    if resp.status_code not in (200, 201):
        return jsonify({"ok": False, "error": f"drive_error {resp.status_code}: {resp.text[:500]}"}), 502

    info = resp.json()
    return jsonify({"ok": True, "id": info.get("id"), "name": info.get("name")})


def app_factory():
    return app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
