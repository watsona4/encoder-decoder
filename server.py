#!/usr/bin/env python3
import base64
import json
import logging
import mimetypes
import os
import pathlib
import secrets
import shutil
import subprocess
import time
import uuid
from urllib.parse import urlencode, urlparse
import re

import redis
import requests
from flask import Flask, Response, jsonify, redirect, request, send_from_directory

# ── Config ────────────────────────────────────────────────────────────────────
PORT = int(os.getenv("PORT", "8000"))

# Redis via individual env vars (no local container)
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_USERNAME = os.getenv("REDIS_USERNAME") or None
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None
REDIS_SSL = os.getenv("REDIS_SSL", "false").lower() in ("1", "true", "yes")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", f"http://localhost:{PORT}/oauth/callback")

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_DRIVE_UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise SystemExit("Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")

if not REDIS_HOST:
    raise SystemExit("Set REDIS_HOST (and optionally REDIS_PORT/DB/USERNAME/PASSWORD/SSL) to use your existing Redis.")

# Build Redis client
r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    username=REDIS_USERNAME,
    password=REDIS_PASSWORD,
    ssl=REDIS_SSL,
    decode_responses=False,  # store tokens as bytes
    socket_timeout=5,
    socket_connect_timeout=5,
)

# Test connection early (fail fast)
try:
    r.ping()
except Exception as e:
    raise SystemExit(f"Failed to connect to Redis at {REDIS_HOST}:{REDIS_PORT} db={REDIS_DB} ssl={REDIS_SSL}: {e}")

app = Flask(__name__, static_folder=".", static_url_path="")

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("b64drive")

DRIVE_FOLDER_ID = os.getenv("DRIVE_FOLDER_ID")  # rclone folder id; required if you want rclone subdir

# ── Token helpers ─────────────────────────────────────────────────────────────
def get_session_id():
    sid = request.cookies.get("sid")
    if not sid:
        sid = secrets.token_urlsafe(32)
    return sid


def redis_key(sid, suffix):
    return f"b64drive:{sid}:{suffix}"


def save_tokens(sid, tok):
    exp = int(time.time()) + int(tok.get("expires_in", 3600)) - 60
    data = {
        "access_token": tok["access_token"],
        "refresh_token": tok.get("refresh_token"),
        "expires_at": exp,
        "scope": tok.get("scope", DRIVE_SCOPE),
        "token_type": tok.get("token_type", "Bearer"),
    }
    r.setex(redis_key(sid, "tokens"), 60 * 60 * 24 * 30, json.dumps(data).encode())


def load_tokens(sid):
    raw = r.get(redis_key(sid, "tokens"))
    return json.loads(raw) if raw else None


def refresh_access_token(sid, tok):
    if not tok or not tok.get("refresh_token"):
        return None
    p = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": tok["refresh_token"],
    }
    resp = requests.post(GOOGLE_OAUTH_TOKEN_URL, data=p, timeout=20)
    if resp.status_code != 200:
        return None
    tr = resp.json()
    if "refresh_token" not in tr:
        tr["refresh_token"] = tok["refresh_token"]
    save_tokens(sid, tr)
    return load_tokens(sid)


def get_valid_access_token(sid):
    tok = load_tokens(sid)
    if not tok:
        return None
    if int(time.time()) >= tok.get("expires_at", 0):
        tok = refresh_access_token(sid, tok)
        if not tok:
            return None
    return tok["access_token"]


AUTOLINK_RE = re.compile(r"<([^>\s]+)>")


def _has_local_reference(markdown_text):
    def is_forbidden_target(target):
        target = target.strip()
        if not target:
            return False
        if target.startswith("#"):
            return False
        parsed = urlparse(target)
        if parsed.scheme:
            if parsed.scheme.lower() in ("http", "https", "mailto", "data"):
                return False
            return True
        if target.startswith(("/", "./", "../", "~/", "\\")):
            return True
        if re.match(r"^[a-zA-Z]:\\", target):
            return True
        if os.path.isabs(target):
            return True
        return True

    for match in re.finditer(r"!\[[^\]]*\]\(([^)]+)\)", markdown_text):
        if is_forbidden_target(match.group(1)):
            return True
    for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", markdown_text):
        if is_forbidden_target(match.group(1)):
            return True
    for match in AUTOLINK_RE.finditer(markdown_text):
        if is_forbidden_target(match.group(1)):
            return True
    include_patterns = (
        re.compile(r"^\s*!include\s+", re.IGNORECASE),
        re.compile(r"^\s*include::", re.IGNORECASE),
        re.compile(r"^\s*%\s*include\b", re.IGNORECASE),
        re.compile(r"^\s*\\(include|input)\b"),
    )
    for line in markdown_text.splitlines():
        for pat in include_patterns:
            if pat.search(line):
                return True
    return False


def make_sid_response(payload):
    sid = get_session_id()
    resp = jsonify(payload)
    resp.set_cookie("sid", sid, max_age=60 * 60 * 24 * 30, httponly=True, samesite="Lax", path="/")
    return resp, sid


# ── UI ────────────────────────────────────────────────────────────────────────
@app.get("/")
def index():
    return send_from_directory(".", "index.html")


# ── Auth & status ─────────────────────────────────────────────────────────────
@app.get("/api/status")
def api_status():
    sid = get_session_id()
    tok = load_tokens(sid)
    authed = bool(tok and int(time.time()) < tok.get("expires_at", 0))
    resp, sid = make_sid_response({"ok": True, "authed": authed})
    return resp


@app.get("/oauth/start")
def oauth_start():
    sid = get_session_id()
    state = secrets.token_urlsafe(24)
    r.setex(redis_key(sid, "state"), 600, state.encode())
    q = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": DRIVE_SCOPE,
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
        "state": state,
    }
    url = f"{GOOGLE_OAUTH_AUTH_URL}?{urlencode(q)}"
    resp = redirect(url, 302)
    resp.set_cookie("sid", sid, max_age=60 * 60 * 24 * 30, httponly=True, samesite="Lax", path="/")
    return resp


@app.get("/oauth/callback")
def oauth_callback():
    sid = get_session_id()
    code = request.args.get("code")
    st = request.args.get("state")
    exp = r.get(redis_key(sid, "state"))
    if not code or not exp or exp.decode() != st:
        return "Invalid state", 400
    d = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    resp = requests.post(GOOGLE_OAUTH_TOKEN_URL, data=d, timeout=20)
    if resp.status_code != 200:
        return f"Token exchange failed: {resp.text}", 400
    save_tokens(sid, resp.json())
    return "<p>Authorized. You can close this tab.</p><script>setTimeout(()=>window.close(),700)</script>"


# ── Chunked upload endpoints ──────────────────────────────────────────────────
TMP_ROOT = pathlib.Path(os.getenv("B64_TMP_DIR", "/tmp/b64drive"))
TMP_ROOT.mkdir(parents=True, exist_ok=True)


def _sid():
    return request.cookies.get("sid") or ""


def _udir(sid, uid):
    d = TMP_ROOT / sid / uid
    d.mkdir(parents=True, exist_ok=True)
    return d


def _b64p(sid, uid):
    return _udir(sid, uid) / "payload.b64"


def _meta(sid, uid):
    return _udir(sid, uid) / "meta.json"


@app.post("/api/chunk/start")
def chunk_start():
    sid = get_session_id()
    uid = uuid.uuid4().hex
    dirp = _udir(sid, uid)
    try:
        _meta(sid, uid).write_bytes(json.dumps({"seq": -1}).encode())
        _b64p(sid, uid).write_bytes(b"")
    except Exception as e:
        logger.exception("chunk_start failed: sid=%s uid=%s dir=%s", sid, uid, dirp)
        return jsonify({"ok": False, "error": f"init_failed: {e}"}), 500
    logger.info("chunk_start ok: sid=%s uid=%s dir=%s", sid, uid, dirp)
    resp, _ = make_sid_response({"ok": True, "upload_id": uid})
    resp.set_cookie("sid", sid, max_age=60 * 60 * 24 * 30, httponly=True, samesite="Lax", path="/")
    return resp


@app.post("/api/chunk/append")
def chunk_append():
    sid = _sid()
    b = request.get_json(force=True)
    uid = b.get("upload_id")
    seq = int(b.get("seq", -1))
    data = b.get("data", "")
    logger.debug(
        "chunk_append in: sid=%s uid=%s seq=%s data_len=%s", sid, uid, seq, len(data) if isinstance(data, str) else -1
    )
    if not uid or seq < 0 or not data:
        logger.warning("chunk_append bad_args: sid=%s uid=%s seq=%s", sid, uid, seq)
        return jsonify({"ok": False, "error": "bad_args"}), 400
    m = _meta(sid, uid)
    if not m.exists():
        logger.warning("chunk_append unknown_upload: sid=%s uid=%s meta=%s", sid, uid, m)
        return jsonify({"ok": False, "error": "unknown_upload"}), 404
    meta = json.loads(m.read_bytes() or b"{}")
    exp = meta.get("seq", -1) + 1
    if seq != exp:
        logger.warning("chunk_append out_of_order: sid=%s uid=%s expected=%s got=%s", sid, uid, exp, seq)
        return jsonify({"ok": False, "error": f"out_of_order expected {exp} got {seq}"}), 409
    b64p = _b64p(sid, uid)
    try:
        with open(b64p, "ab") as f:
            f.write(data.encode())
            f.write(b"\n")
        meta["seq"] = seq
        m.write_bytes(json.dumps(meta).encode())
    except Exception as e:
        logger.exception("chunk_append write_failed: sid=%s uid=%s path=%s", sid, uid, b64p)
        return jsonify({"ok": False, "error": f"write_failed: {e}"}), 500
    logger.debug(
        "chunk_append ok: sid=%s uid=%s seq=%s path=%s size_now=%s",
        sid,
        uid,
        seq,
        b64p,
        b64p.stat().st_size if b64p.exists() else -1,
    )
    return jsonify({"ok": True, "next": seq + 1})


def _iter_b64_file_decode(p: pathlib.Path):
    carry = ""
    with open(p, "rt", encoding="utf-8", errors="ignore") as f:
        for slab in f:
            s = carry + slab.strip().replace(" ", "")
            use = (len(s) // 4) * 4
            if use:
                yield base64.b64decode(s[:use])
                carry = s[use:]
            else:
                carry = s
    if carry:
        pad = carry + "==="[: (4 - len(carry) % 4) % 4]
        yield base64.b64decode(pad)


@app.post("/api/chunk/finish/download")
def chunk_finish_download():
    sid = _sid()
    b = request.get_json(force=True)
    uid = b.get("upload_id")
    name = b.get("name", "file.bin")
    mime = b.get("mime", "application/octet-stream")
    p = _b64p(sid, uid) if uid else None
    logger.info(
        "finish_download in: sid=%s uid=%s name=%s mime=%s path=%s exists=%s",
        sid,
        uid,
        name,
        mime,
        p,
        p.exists() if p else False,
    )
    if not uid:
        return jsonify({"ok": False, "error": "bad_args"}), 400
    if not p.exists():
        logger.warning("finish_download unknown_upload: sid=%s uid=%s path=%s", sid, uid, p)
        return jsonify({"ok": False, "error": "unknown_upload"}), 404
    h = {"Content-Type": mime, "Content-Disposition": f'attachment; filename="{name}"'}

    def g():
        try:
            for c in _iter_b64_file_decode(p):
                yield c
            logger.info("finish_download decode_complete: sid=%s uid=%s", sid, uid)
        finally:
            try:
                shutil.rmtree(_udir(sid, uid), ignore_errors=True)
                logger.info("finish_download cleanup_ok: sid=%s uid=%s dir=%s", sid, uid, _udir(sid, uid))
            except Exception:
                logger.exception("finish_download cleanup_failed: sid=%s uid=%s", sid, uid)

    return Response(g(), headers=h)


@app.post("/api/chunk/finish/drive")
def chunk_finish_drive():
    sid = _sid()
    tok = get_valid_access_token(sid)
    if not tok:
        return jsonify({"ok": False, "error": "not_authed"}), 401
    b = request.get_json(force=True)
    uid = b.get("upload_id")
    name = b.get("name", "file.bin")
    mime = b.get("mime", "application/octet-stream")
    p = _b64p(sid, uid) if uid else None
    logger.info(
        "finish_drive in: sid=%s uid=%s name=%s mime=%s path=%s exists=%s",
        sid,
        uid,
        name,
        mime,
        p,
        p.exists() if p else False,
    )
    if not uid:
        return jsonify({"ok": False, "error": "bad_args"}), 400
    if not p.exists():
        logger.warning("finish_drive unknown_upload: sid=%s uid=%s path=%s", sid, uid, p)
        return jsonify({"ok": False, "error": "unknown_upload"}), 404
    out = _udir(sid, uid) / "payload.bin"
    try:
        with open(out, "wb") as o:
            for c in _iter_b64_file_decode(p):
                o.write(c)
        logger.info("finish_drive decode_done: sid=%s uid=%s out=%s size=%s", sid, uid, out, out.stat().st_size)
    except Exception:
        logger.exception("finish_drive decode_failed: sid=%s uid=%s", sid, uid)
        return jsonify({"ok": False, "error": "decode_failed"}), 500
    ok, payload = _drive_upload(sid, tok, out, name, mime)
    try:
        shutil.rmtree(_udir(sid, uid), ignore_errors=True)
        logger.info("finish_drive cleanup_ok: sid=%s uid=%s", sid, uid)
    except Exception:
        logger.exception("finish_drive cleanup_failed: sid=%s uid=%s", sid, uid)
    if not ok:
        return jsonify(payload), 502
    return jsonify({"ok": True, "id": payload.get("id"), "name": payload.get("name")})


def _drive_upload(sid, tok, file_path, name, mime):
    meta = {"name": name}
    if DRIVE_FOLDER_ID:
        meta["parents"] = [DRIVE_FOLDER_ID]
    boundary = "bnd" + uuid.uuid4().hex

    def multipart():
        yield f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n".encode()
        yield json.dumps(meta).encode()
        yield f"\r\n--{boundary}\r\nContent-Type: {mime}\r\n\r\n".encode()
        with open(file_path, "rb") as f:
            while True:
                buf = f.read(1024 * 1024)
                if not buf:
                    break
                yield buf
        yield f"\r\n--{boundary}--\r\n".encode()

    headers = {
        "Authorization": f"Bearer {tok}",
        "Content-Type": f"multipart/related; boundary={boundary}",
    }
    resp = requests.post(GOOGLE_DRIVE_UPLOAD_URL, headers=headers, data=multipart(), timeout=600)
    if resp.status_code not in (200, 201):
        new = refresh_access_token(sid, load_tokens(sid) or {})
        if new:
            headers["Authorization"] = f"Bearer {new['access_token']}"
            resp = requests.post(GOOGLE_DRIVE_UPLOAD_URL, headers=headers, data=multipart(), timeout=600)
    try:
        info = resp.json()
    except Exception:
        info = {}
    if resp.status_code not in (200, 201):
        return False, {"ok": False, "error": f"drive_error {resp.status_code}: {resp.text[:500]}"}
    return True, info


@app.post("/api/markdown/convert")
def markdown_convert():
    sid = _sid()
    tok = get_valid_access_token(sid)
    if not tok:
        return jsonify({"ok": False, "error": "not_authed"}), 401
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "error": "invalid_json"}), 400
    markdown_text = body.get("markdown") if isinstance(body, dict) else None
    filename = (body.get("filename") or "").strip() if isinstance(body, dict) else ""
    if not isinstance(markdown_text, str) or not markdown_text.strip():
        return jsonify({"ok": False, "error": "missing_markdown"}), 400
    if _has_local_reference(markdown_text):
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "local_references_forbidden",
                    "message": "Markdown references local files or include directives, which is not allowed.",
                }
            ),
            400,
        )
    filename = os.path.basename(filename)
    if not filename:
        filename = "document.docx"
    if not pathlib.Path(filename).suffix:
        filename = f"{filename}.docx" if not filename.lower().endswith(".docx") else filename
    suffix = pathlib.Path(filename).suffix or ".docx"
    uid = uuid.uuid4().hex
    workdir = _udir(sid, uid)
    input_md = workdir / "input.md"
    output_file = workdir / f"output{suffix}"
    try:
        input_md.write_text(markdown_text, encoding="utf-8")
    except Exception as e:
        logger.exception("markdown_convert write_failed: sid=%s uid=%s", sid, uid)
        return jsonify({"ok": False, "error": f"write_failed: {e}"}), 500
    try:
        subprocess.run(["pandoc", str(input_md), "-o", str(output_file)], check=True, timeout=300)
    except FileNotFoundError:
        logger.exception("markdown_convert pandoc_missing: sid=%s uid=%s", sid, uid)
        return jsonify({"ok": False, "error": "pandoc_not_found"}), 500
    except subprocess.CalledProcessError as e:
        logger.exception("markdown_convert pandoc_failed: sid=%s uid=%s", sid, uid)
        return jsonify({"ok": False, "error": f"pandoc_failed: {e.returncode}"}), 500
    except subprocess.TimeoutExpired:
        logger.exception("markdown_convert pandoc_timeout: sid=%s uid=%s", sid, uid)
        return jsonify({"ok": False, "error": "pandoc_timeout"}), 504
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    if not output_file.exists() or output_file.stat().st_size == 0:
        return jsonify({"ok": False, "error": "conversion_failed"}), 500
    ok, info = _drive_upload(sid, tok, output_file, filename, mime)
    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        logger.exception("markdown_convert cleanup_failed: sid=%s uid=%s", sid, uid)
    if not ok:
        return jsonify(info), 502
    return jsonify({"ok": True, "id": info.get("id"), "name": info.get("name", filename)})


# ── Debug endpoint ────────────────────────────────────────────────────────────
@app.get("/api/chunk/debug")
def chunk_debug():
    sid = _sid()
    base = TMP_ROOT / sid
    info = []
    if base.exists():
        for uid_dir in base.iterdir():
            if uid_dir.is_dir():
                b64 = _b64p(sid, uid_dir.name)
                info.append({
                    "uid": uid_dir.name,
                    "meta_exists": (_meta(sid, uid_dir.name)).exists(),
                    "b64_exists": b64.exists(),
                    "b64_size": b64.stat().st_size if b64.exists() else 0,
                })
    logger.info("chunk_debug: sid=%s entries=%s", sid, len(info))
    return jsonify({"sid": sid, "root": str(base), "uploads": info})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
