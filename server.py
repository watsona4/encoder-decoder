#!/usr/bin/env python3
import base64
import json
import logging
import mimetypes
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import time
import uuid
from urllib.parse import urlencode, urlparse

import redis
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from flask import Flask, Response, jsonify, redirect, request, send_from_directory
from google.auth.transport.requests import Request as GARequest
from google.oauth2 import service_account

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
SA_DRIVE_SCOPE = os.getenv("SA_DRIVE_SCOPE", "https://www.googleapis.com/auth/drive")
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_DRIVE_UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files"
GOOGLE_DRIVE_FILES_URL = "https://www.googleapis.com/drive/v3/files"

# Optional Service Account + target folder support
GDRIVE_USE_SERVICE_ACCOUNT = os.getenv("GDRIVE_USE_SERVICE_ACCOUNT", "false").lower() in ("1", "true", "yes")
SA_KEY_FILE = os.getenv("SA_KEY_FILE")  # path to service-account JSON in container

# Drive subfolder for uploads
DRIVE_FOLDER_ID = os.getenv("DRIVE_FOLDER_ID")  # explicit folder id override
DRIVE_SUBFOLDER_NAME = os.getenv("DRIVE_SUBFOLDER_NAME", "rclone").strip() or "rclone"

# Hybrid encryption / signing keys (server-side)
PRIVATE_KEY_FILE = os.getenv("PRIVATE_KEY_FILE")  # RSA private key for unwrap (PEM)
SIGN_PUBLIC_KEY_FILE = os.getenv("SIGN_PUBLIC_KEY_FILE")  # Ed25519 public key for verify (PEM)

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


def _debug_event(event: str, **kwargs):
    """Emit a structured debug log if DEBUG is enabled."""
    if not logger.isEnabledFor(logging.DEBUG):
        return
    payload = " ".join(f"{k}={kwargs[k]!r}" for k in sorted(kwargs))
    logger.debug("%s %s", event, payload.strip())


def _token_preview(tok: str | None):
    if not tok:
        return None
    return f"{tok[:6]}...len={len(tok)}"

# ── Key loading (lazy) ────────────────────────────────────────────────────────
_RSA_PRIVATE = None
_SIGN_PUB = None


def _get_rsa_private():
    global _RSA_PRIVATE
    if _RSA_PRIVATE is not None:
        return _RSA_PRIVATE
    if not PRIVATE_KEY_FILE:
        raise RuntimeError("PRIVATE_KEY_FILE not set")
    with open(PRIVATE_KEY_FILE, "rb") as f:
        _RSA_PRIVATE = load_pem_private_key(f.read(), password=None)
    return _RSA_PRIVATE


def _get_sign_pub():
    global _SIGN_PUB
    if _SIGN_PUB is not None:
        return _SIGN_PUB
    if not SIGN_PUBLIC_KEY_FILE:
        raise RuntimeError("SIGN_PUBLIC_KEY_FILE not set")
    with open(SIGN_PUBLIC_KEY_FILE, "rb") as f:
        _SIGN_PUB = load_pem_public_key(f.read())
    return _SIGN_PUB


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def _verify_sig_encv3(header_b64: str, sig_b64: str, cipher_b64: str):
    # Signature is over the exact, stable text:
    #   "ENCV3:<headerB64>\n<cipherB64>"
    msg = (f"ENCV3:{header_b64}\n{cipher_b64}").encode("utf-8")
    sig = _b64d(sig_b64)
    pub = _get_sign_pub()
    pub.verify(sig, msg)  # raises on failure


def _decrypt_encv3(header: dict, ciphertext: bytes) -> tuple[bytes, str]:
    if header.get("v") not in (3, "3", None):
        # still allow missing v for early drafts
        pass
    if header.get("wrap") != "RSA-OAEP-SHA256":
        raise ValueError("unsupported_wrap")
    if header.get("alg") != "AES-256-GCM":
        raise ValueError("unsupported_alg")
    iv = _b64d(header["iv"])
    wrapped_key = _b64d(header["wrapped_key"])
    priv = _get_rsa_private()
    aes_key = priv.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plain = AESGCM(aes_key).decrypt(iv, ciphertext, None)
    return plain, (header.get("filename") or "file.bin")


# ── Token helpers ─────────────────────────────────────────────────────────────
def get_session_id():
    sid = request.cookies.get("sid")
    if not sid:
        sid = secrets.token_urlsafe(32)
        _debug_event("sid_generated", sid=_token_preview(sid))
    else:
        _debug_event("sid_loaded", sid=_token_preview(sid))
    return sid


def redis_key(sid, suffix):
    key = f"b64drive:{sid}:{suffix}"
    _debug_event("redis_key", key=key)
    return key


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
    _debug_event(
        "save_tokens",
        sid=_token_preview(sid),
        scope=data["scope"],
        expires_at=exp,
        refresh=bool(data["refresh_token"]),
        access=_token_preview(data["access_token"]),
    )


def load_tokens(sid):
    key = redis_key(sid, "tokens")
    raw = r.get(key)
    if raw:
        _debug_event("load_tokens_hit", sid=_token_preview(sid), key=key)
        return json.loads(raw)
    _debug_event("load_tokens_miss", sid=_token_preview(sid), key=key)
    return None


def refresh_access_token(sid, tok):
    if not tok or not tok.get("refresh_token"):
        _debug_event("refresh_skip", reason="missing_token", sid=_token_preview(sid))
        return None
    p = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": tok["refresh_token"],
    }
    resp = requests.post(GOOGLE_OAUTH_TOKEN_URL, data=p, timeout=20)
    _debug_event(
        "refresh_token_response",
        status=resp.status_code,
        sid=_token_preview(sid),
        ok=resp.status_code == 200,
    )
    if resp.status_code != 200:
        return None
    tr = resp.json()
    if "refresh_token" not in tr:
        tr["refresh_token"] = tok["refresh_token"]
    save_tokens(sid, tr)
    new_tok = load_tokens(sid)
    _debug_event("refresh_token_success", sid=_token_preview(sid), has_token=bool(new_tok))
    return new_tok
    


def get_valid_access_token(sid):
    tok = load_tokens(sid)
    if not tok:
        _debug_event("access_token_missing", sid=_token_preview(sid))
        return None
    if int(time.time()) >= tok.get("expires_at", 0):
        tok = refresh_access_token(sid, tok)
        if not tok:
            _debug_event("access_token_refresh_failed", sid=_token_preview(sid))
            return None
        _debug_event("access_token_refreshed", sid=_token_preview(sid))
    return tok["access_token"]


def get_sa_access_token():
    """Fetch an access token using the service account, scoped to Drive."""
    if not SA_KEY_FILE:
        raise RuntimeError("SA_KEY_FILE not set")
    _debug_event("sa_token_request", key_file=SA_KEY_FILE)
    creds = service_account.Credentials.from_service_account_file(
        SA_KEY_FILE,
        scopes=[SA_DRIVE_SCOPE],
    )
    creds.refresh(GARequest())
    _debug_event("sa_token_acquired", expires_at=str(creds.expiry))
    return creds.token


AUTOLINK_RE = re.compile(r"<([^>\s]+)>")


def _has_local_reference(markdown_text):
    _debug_event("check_local_ref_start", length=len(markdown_text))
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
            _debug_event("check_local_ref_image", target=match.group(1))
            return True
    for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", markdown_text):
        if is_forbidden_target(match.group(1)):
            _debug_event("check_local_ref_link", target=match.group(1))
            return True
    for match in AUTOLINK_RE.finditer(markdown_text):
        if is_forbidden_target(match.group(1)):
            _debug_event("check_local_ref_autolink", target=match.group(1))
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
                _debug_event("check_local_ref_include", line=line.strip())
                return True
    _debug_event("check_local_ref_none")
    return False


def make_sid_response(payload, sid=None):
    if sid is None:
        sid = get_session_id()
    _debug_event("make_sid_response", sid=_token_preview(sid), payload_keys=list(payload.keys()))
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
    _debug_event("api_status", sid=_token_preview(sid), authed=authed)
    resp, sid = make_sid_response({"ok": True, "authed": authed}, sid=sid)
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
    _debug_event("oauth_start", sid=_token_preview(sid), state=_token_preview(state), url=url)
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
    _debug_event("oauth_callback_response", status=resp.status_code, sid=_token_preview(sid))
    if resp.status_code != 200:
        return f"Token exchange failed: {resp.text}", 400
    save_tokens(sid, resp.json())
    _debug_event("oauth_callback_success", sid=_token_preview(sid))
    return "<p>Authorized. You can close this tab.</p><script>setTimeout(()=>window.close(),700)</script>"


# ── Chunked upload endpoints ──────────────────────────────────────────────────
TMP_ROOT = pathlib.Path(os.getenv("B64_TMP_DIR", "/tmp/b64drive"))
TMP_ROOT.mkdir(parents=True, exist_ok=True)


def _sid():
    return request.cookies.get("sid") or ""


def _udir(sid, uid):
    d = TMP_ROOT / sid / uid
    d.mkdir(parents=True, exist_ok=True)
    _debug_event("udir", sid=_token_preview(sid), uid=uid, dir=str(d))
    return d


def _b64p(sid, uid):
    path = _udir(sid, uid) / "payload.b64"
    _debug_event("b64_path", sid=_token_preview(sid), uid=uid, path=str(path))
    return path


def _meta(sid, uid):
    path = _udir(sid, uid) / "meta.json"
    _debug_event("meta_path", sid=_token_preview(sid), uid=uid, path=str(path))
    return path


@app.post("/api/chunk/start")
def chunk_start():
    sid = get_session_id()
    uid = uuid.uuid4().hex
    _debug_event("chunk_start_in", sid=_token_preview(sid), uid=uid)
    dirp = _udir(sid, uid)
    try:
        _meta(sid, uid).write_bytes(json.dumps({"seq": -1}).encode())
        _b64p(sid, uid).write_bytes(b"")
    except Exception as e:
        logger.exception("chunk_start failed: sid=%s uid=%s dir=%s", sid, uid, dirp)
        _debug_event("chunk_start_failed", sid=_token_preview(sid), uid=uid, error=str(e))
        return jsonify({"ok": False, "error": f"init_failed: {e}"}), 500
    logger.info("chunk_start ok: sid=%s uid=%s dir=%s", sid, uid, dirp)
    _debug_event("chunk_start_ok", sid=_token_preview(sid), uid=uid, dir=str(dirp))
    resp, _ = make_sid_response({"ok": True, "upload_id": uid}, sid=sid)
    return resp


@app.post("/api/chunk/append")
def chunk_append():
    sid = _sid()
    b = request.get_json(force=True)
    _debug_event("chunk_append_body", sid=_token_preview(sid), body_keys=list(b.keys()))
    uid = b.get("upload_id")
    seq = int(b.get("seq", -1))
    data = b.get("data", "")
    logger.debug(
        "chunk_append in: sid=%s uid=%s seq=%s data_len=%s", sid, uid, seq, len(data) if isinstance(data, str) else -1
    )
    if not uid or seq < 0 or not data:
        logger.warning("chunk_append bad_args: sid=%s uid=%s seq=%s", sid, uid, seq)
        _debug_event("chunk_append_bad_args", sid=_token_preview(sid), uid=uid, seq=seq)
        return jsonify({"ok": False, "error": "bad_args"}), 400
    m = _meta(sid, uid)
    if not m.exists():
        logger.warning("chunk_append unknown_upload: sid=%s uid=%s meta=%s", sid, uid, m)
        _debug_event("chunk_append_unknown_upload", sid=_token_preview(sid), uid=uid)
        return jsonify({"ok": False, "error": "unknown_upload"}), 404
    meta = json.loads(m.read_bytes() or b"{}")
    _debug_event("chunk_append_meta", sid=_token_preview(sid), uid=uid, meta=meta)
    exp = meta.get("seq", -1) + 1
    if seq != exp:
        logger.warning("chunk_append out_of_order: sid=%s uid=%s expected=%s got=%s", sid, uid, exp, seq)
        _debug_event("chunk_append_out_of_order", sid=_token_preview(sid), uid=uid, expected=exp, got=seq)
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
    _debug_event(
        "chunk_append_written",
        sid=_token_preview(sid),
        uid=uid,
        seq=seq,
        bytes_written=len(data),
        file_size=b64p.stat().st_size if b64p.exists() else -1,
    )
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
    _debug_event("iter_b64_start", path=str(p))
    with open(p, "rt", encoding="utf-8", errors="ignore") as f:
        for slab in f:
            s = carry + slab.strip().replace(" ", "")
            use = (len(s) // 4) * 4
            if use:
                chunk = base64.b64decode(s[:use])
                _debug_event("iter_b64_chunk", read=len(slab), decoded=len(chunk))
                yield chunk
                carry = s[use:]
            else:
                carry = s
    if carry:
        pad = carry + "==="[: (4 - len(carry) % 4) % 4]
        chunk = base64.b64decode(pad)
        _debug_event("iter_b64_tail", decoded=len(chunk))
        yield chunk


@app.post("/api/chunk/finish/download")
def chunk_finish_download():
    sid = _sid()
    b = request.get_json(force=True)
    _debug_event("finish_download_body", sid=_token_preview(sid), body=b)
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
        _debug_event("finish_download_missing_uid", sid=_token_preview(sid))
        return jsonify({"ok": False, "error": "bad_args"}), 400
    if not p.exists():
        logger.warning("finish_download unknown_upload: sid=%s uid=%s path=%s", sid, uid, p)
        _debug_event("finish_download_missing_file", sid=_token_preview(sid), uid=uid)
        return jsonify({"ok": False, "error": "unknown_upload"}), 404
    h = {"Content-Type": mime, "Content-Disposition": f'attachment; filename="{name}"'}
    _debug_event("finish_download_ready", sid=_token_preview(sid), headers=h, path=str(p))

    def g():
        try:
            for c in _iter_b64_file_decode(p):
                _debug_event("finish_download_stream", chunk=len(c))
                yield c
            logger.info("finish_download decode_complete: sid=%s uid=%s", sid, uid)
        finally:
            try:
                shutil.rmtree(_udir(sid, uid), ignore_errors=True)
                logger.info("finish_download cleanup_ok: sid=%s uid=%s dir=%s", sid, uid, _udir(sid, uid))
            except Exception:
                logger.exception("finish_download cleanup_failed: sid=%s uid=%s", sid, uid)
                _debug_event("finish_download_cleanup_failed", sid=_token_preview(sid), uid=uid)

    return Response(g(), headers=h)


@app.post("/api/chunk/finish/drive")
def chunk_finish_drive():
    sid = _sid()
    _debug_event("finish_drive_start", sid=_token_preview(sid), use_sa=GDRIVE_USE_SERVICE_ACCOUNT)
    # Choose auth mode
    if GDRIVE_USE_SERVICE_ACCOUNT:
        try:
            tok = get_sa_access_token()
        except Exception as e:
            logger.exception("service_account_token_failed")
            return jsonify({"ok": False, "error": f"sa_auth_failed: {e}"}), 500
    else:
        tok = get_valid_access_token(sid)
        if not tok:
            return jsonify({"ok": False, "error": "not_authed"}), 401
    _debug_event("finish_drive_token_ready", sid=_token_preview(sid), use_sa=GDRIVE_USE_SERVICE_ACCOUNT)
    b = request.get_json(force=True)
    _debug_event("finish_drive_body", sid=_token_preview(sid), body_keys=list(b.keys()))
    uid = b.get("upload_id")

    encrypted = bool(b.get("encrypted"))
    enc_header_b64 = b.get("enc_header_b64")
    sig_b64 = b.get("sig_b64")
    if not encrypted and enc_header_b64 and sig_b64:
        encrypted = True

    name = b.get("name", "file.bin")
    mime = b.get("mime", "application/octet-stream")
    p = _b64p(sid, uid) if uid else None
    logger.info(
        "finish_drive in: sid=%s uid=%s encrypted=%s name=%s mime=%s path=%s exists=%s",
        sid,
        uid,
        encrypted,
        name,
        mime,
        p,
        p.exists() if p else False,
    )

    if not uid:
        _debug_event("finish_drive_missing_uid", sid=_token_preview(sid))
        return jsonify({"ok": False, "error": "bad_args"}), 400
    if not p.exists():
        logger.warning("finish_drive unknown_upload: sid=%s uid=%s path=%s", sid, uid, p)
        _debug_event("finish_drive_missing_file", sid=_token_preview(sid), uid=uid, path=str(p))
        return jsonify({"ok": False, "error": "unknown_upload"}), 404
    out = _udir(sid, uid) / "payload.bin"
    try:
        # decode stored base64 to raw bytes (ciphertext if encrypted, plaintext if not)
        raw = bytearray()
        for c in _iter_b64_file_decode(p):
            raw.extend(c)
            _debug_event("finish_drive_raw_chunk", size=len(raw))

        if encrypted:
            if not enc_header_b64 or not sig_b64:
                _debug_event("finish_drive_missing_enc_params", sid=_token_preview(sid))
                return jsonify({"ok": False, "error": "missing_enc_params"}), 400

            # Reconstruct ciphertext base64 as signed: remove whitespace/newlines.
            cipher_b64 = p.read_text("utf-8", errors="ignore")
            cipher_b64 = cipher_b64.replace("\r", "").replace("\n", "").replace(" ", "")
            _verify_sig_encv3(enc_header_b64, sig_b64, cipher_b64)
            _debug_event("finish_drive_signature_verified", sid=_token_preview(sid))

            header = json.loads(base64.b64decode(enc_header_b64).decode("utf-8"))
            plain, fname = _decrypt_encv3(header, bytes(raw))
            _debug_event("finish_drive_decrypt_ok", sid=_token_preview(sid), header_keys=list(header.keys()))

            # Prefer embedded filename if present
            name = fname or name
            mime = header.get("mime") or mime

            with open(out, "wb") as o:
                o.write(plain)
            logger.info(
                "finish_drive verified+decrypted: sid=%s uid=%s out=%s size=%s", sid, uid, out, out.stat().st_size
            )
        else:
            with open(out, "wb") as o:
                o.write(bytes(raw))
            logger.info("finish_drive decoded: sid=%s uid=%s out=%s size=%s", sid, uid, out, out.stat().st_size)
            _debug_event("finish_drive_plain_saved", sid=_token_preview(sid), path=str(out), size=out.stat().st_size)

    except Exception as e:
        logger.exception("finish_drive decode_or_decrypt_failed: sid=%s uid=%s", sid, uid)
        _debug_event("finish_drive_decode_failed", sid=_token_preview(sid), error=str(e))
        if e.__class__.__name__ == "InvalidSignature":
            return jsonify({"ok": False, "error": "bad_signature"}), 400
        return jsonify({"ok": False, "error": f"decode_failed: {e}"}), 500

    try:
        ok, payload = _drive_upload(sid, tok, out, name, mime)
        _debug_event("finish_drive_upload_result", sid=_token_preview(sid), ok=ok, payload_keys=list(payload.keys()) if isinstance(payload, dict) else None)
    finally:
        try:
            shutil.rmtree(_udir(sid, uid), ignore_errors=True)
            logger.info("finish_drive cleanup_ok: sid=%s uid=%s", sid, uid)
        except Exception:
            logger.exception("finish_drive cleanup_failed: sid=%s uid=%s", sid, uid)
            _debug_event("finish_drive_cleanup_failed", sid=_token_preview(sid), uid=uid)

    if not ok:
        _debug_event("finish_drive_upload_failed", sid=_token_preview(sid), payload=payload)
        return jsonify(payload), 502
    result = {"ok": True, "id": payload.get("id"), "name": payload.get("name")}
    _debug_event("finish_drive_response", sid=_token_preview(sid), result=result)
    return jsonify(result)


# ── Drive folder helpers ──────────────────────────────────────────────────────
_RCLONE_FOLDER_CACHE_KEY = b"b64drive:rclone_folder_id:v1"
_RCLONE_FOLDER_ID = None


def _drive_headers(tok):
    hdrs = {"Authorization": f"Bearer {tok}"}
    _debug_event("drive_headers", header_keys=list(hdrs.keys()))
    return hdrs


def _ensure_drive_folder(tok) -> str | None:
    """Return a folder id to upload into. Prefers DRIVE_FOLDER_ID; else ensures DRIVE_SUBFOLDER_NAME exists."""
    global _RCLONE_FOLDER_ID
    if DRIVE_FOLDER_ID:
        _debug_event("ensure_drive_folder_env", folder=DRIVE_FOLDER_ID)
        return DRIVE_FOLDER_ID

    if _RCLONE_FOLDER_ID:
        _debug_event("ensure_drive_folder_cached", folder=_RCLONE_FOLDER_ID)
        return _RCLONE_FOLDER_ID

    try:
        cached = r.get(_RCLONE_FOLDER_CACHE_KEY)
        if cached:
            _RCLONE_FOLDER_ID = cached.decode("utf-8")
            _debug_event("ensure_drive_folder_redis_hit", folder=_RCLONE_FOLDER_ID)
            return _RCLONE_FOLDER_ID
    except Exception:
        pass

    name = DRIVE_SUBFOLDER_NAME
    sub_name = name.replace("'", "\\'")
    q = f"name='{sub_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
    params = {"q": q, "fields": "files(id,name)", "spaces": "drive", "pageSize": "10"}
    resp = requests.get(GOOGLE_DRIVE_FILES_URL, headers=_drive_headers(tok), params=params, timeout=20)
    _debug_event("ensure_drive_folder_query", status=resp.status_code, has_files=resp.status_code == 200)
    if resp.status_code == 200:
        files = (resp.json() or {}).get("files") or []
        if files:
            _RCLONE_FOLDER_ID = files[0]["id"]
            try:
                r.setex(_RCLONE_FOLDER_CACHE_KEY, 60 * 60 * 24, str(_RCLONE_FOLDER_ID).encode())
            except Exception:
                pass
            _debug_event("ensure_drive_folder_exists", folder=_RCLONE_FOLDER_ID)
            return _RCLONE_FOLDER_ID

    # Create folder
    meta = {"name": name, "mimeType": "application/vnd.google-apps.folder"}
    cresp = requests.post(
        GOOGLE_DRIVE_FILES_URL,
        headers={**_drive_headers(tok), "Content-Type": "application/json"},
        data=json.dumps(meta).encode(),
        timeout=20,
    )
    if cresp.status_code in (200, 201):
        _RCLONE_FOLDER_ID = (cresp.json() or {}).get("id")
        if _RCLONE_FOLDER_ID:
            try:
                r.setex(_RCLONE_FOLDER_CACHE_KEY, 60 * 60 * 24, _RCLONE_FOLDER_ID.encode())
            except Exception:
                pass
            _debug_event("ensure_drive_folder_created", folder=_RCLONE_FOLDER_ID)
            return _RCLONE_FOLDER_ID

    logger.warning("could_not_ensure_folder: name=%s status=%s body=%s", name, cresp.status_code, cresp.text[:300])
    _debug_event("ensure_drive_folder_failed", status=cresp.status_code)
    return None


def _drive_upload(sid, tok, file_path, name, mime):
    folder_id = _ensure_drive_folder(tok)
    meta = {"name": name}
    if folder_id:
        meta["parents"] = [folder_id]
    _debug_event("drive_upload_meta", sid=_token_preview(sid), folder=folder_id, mime=mime, size=os.path.getsize(file_path))
    if not folder_id:
        _debug_event("drive_upload_no_folder", sid=_token_preview(sid))

    boundary = "bnd" + uuid.uuid4().hex
    upload_params = {"uploadType": "multipart"}

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
    resp = requests.post(GOOGLE_DRIVE_UPLOAD_URL, headers=headers, params=upload_params, data=multipart(), timeout=600)
    _debug_event(
        "drive_upload_post",
        status=resp.status_code,
        name=name,
        mime=mime,
        file=str(file_path),
    )
    if resp.status_code not in (200, 201) and not GDRIVE_USE_SERVICE_ACCOUNT:
        _debug_event("drive_upload_retry_needed", status=resp.status_code)
        new = refresh_access_token(sid, load_tokens(sid) or {})
        if new:
            headers["Authorization"] = f"Bearer {new['access_token']}"
            resp = requests.post(
                GOOGLE_DRIVE_UPLOAD_URL, headers=headers, params=upload_params, data=multipart(), timeout=600
            )
            _debug_event("drive_upload_retry_response", status=resp.status_code)

    try:
        info = resp.json()
    except Exception:
        info = {}
    if resp.status_code not in (200, 201):
        _debug_event("drive_upload_error", status=resp.status_code)
        return False, {"ok": False, "error": f"drive_error {resp.status_code}: {resp.text[:500]}"}
    _debug_event("drive_upload_success", status=resp.status_code, response_keys=list(info.keys()))
    return True, info


@app.post("/api/markdown/convert")
def markdown_convert():
    sid = _sid()
    _debug_event("markdown_convert_start", sid=_token_preview(sid))
    tok = get_valid_access_token(sid)
    if not tok:
        return jsonify({"ok": False, "error": "not_authed"}), 401
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "error": "invalid_json"}), 400
    markdown_text = body.get("markdown") if isinstance(body, dict) else None
    filename = (body.get("filename") or "").strip() if isinstance(body, dict) else ""
    _debug_event("markdown_convert_body", sid=_token_preview(sid), has_markdown=isinstance(markdown_text, str))
    if not isinstance(markdown_text, str) or not markdown_text.strip():
        return jsonify({"ok": False, "error": "missing_markdown"}), 400
    if _has_local_reference(markdown_text):
        return (
            jsonify({
                "ok": False,
                "error": "local_references_forbidden",
                "message": "Markdown references local files or include directives, which is not allowed.",
            }),
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
    _debug_event("markdown_convert_paths", sid=_token_preview(sid), input=str(input_md), output=str(output_file))
    try:
        input_md.write_text(markdown_text, encoding="utf-8")
    except Exception as e:
        logger.exception("markdown_convert write_failed: sid=%s uid=%s", sid, uid)
        return jsonify({"ok": False, "error": f"write_failed: {e}"}), 500
    try:
        subprocess.run(["pandoc", str(input_md), "-o", str(output_file)], check=True, timeout=300)
        _debug_event("markdown_convert_pandoc_ok", sid=_token_preview(sid))
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
    _debug_event("markdown_convert_drive_upload", sid=_token_preview(sid), ok=ok)
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
    _debug_event("chunk_debug_start", sid=_token_preview(sid), base=str(base), base_exists=base.exists())
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
    _debug_event("chunk_debug_summary", sid=_token_preview(sid), entries=len(info))
    return jsonify({"sid": sid, "root": str(base), "uploads": info})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
