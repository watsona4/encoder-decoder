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
import zipfile
from urllib.parse import urlencode, urlparse
import re

import redis
import requests
import yaml
from flask import Flask, Response, jsonify, redirect, request, send_from_directory
from google.oauth2 import service_account
from google.auth.transport.requests import Request as GARequest

# ── Config ────────────────────────────────────────────────────────────────────
PORT = int(os.getenv("PORT", "8000"))
BASE_DIR = pathlib.Path(__file__).resolve().parent

# Redis via individual env vars (no local container)
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_USERNAME = os.getenv("REDIS_USERNAME") or None
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None
REDIS_SSL = os.getenv("REDIS_SSL", "false").lower() in ("1", "true", "yes")

# Local storage path (replaces Google Drive upload)
LOCAL_STORAGE_PATH = pathlib.Path(os.getenv("LOCAL_STORAGE_PATH", "/storage"))

# Google OAuth is now optional (keeping for backwards compatibility)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", f"http://localhost:{PORT}/oauth/callback")

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_DRIVE_UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"

# Google auth is no longer required - files are saved locally
GOOGLE_AUTH_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

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

# ── Basic Authentication ──────────────────────────────────────────────────────
BASIC_AUTH_USER = os.getenv("BASIC_AUTH_USER", "").strip()
BASIC_AUTH_PASS = os.getenv("BASIC_AUTH_PASS", "").strip()
BASIC_AUTH_ENABLED = bool(BASIC_AUTH_USER and BASIC_AUTH_PASS)
if not BASIC_AUTH_ENABLED:
    logger.warning("BASIC_AUTH_USER/PASS not set - site is unprotected!")


def check_basic_auth():
    """Check Basic Auth credentials from request."""
    if not BASIC_AUTH_ENABLED:
        return True
    auth = request.authorization
    if not auth:
        return False
    return (secrets.compare_digest(auth.username, BASIC_AUTH_USER) and
            secrets.compare_digest(auth.password, BASIC_AUTH_PASS))


def require_auth(f):
    """Decorator to require Basic Auth for endpoint access."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_basic_auth():
            logger.warning("basic_auth failed from %s", request.remote_addr)
            return Response(
                "Unauthorized", 401,
                {"WWW-Authenticate": 'Basic realm="B64Drive"'}
            )
        return f(*args, **kwargs)
    return decorated


class PassphraseRequired(Exception):
    pass


class PassphraseIncorrect(Exception):
    pass


def _clean_fp_value(val: str):
    val = (val or "").strip()
    if "=" in val:
        val = val.split("=")[-1]
    return val.strip()


def _load_sender_fingerprints():
    env = ENV_SENDER_CERT_FPS
    senders = []
    if env:
        for idx, entry in enumerate(env.split(","), 1):
            cleaned = _clean_fp_value(entry)
            if cleaned:
                senders.append({"name": f"env_sender_{idx}", "fingerprint": cleaned})
        return senders
    if not FINGERPRINTS_FILE.exists():
        return senders
    try:
        data = yaml.safe_load(FINGERPRINTS_FILE.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        logger.warning("Failed to parse fingerprints file %s: %s", FINGERPRINTS_FILE, exc)
        return senders
    raw_senders = []
    if isinstance(data, dict):
        raw_senders = data.get("senders") or []
        if not raw_senders and data.get("sender"):
            raw_senders = [data["sender"]]
    for idx, entry in enumerate(raw_senders, 1):
        if isinstance(entry, dict):
            fingerprint = entry.get("fingerprint") or entry.get("value") or entry.get("sha256")
            name = entry.get("name") or entry.get("label") or f"sender_{idx}"
        else:
            fingerprint = entry
            name = f"sender_{idx}"
        fingerprint = _clean_fp_value(fingerprint)
        if fingerprint:
            senders.append({"name": name, "fingerprint": fingerprint})
    return senders

# Optional Service Account + target folder support
GDRIVE_USE_SERVICE_ACCOUNT = os.getenv("GDRIVE_USE_SERVICE_ACCOUNT", "false").lower() in ("1","true","yes")
SA_KEY_FILE = os.getenv("SA_KEY_FILE")  # path to service-account JSON in container
DRIVE_FOLDER_ID = os.getenv("DRIVE_FOLDER_ID")  # rclone folder id; required if you want rclone subdir

# Bundle decode (Receive-OneBundle equivalent) settings
BUNDLE_PROCESS_ENABLED = os.getenv("BUNDLE_PROCESS_ENABLED", "true").lower() in ("1", "true", "yes")
RECIPIENT_PRIVATE_KEY_PATH = pathlib.Path(
    os.getenv("RECIPIENT_PRIVATE_KEY_PATH", str(BASE_DIR / "keys" / "recipient_private.pem"))
)
FINGERPRINTS_FILE = pathlib.Path(os.getenv("FINGERPRINTS_FILE", str(BASE_DIR / "keys" / "fingerprints.yaml")))
ENV_SENDER_CERT_FPS = os.getenv("EXPECTED_SENDER_CERT_SHA256", "").strip()
SENDER_FINGERPRINTS = []
SENDER_FINGERPRINTS = _load_sender_fingerprints()

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

def get_sa_access_token():
    """Fetch an access token using the service account, scoped to Drive."""
    if not SA_KEY_FILE:
        raise RuntimeError("SA_KEY_FILE not set")
    creds = service_account.Credentials.from_service_account_file(
        SA_KEY_FILE,
        scopes=["https://www.googleapis.com/auth/drive.file"],
    )
    creds.refresh(GARequest())
    return creds.token


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
@require_auth
def index():
    return send_from_directory(".", "index_simple.html")


@app.get("/index.html")
@require_auth
def index_full():
    return send_from_directory(".", "index.html")


# ── Auth & status ─────────────────────────────────────────────────────────────
@app.get("/api/status")
@require_auth
def api_status():
    sid = get_session_id()
    # Auth is no longer required - files are saved locally
    # Always report as authed for backwards compatibility with UI
    resp, sid = make_sid_response({"ok": True, "authed": True, "storage": "local", "storage_path": str(LOCAL_STORAGE_PATH)})
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
@require_auth
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
@require_auth
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


def _extract_block(text: str, begin_marker: str, end_marker: str):
    start = text.find(begin_marker)
    if start < 0:
        raise ValueError(f"missing marker: {begin_marker}")
    start += len(begin_marker)
    end = text.find(end_marker, start)
    if end < 0:
        raise ValueError(f"missing marker: {end_marker}")
    return text[start:end].strip()


def _run_openssl(args, label, input_bytes=None):
    cmd = ["openssl", *args]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input_bytes)
    if proc.returncode != 0:
        err = proc.stderr.decode() or proc.stdout.decode() or str(proc.returncode)
        raise RuntimeError(f"{label} failed: {err.strip()}")
    return proc


def _normalize_fingerprint(fp: str):
    return fp.strip().replace(":", "").replace(" ", "").lower()


def _verify_sender_fingerprint(cert_path: pathlib.Path):
    if not SENDER_FINGERPRINTS:
        return
    result = _run_openssl(
        ["x509", "-in", str(cert_path), "-noout", "-fingerprint", "-sha256"],
        "sender fingerprint",
    )
    output = result.stdout.decode().strip()
    got_raw = output.split("=")[-1].strip() if "=" in output else output
    got_norm = _normalize_fingerprint(got_raw)
    expected = {
        _normalize_fingerprint(entry.get("fingerprint"))
        for entry in SENDER_FINGERPRINTS
        if entry.get("fingerprint")
    }
    if got_norm not in expected:
        labels = [
            f"{entry.get('name') or 'sender'} ({entry.get('fingerprint')})"
            for entry in SENDER_FINGERPRINTS
            if entry.get("fingerprint")
        ]
        raise RuntimeError(
            f"sender cert fingerprint mismatch (expected one of {', '.join(labels)}, got {got_raw})"
        )


def _process_bundle_payload(bundle_path: pathlib.Path, workdir: pathlib.Path, passphrase: str | None = None):
    if not BUNDLE_PROCESS_ENABLED:
        raise RuntimeError("bundle processing disabled on server")
    if not RECIPIENT_PRIVATE_KEY_PATH.exists():
        raise RuntimeError(f"recipient private key missing: {RECIPIENT_PRIVATE_KEY_PATH}")
    raw_text = bundle_path.read_text(encoding="utf-8", errors="ignore")
    cert_block = _extract_block(raw_text, "-----BEGIN SENDER SIGNING CERT-----", "-----END SENDER SIGNING CERT-----")
    payload_block = _extract_block(
        raw_text, "-----BEGIN ENCRYPTED CMS PAYLOAD-----", "-----END ENCRYPTED CMS PAYLOAD-----"
    )
    sender_cert = workdir / "sender_sign_cert.pem"
    enc_pem = workdir / "payload.enc.cms.pem"
    signed_pem = workdir / "payload.signed.pem"
    zip_path = workdir / "payload.zip"
    sender_cert.write_text(cert_block.strip() + "\n", encoding="utf-8", errors="ignore")
    enc_pem.write_text(payload_block.strip() + "\n", encoding="utf-8", errors="ignore")
    _verify_sender_fingerprint(sender_cert)
    decrypt_args = [
        "cms",
        "-decrypt",
        "-binary",
        "-inform",
        "PEM",
        "-in",
        str(enc_pem),
        "-inkey",
        str(RECIPIENT_PRIVATE_KEY_PATH),
        "-out",
        str(signed_pem),
    ]
    decrypt_input = None
    if passphrase:
        decrypt_args += ["-passin", "stdin"]
        decrypt_input = (passphrase + "\n").encode()
    try:
        _run_openssl(decrypt_args, "cms decrypt", input_bytes=decrypt_input)
    except RuntimeError as exc:
        msg = str(exc).lower()
        if "passphrase" in msg or "password" in msg:
            if passphrase:
                raise PassphraseIncorrect("incorrect passphrase") from exc
            raise PassphraseRequired("passphrase required") from exc
        raise
    _run_openssl(
        ["cms", "-verify", "-binary", "-inform", "PEM", "-in", str(signed_pem), "-CAfile", str(sender_cert), "-out", str(zip_path)],
        "cms verify",
    )
    extract_target = workdir / "bundle_payload.bin"
    extracted_name = None
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            files = [info for info in zf.infolist() if not info.is_dir()]
            if not files:
                raise RuntimeError("zip archive is empty")
            member = max(files, key=lambda m: m.file_size)
            data = zf.read(member)
            extracted_name = pathlib.Path(member.filename).name
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"invalid zip extracted from CMS: {exc}") from exc
    extract_target.write_bytes(data)
    return extract_target, extracted_name


def _convert_msg_to_pdf(msg_path: pathlib.Path, workdir: pathlib.Path) -> pathlib.Path:
    """Convert Outlook .msg file to PDF using extract-msg + wkhtmltopdf."""
    import extract_msg

    msg = extract_msg.openMsg(str(msg_path))

    # Build HTML with headers and body
    html_parts = ['<html><body style="font-family: Arial, sans-serif;">']
    html_parts.append(f'<p><b>From:</b> {msg.sender or "Unknown"}</p>')
    html_parts.append(f'<p><b>To:</b> {msg.to or ""}</p>')
    if msg.cc:
        html_parts.append(f'<p><b>CC:</b> {msg.cc}</p>')
    html_parts.append(f'<p><b>Subject:</b> {msg.subject or "(No Subject)"}</p>')
    html_parts.append(f'<p><b>Date:</b> {msg.date or ""}</p>')
    html_parts.append('<hr>')

    # Add body (prefer HTML, fallback to plain text)
    if msg.htmlBody:
        # Strip outer html/body tags if present, inject into our wrapper
        body = msg.htmlBody
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='replace')
        html_parts.append(body)
    elif msg.body:
        html_parts.append(f'<pre>{msg.body}</pre>')
    else:
        html_parts.append('<p>(No message body)</p>')

    # List attachments at the end
    if msg.attachments:
        html_parts.append('<hr><p><b>Attachments:</b></p><ul>')
        for att in msg.attachments:
            name = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', None) or 'unnamed'
            html_parts.append(f'<li>{name}</li>')
        html_parts.append('</ul>')

    html_parts.append('</body></html>')
    html_content = '\n'.join(html_parts)

    # Write HTML to temp file
    html_path = workdir / "email.html"
    html_path.write_text(html_content, encoding='utf-8')

    # Convert to PDF with wkhtmltopdf
    pdf_path = workdir / "email.pdf"
    result = subprocess.run(
        ['wkhtmltopdf', '--enable-local-file-access', '--load-error-handling', 'ignore',
         '--load-media-error-handling', 'ignore', str(html_path), str(pdf_path)],
        capture_output=True,
        timeout=120
    )
    if result.returncode != 0:
        stderr = result.stderr.decode('utf-8', errors='replace')
        # Log warning but check if PDF was still created
        logger.warning("wkhtmltopdf stderr: %s", stderr[:500])

    if not pdf_path.exists() or pdf_path.stat().st_size == 0:
        raise RuntimeError("wkhtmltopdf produced no output")

    msg.close()
    return pdf_path


@app.post("/api/chunk/finish/download")
@require_auth
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
@require_auth
def chunk_finish_drive():
    """Save file to local storage (previously uploaded to Google Drive)."""
    sid = _sid()
    b = request.get_json(force=True)
    uid = b.get("upload_id")
    name = b.get("name", "file.bin")
    mime = b.get("mime", "application/octet-stream")
    bundle_payload = bool(b.get("bundle_payload"))
    passphrase = (b.get("passphrase") or "").strip()
    p = _b64p(sid, uid) if uid else None
    logger.info(
        "finish_drive in: sid=%s uid=%s bundle=%s name=%s mime=%s path=%s exists=%s",
        sid,
        uid,
        bundle_payload,
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
    workdir = _udir(sid, uid)
    out = workdir / "payload.bin"
    try:
        with open(out, "wb") as o:
            for c in _iter_b64_file_decode(p):
                o.write(c)
        logger.info("finish_drive decode_done: sid=%s uid=%s out=%s size=%s", sid, uid, out, out.stat().st_size)
    except Exception:
        logger.exception("finish_drive decode_failed: sid=%s uid=%s", sid, uid)
        return jsonify({"ok": False, "error": "decode_failed"}), 500
    upload_path = out
    derived_name = None
    if bundle_payload:
        try:
            upload_path, derived_name = _process_bundle_payload(out, workdir, passphrase=passphrase or None)
            logger.info(
                "finish_drive bundle_process_ok: sid=%s uid=%s src=%s out=%s size=%s name=%s",
                sid,
                uid,
                out,
                upload_path,
                upload_path.stat().st_size,
                derived_name,
            )
        except PassphraseRequired:
            return jsonify({"ok": False, "error": "passphrase_required"}), 400
        except PassphraseIncorrect:
            return jsonify({"ok": False, "error": "passphrase_incorrect"}), 400
        except Exception as exc:
            logger.exception("finish_drive bundle_process_failed: sid=%s uid=%s", sid, uid)
            return jsonify({"ok": False, "error": f"bundle_process_failed: {exc}"}), 500
    upload_name = derived_name or (name or "").strip() or "file.bin"

    # Convert .msg to PDF if applicable
    if upload_name.lower().endswith('.msg'):
        try:
            converted_path = _convert_msg_to_pdf(upload_path, workdir)
            upload_path = converted_path
            upload_name = pathlib.Path(upload_name).stem + ".pdf"
            logger.info("msg_to_pdf conversion ok: %s -> %s", name, upload_name)
        except Exception as e:
            logger.warning("msg_to_pdf conversion failed, keeping original: %s", e)

    # Save to local storage instead of Google Drive
    ok, payload = _local_save(upload_path, upload_name)
    try:
        shutil.rmtree(_udir(sid, uid), ignore_errors=True)
        logger.info("finish_drive cleanup_ok: sid=%s uid=%s", sid, uid)
    except Exception:
        logger.exception("finish_drive cleanup_failed: sid=%s uid=%s", sid, uid)
    if not ok:
        return jsonify(payload), 500
    return jsonify({"ok": True, "id": payload.get("id"), "name": payload.get("name"), "path": payload.get("path")})


def _local_save(file_path, name):
    """Save file to local storage directory."""
    try:
        # Ensure storage directory exists
        LOCAL_STORAGE_PATH.mkdir(parents=True, exist_ok=True)

        # Sanitize filename - remove path separators
        safe_name = os.path.basename(name)
        if not safe_name:
            safe_name = "file.bin"

        # Handle duplicate filenames by adding a suffix
        dest_path = LOCAL_STORAGE_PATH / safe_name
        if dest_path.exists():
            base, ext = os.path.splitext(safe_name)
            counter = 1
            while dest_path.exists():
                dest_path = LOCAL_STORAGE_PATH / f"{base}_{counter}{ext}"
                counter += 1

        # Copy file to storage
        shutil.copy2(file_path, dest_path)
        file_id = uuid.uuid4().hex

        logger.info("_local_save ok: src=%s dest=%s size=%s", file_path, dest_path, dest_path.stat().st_size)
        return True, {"id": file_id, "name": dest_path.name, "path": str(dest_path)}
    except Exception as e:
        logger.exception("_local_save failed: src=%s name=%s", file_path, name)
        return False, {"ok": False, "error": f"local_save_failed: {e}"}


def _drive_upload(sid, tok, file_path, name, mime):
    """Legacy Google Drive upload - kept for backwards compatibility."""
    meta = {"name": name}
    if DRIVE_FOLDER_ID:
        meta["parents"] = [DRIVE_FOLDER_ID]
    boundary = "bnd" + uuid.uuid4().hex
    logger.info("_drive_upload: meta=%s", meta)

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
@require_auth
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
@require_auth
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
