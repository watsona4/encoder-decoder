import base64
import json
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("UNIT_TESTING", "1")

server = __import__("server")
app = server.app


@pytest.fixture(autouse=True)
def _reset_tmp(tmp_path):
    app.config.update(TESTING=True)
    server.TMP_ROOT = tmp_path
    yield


def _client_with_cookie(sid="test-sid"):
    client = app.test_client()
    client.set_cookie("sid", sid, path="/")
    return client, sid


def _store_tokens(sid):
    server.save_tokens(
        sid,
        {
            "access_token": "tok",
            "refresh_token": "tok-refresh",
            "expires_in": 3600,
        },
    )


def test_chunk_roundtrip_download(tmp_path):
    client, sid = _client_with_cookie()
    start = client.post("/api/chunk/start")
    upload_id = start.get_json()["upload_id"]

    payload = b"hello world" * 10

    resp = client.post(
        "/api/chunk/append",
        data=payload,
        headers={
            "Upload-Id": upload_id,
            "Upload-Seq": "0",
            "Content-Type": "application/octet-stream",
        },
    )
    assert resp.status_code == 200
    assert resp.get_json().get("ok") is True

    dl = client.post(
        "/api/chunk/finish/download",
        json={
            "upload_id": upload_id,
            "name": "test.bin",
            "mime": "application/octet-stream",
        },
    )
    assert dl.status_code == 200
    assert dl.data == payload


def test_chunk_append_requires_body():
    client, sid = _client_with_cookie()
    start = client.post("/api/chunk/start")
    upload_id = start.get_json()["upload_id"]

    resp = client.post(
        "/api/chunk/append",
        data=b"",
        headers={"Upload-Id": upload_id, "Upload-Seq": "0"},
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "bad_args"


def test_chunk_append_out_of_order():
    client, sid = _client_with_cookie()
    start = client.post("/api/chunk/start")
    upload_id = start.get_json()["upload_id"]

    resp = client.post(
        "/api/chunk/append",
        data=b"abc",
        headers={"Upload-Id": upload_id, "Upload-Seq": "0"},
    )
    assert resp.status_code == 200

    resp2 = client.post(
        "/api/chunk/append",
        data=b"abc",
        headers={"Upload-Id": upload_id, "Upload-Seq": "0"},
    )
    assert resp2.status_code == 409
    assert "out_of_order" in resp2.get_json()["error"]


def test_chunk_append_unknown_upload():
    client, _ = _client_with_cookie()
    resp = client.post(
        "/api/chunk/append",
        data=b"abc",
        headers={"Upload-Id": "missing", "Upload-Seq": "0"},
    )
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "unknown_upload"


def test_finish_download_unknown_upload():
    client, _ = _client_with_cookie()
    resp = client.post(
        "/api/chunk/finish/download",
        json={
            "upload_id": "missing",
            "name": "file.bin",
            "mime": "application/octet-stream",
        },
    )
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "unknown_upload"


def test_finish_drive_requires_encryption():
    client, sid = _client_with_cookie()
    _store_tokens(sid)

    start = client.post("/api/chunk/start")
    upload_id = start.get_json()["upload_id"]
    client.post(
        "/api/chunk/append",
        data=b"abc",
        headers={"Upload-Id": upload_id, "Upload-Seq": "0"},
    )

    resp = client.post(
        "/api/chunk/finish/drive",
        json={
            "upload_id": upload_id,
            "name": "x.bin",
            "mime": "application/octet-stream",
            "encrypted": False,
        },
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "encryption_required"


def test_finish_drive_missing_params_for_encrypted():
    client, sid = _client_with_cookie()
    _store_tokens(sid)

    start = client.post("/api/chunk/start")
    upload_id = start.get_json()["upload_id"]
    client.post(
        "/api/chunk/append",
        data=b"abc",
        headers={"Upload-Id": upload_id, "Upload-Seq": "0"},
    )

    resp = client.post(
        "/api/chunk/finish/drive",
        json={
            "upload_id": upload_id,
            "name": "x.bin",
            "mime": "application/octet-stream",
            "encrypted": True,
        },
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "missing_enc_params"


def test_finish_drive_happy_path(monkeypatch, tmp_path):
    client, sid = _client_with_cookie()
    _store_tokens(sid)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_private_pem = rsa_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        NoEncryption(),
    )
    rsa_private_file = tmp_path / "rsa_private.pem"
    rsa_private_file.write_bytes(rsa_private_pem)

    sign_key = ed25519.Ed25519PrivateKey.generate()
    sign_pub = sign_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    sign_pub_file = tmp_path / "sign_pub.pem"
    sign_pub_file.write_bytes(sign_pub)

    server.PRIVATE_KEY_FILE = str(rsa_private_file)
    server.SIGN_PUBLIC_KEY_FILE = str(sign_pub_file)
    server._RSA_PRIVATE = None
    server._SIGN_PUB = None

    start = client.post("/api/chunk/start")
    upload_id = start.get_json()["upload_id"]

    plaintext = b"super secret message"
    iv = os.urandom(12)
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    cipher = aesgcm.encrypt(iv, plaintext, None)

    wrapped_key = rsa_key.public_key().encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    header = {
        "v": 3,
        "alg": "AES-256-GCM",
        "wrap": "RSA-OAEP-SHA256",
        "filename": "secret.bin",
        "mime": "application/octet-stream",
        "iv": base64.b64encode(iv).decode("ascii"),
        "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
    }
    header_b64 = base64.b64encode(json.dumps(header).encode()).decode("ascii")
    cipher_b64 = base64.b64encode(cipher).decode("ascii")
    msg = f"ENCV3:{header_b64}\n{cipher_b64}".encode()
    sig_b64 = base64.b64encode(sign_key.sign(msg)).decode("ascii")

    append = client.post(
        "/api/chunk/append",
        data=cipher,
        headers={"Upload-Id": upload_id, "Upload-Seq": "0"},
    )
    assert append.status_code == 200

    called = {}

    def _fake_drive_upload(*args, **kwargs):
        called["hit"] = True
        return True, {"id": "gid", "name": "secret.bin"}

    monkeypatch.setattr(server, "_drive_upload", _fake_drive_upload)

    resp = client.post(
        "/api/chunk/finish/drive",
        json={
            "upload_id": upload_id,
            "name": "ignored.bin",
            "mime": "application/octet-stream",
            "encrypted": True,
            "enc_header_b64": header_b64,
            "sig_b64": sig_b64,
        },
    )

    assert resp.status_code == 200
    js = resp.get_json()
    assert js["ok"] is True
    assert js["name"] == "secret.bin"
    assert called["hit"] is True


def test_chunked_decrypt_encv3(tmp_path):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_private_pem = rsa_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        NoEncryption(),
    )
    rsa_private_file = tmp_path / "rsa_private.pem"
    rsa_private_file.write_bytes(rsa_private_pem)

    server.PRIVATE_KEY_FILE = str(rsa_private_file)
    server._RSA_PRIVATE = None

    iv_base = os.urandom(12)
    chunk_size = 5
    plaintext = b"chunked plaintext payload"
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    wrapped_key = rsa_key.public_key().encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    cipher_chunks = []
    for idx in range(0, len(plaintext), chunk_size):
        chunk = plaintext[idx : idx + chunk_size]
        iv = bytearray(iv_base)
        base_counter = int.from_bytes(iv[-4:], "big") + idx // chunk_size
        iv[-4:] = base_counter.to_bytes(4, "big")
        cipher_chunks.append(
            aesgcm.encrypt(bytes(iv), chunk, (idx // chunk_size).to_bytes(4, "big"))
        )

    cipher = b"".join(cipher_chunks)
    header = {
        "v": 3,
        "alg": "AES-256-GCM",
        "wrap": "RSA-OAEP-SHA256",
        "filename": "chunked.bin",
        "mime": "application/octet-stream",
        "iv": base64.b64encode(iv_base).decode("ascii"),
        "iv_base": base64.b64encode(iv_base).decode("ascii"),
        "chunk_size": chunk_size,
        "chunk_count": len(cipher_chunks),
        "last_chunk_bytes": len(plaintext) % chunk_size or chunk_size,
        "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
    }

    plain, name = server._decrypt_encv3(header, cipher)
    assert plain == plaintext
    assert name == "chunked.bin"


def test_finish_drive_chunked_signature(monkeypatch, tmp_path):
    client, sid = _client_with_cookie()
    _store_tokens(sid)

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_private_pem = rsa_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.TraditionalOpenSSL,
        NoEncryption(),
    )
    rsa_private_file = tmp_path / "rsa_private.pem"
    rsa_private_file.write_bytes(rsa_private_pem)

    sign_key = ed25519.Ed25519PrivateKey.generate()
    sign_pub = sign_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    sign_pub_file = tmp_path / "sign_pub.pem"
    sign_pub_file.write_bytes(sign_pub)

    server.PRIVATE_KEY_FILE = str(rsa_private_file)
    server.SIGN_PUBLIC_KEY_FILE = str(sign_pub_file)
    server._RSA_PRIVATE = None
    server._SIGN_PUB = None

    start = client.post("/api/chunk/start")
    upload_id = start.get_json()["upload_id"]

    plaintext = b"chunked message payload"
    chunk_size = 5  # deliberately not divisible by 3 so base64 concatenation differs
    iv_base = os.urandom(12)
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    cipher_chunks = []
    for idx in range(0, len(plaintext), chunk_size):
        chunk = plaintext[idx : idx + chunk_size]
        iv = bytearray(iv_base)
        counter = int.from_bytes(iv[-4:], "big") + idx // chunk_size
        iv[-4:] = counter.to_bytes(4, "big")
        cipher_chunks.append(
            aesgcm.encrypt(bytes(iv), chunk, (idx // chunk_size).to_bytes(4, "big"))
        )

    wrapped_key = rsa_key.public_key().encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    cipher = b"".join(cipher_chunks)
    header = {
        "v": 3,
        "alg": "AES-256-GCM",
        "wrap": "RSA-OAEP-SHA256",
        "filename": "chunked.sig.bin",
        "mime": "application/octet-stream",
        "iv": base64.b64encode(iv_base).decode("ascii"),
        "iv_base": base64.b64encode(iv_base).decode("ascii"),
        "chunk_size": chunk_size,
        "chunk_count": len(cipher_chunks),
        "last_chunk_bytes": len(plaintext) % chunk_size or chunk_size,
        "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
    }

    header_b64 = base64.b64encode(json.dumps(header).encode()).decode("ascii")
    cipher_b64 = base64.b64encode(cipher).decode("ascii")
    sig_b64 = base64.b64encode(
        sign_key.sign(f"ENCV3:{header_b64}\n{cipher_b64}".encode())
    ).decode("ascii")

    for seq, chunk in enumerate(cipher_chunks):
        resp = client.post(
            "/api/chunk/append",
            data=chunk,
            headers={"Upload-Id": upload_id, "Upload-Seq": str(seq)},
        )
        assert resp.status_code == 200

    called = {}

    def _fake_drive_upload(*args, **kwargs):
        called["hit"] = True
        return True, {"id": "gid", "name": "chunked.sig.bin"}

    monkeypatch.setattr(server, "_drive_upload", _fake_drive_upload)

    resp = client.post(
        "/api/chunk/finish/drive",
        json={
            "upload_id": upload_id,
            "name": "ignored.bin",
            "mime": "application/octet-stream",
            "encrypted": True,
            "enc_header_b64": header_b64,
            "sig_b64": sig_b64,
        },
    )

    assert resp.status_code == 200
    js = resp.get_json()
    assert js["ok"] is True
    assert js["name"] == "chunked.sig.bin"
    assert called["hit"] is True

