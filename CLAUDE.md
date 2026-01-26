# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

B64Drive ("Decoder Ring") is a secure file transfer application that provides:
- Chunked file uploads with base64 encoding
- CMS (Cryptographic Message Syntax) bundle encryption/decryption via OpenSSL
- Markdown-to-Word/PDF conversion via Pandoc
- Outlook .msg to PDF conversion via extract-msg + wkhtmltopdf
- Local file storage (previously Google Drive, migrated Jan 2025)

## Commands

### Docker

```bash
# Build and run
docker-compose up --build

# Service runs at http://localhost:8227 (maps to internal port 8000)
```

### Testing

```bash
# Run all tests
pytest tests/test_chunks.py -v

# Run single test
pytest tests/test_chunks.py::test_chunk_roundtrip_download -v
```

Tests set `UNIT_TESTING=1` environment variable and use Flask test client with cookie-based session mocking.

### CLI Tool

```bash
# Replicate browser upload flow from command line
python cli_chunk_runner.py <bundle-or-json-file> [--skip-drive] [--no-bundle-payload]
```

## Architecture

### Backend (`server.py`)

Flask application with Redis for session/token storage. Key endpoint groups:

- **Chunked uploads**: `/api/chunk/start`, `/api/chunk/append`, `/api/chunk/finish/drive`, `/api/chunk/finish/download`
- **Bundle processing**: CMS decryption with sender certificate verification using OpenSSL subprocess calls
- **Markdown conversion**: Pandoc integration with security restrictions (blocks local file references and include directives)
- **MSG conversion**: Auto-converts .msg files to PDF on upload via `_convert_msg_to_pdf()`
- **Status**: `/health` (unauthenticated, for Docker), `/api/status` (authenticated), `/api/chunk/debug` (active uploads)

Temporary upload data stored in `/tmp/b64drive/{sid}/{uid}/`.

### Frontend

- `/` serves `index_simple.html` - Simplified UI for clipboard-based bundle uploads (default)
- `/index.html` - Full UI with drag-and-drop file picker, chunked upload progress, markdown submission

Both use vanilla JavaScript with no frameworks.

### Encryption Flow

Client-side hybrid encryption (v3 format):
1. AES-256-GCM encrypts file content
2. RSA-OAEP wraps the AES key
3. Ed25519 signs the message
4. Server decrypts using keys from `/app/keys/` volume

Bundle processing verifies sender against SHA256 fingerprints in `FINGERPRINTS_FILE`.

### Key Environment Variables

| Variable | Purpose |
|----------|---------|
| `BASIC_AUTH_USER` | Username for Basic Auth (required) |
| `BASIC_AUTH_PASS` | Password for Basic Auth (required) |
| `REDIS_HOST/PORT/USERNAME/PASSWORD` | Redis connection |
| `LOCAL_STORAGE_PATH` | File storage directory |
| `BUNDLE_PROCESS_ENABLED` | Enable CMS decryption |
| `RECIPIENT_PRIVATE_KEY_PATH` | Server decryption key |
| `FINGERPRINTS_FILE` | Trusted sender fingerprints (YAML) |
| `LOG_LEVEL` | Logging verbosity (DEBUG/INFO/etc) |

### Authentication

All endpoints are protected by HTTP Basic Authentication. Set `BASIC_AUTH_USER` and `BASIC_AUTH_PASS` in `.env`. If not configured, a warning is logged and the site runs unprotected.

## Tech Stack

- Python 3.12 / Flask 3.0.3 / Gunicorn
- Redis for sessions
- OpenSSL for CMS operations
- Pandoc for document conversion
- wkhtmltopdf + extract-msg for .msg to PDF conversion
- cryptography library for test key generation
