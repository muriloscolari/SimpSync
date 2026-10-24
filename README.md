# SimpSync

SimpSync is the hardened, zero-knowledge encrypted synchronization backend for SimpMusic.
The server stores opaque AES-256-GCM encrypted envelopes and synchronization metadata;
key derivation (`PBKDF2-HMAC-SHA256`), keyring wrapping (`DEK` wrapped by Master Password and Recovery Key),
and payload encryption happen exclusively on the client.

## Endpoints

- `GET /healthz`
- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `POST /v1/auth/recover`
- `POST /v1/auth/logout`
- `GET /v1/devices`
- `DELETE /v1/devices/{id}`
- `POST /v1/sync`
- `GET /v1/ws`

## Security & Hardening Architecture

- **Argon2id Concurrency Semaphore**: Limits simultaneous Argon2id password verifications to `2` (capping memory usage at `128 MiB` to prevent OOM DoS attacks).
- **Per-IP Token-Bucket Rate Limiting**: Bounded in-memory rate limiter (`maxTrackedIPs = 4096`) on authentication and sync routes with automatic TTL eviction.
- **Constant-Time Verification**: Uses `crypto/subtle.ConstantTimeCompare` on decoded Argon2id hashes and domain-separated SHA-256 recovery key digests.
- **Registration Lock**: Supports `ALLOW_REGISTRATION=false` and `MAX_USERS=1` so personal self-hosted instances cannot be abused by third parties.
- **Non-Blocking WebSocket Hub**: Dedicated `readPump`/`writePump` per client with `SetReadLimit(4096)`, 30s Ping/Pong heartbeats, and per-user connection limits (`MAX_DEVICES_PER_USER=10`).
- **Container Hardening**: Runs as non-root (`uid=10001`) on a `read_only: true` filesystem with `cap_drop: [ALL]`, `no-new-privileges`, `mem_limit: 512m`, `pids_limit: 100`, bound strictly to loopback `127.0.0.1:8787:8787` behind Nginx.

## Deployment with Docker & Nginx

1. Copy `.env.example` to `.env` and set a strong `AUTH_PEPPER` (`openssl rand -hex 32`) and `POSTGRES_PASSWORD`:
   ```sh
   cp .env.example .env
   docker compose up -d --build
   ```
2. Configure Nginx using `nginx.conf.example` to proxy `https://sync.muriloscolari.me` to `http://127.0.0.1:8787`.

## Running Tests

```sh
go test -race -v ./...
go vet ./...
```
