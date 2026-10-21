# SimpSync

SimpSync is the backend for encrypted SimpMusic synchronization. The server stores
opaque encrypted envelopes and synchronization metadata; encryption and key
derivation happen in the client.

## MVP endpoints

- `GET /healthz`
- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `POST /v1/auth/recover`
- `POST /v1/auth/logout`
- `GET /v1/devices`
- `POST /v1/sync`
- `GET /v1/ws`

`authProof` is a client-derived authentication proof, not the master password.
The server never receives the master password or plaintext entity data. `envelope`
is an opaque, versioned client-side encrypted payload.

Set `ALLOWED_ORIGINS` to a comma-separated list before using WebSocket clients.
The server rejects browser WebSocket origins by default when it is empty.

## Development

```sh
cp .env.example .env
docker compose up --build
```

Without PostgreSQL, run the unit tests:

```sh
go test ./...
```

The server applies ordered files from `migrations/` on startup and records
completed files in `schema_migration`. Keep migration files append-only.

The current MVP intentionally does not implement password recovery, conflict
merging, or device listing/revocation endpoints yet. Those are required before
production deployment.
