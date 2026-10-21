# SimpSync

SimpSync is the backend for encrypted SimpMusic synchronization. The server stores
opaque encrypted envelopes and synchronization metadata; encryption and key
derivation happen in the client.

## MVP endpoints

- `GET /healthz`
- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `POST /v1/sync`
- `GET /v1/ws`

`authProof` is a client-derived authentication proof, not the master password.
The server never receives the master password or plaintext entity data. `envelope`
is an opaque, versioned client-side encrypted payload.

## Development

```sh
cp .env.example .env
docker compose up --build
```

Without PostgreSQL, run the unit tests:

```sh
go test ./...
```

The current MVP intentionally does not implement password recovery, conflict
merging, or device listing/revocation endpoints yet. Those are required before
production deployment.
