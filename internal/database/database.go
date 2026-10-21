package database

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("not found")

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) UserByEmail(ctx context.Context, email string) (uuid.UUID, string, error) {
	var id uuid.UUID
	var verifier string
	err := s.Pool.QueryRow(ctx, `SELECT id, auth_verifier FROM app_user WHERE email=$1`, email).Scan(&id, &verifier)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrNotFound
	}
	return id, verifier, err
}

func (s *Store) CreateUser(ctx context.Context, email, verifier string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.Pool.Exec(ctx, `INSERT INTO app_user(id,email,auth_verifier) VALUES($1,$2,$3)`, id, email, verifier)
	return id, err
}

func (s *Store) CreateSession(ctx context.Context, userID uuid.UUID, deviceName string, tokenHash []byte, expires time.Time) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.Pool.Exec(ctx, `INSERT INTO device_session(id,user_id,device_name,token_hash) VALUES($1,$2,$3,$4)`, id, userID, deviceName, tokenHash)
	return id, err
}

func (s *Store) SessionUser(ctx context.Context, tokenHash []byte) (uuid.UUID, error) {
	var userID uuid.UUID
	err := s.Pool.QueryRow(ctx, `UPDATE device_session SET last_seen_at=now() WHERE token_hash=$1 AND revoked_at IS NULL RETURNING user_id`, tokenHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return userID, err
}

func (s *Store) UpsertBlob(ctx context.Context, userID uuid.UUID, entityType, entityID string, envelope []byte, deleted bool) (int64, error) {
	var version int64
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO sync_blob(user_id,entity_type,entity_id,envelope,version,deleted_at)
		VALUES($1,$2,$3,$4,nextval('sync_revision_seq'),CASE WHEN $5 THEN now() ELSE NULL END)
		ON CONFLICT(user_id,entity_type,entity_id) DO UPDATE SET
			envelope=EXCLUDED.envelope,
			version=EXCLUDED.version,
			deleted_at=EXCLUDED.deleted_at,
			updated_at=now()
		RETURNING version`, userID, entityType, entityID, envelope, deleted).Scan(&version)
	return version, err
}

func (s *Store) Changes(ctx context.Context, userID uuid.UUID, cursor int64) ([][]any, int64, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT entity_type, entity_id, envelope, version, deleted_at, updated_at
		FROM sync_blob WHERE user_id=$1 AND version>$2 ORDER BY version ASC LIMIT 1000`, userID, cursor)
	if err != nil {
		return nil, cursor, err
	}
	defer rows.Close()
	var changes [][]any
	var newest = cursor
	for rows.Next() {
		var entityType, entityID string
		var envelope []byte
		var version int64
		var deletedAt *time.Time
		var updatedAt time.Time
		if err := rows.Scan(&entityType, &entityID, &envelope, &version, &deletedAt, &updatedAt); err != nil {
			return nil, cursor, err
		}
		changes = append(changes, []any{entityType, entityID, envelope, version, deletedAt != nil, updatedAt})
		if version > newest {
			newest = version
		}
	}
	return changes, newest, rows.Err()
}
