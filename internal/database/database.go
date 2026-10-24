package database

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/muriloscolari/SimpSync/internal/models"
)

var (
	ErrNotFound           = errors.New("not found")
	ErrRegistrationClosed = errors.New("registration is closed")
	ErrQuotaExceeded      = errors.New("storage quota exceeded")
)

const (
	maxPullBatchItems = 200
	maxPullBatchBytes = 2 << 20 // 2 MiB max payload per pull response
)

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
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

func (s *Store) RegisterUser(
	ctx context.Context,
	email, verifier string,
	recoveryHash []byte,
	allowRegistration bool,
	maxUsers int,
) (uuid.UUID, error) {
	if !allowRegistration {
		return uuid.Nil, ErrRegistrationClosed
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `LOCK TABLE app_user IN EXCLUSIVE MODE`); err != nil {
		return uuid.Nil, err
	}
	if maxUsers > 0 {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM app_user`).Scan(&count); err != nil {
			return uuid.Nil, err
		}
		if count >= maxUsers {
			return uuid.Nil, ErrRegistrationClosed
		}
	}

	id := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO app_user(id,email,auth_verifier) VALUES($1,$2,$3)`, id, email, verifier); err != nil {
		return uuid.Nil, err
	}
	if len(recoveryHash) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO account_recovery(user_id,recovery_key_hash)
			VALUES($1,$2)
			ON CONFLICT(user_id) DO UPDATE SET recovery_key_hash=EXCLUDED.recovery_key_hash, rotated_at=now()`,
			id, recoveryHash); err != nil {
			return uuid.Nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func (s *Store) RecoverUser(
	ctx context.Context,
	email string,
	recoveryHash []byte,
	legacyRecoveryHash []byte,
	verifier string,
) (uuid.UUID, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		UPDATE app_user SET auth_verifier=$4
		FROM account_recovery
		WHERE app_user.id=account_recovery.user_id
		  AND app_user.email=$1
		  AND (account_recovery.recovery_key_hash=$2 OR account_recovery.recovery_key_hash=$3)
		RETURNING app_user.id`, email, recoveryHash, legacyRecoveryHash, verifier).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}

	// Upgrade stored recovery hash to the domain-separated SHA-256 digest and revoke all prior sessions.
	if _, err := tx.Exec(ctx, `UPDATE account_recovery SET recovery_key_hash=$2, rotated_at=now() WHERE user_id=$1`, userID, recoveryHash); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE device_session SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID); err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

func (s *Store) CreateSession(
	ctx context.Context,
	userID uuid.UUID,
	deviceName string,
	tokenHash []byte,
	expires time.Time,
	maxDevices int,
) (uuid.UUID, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if maxDevices > 0 {
		// Revoke oldest active sessions beyond (maxDevices - 1) so the new session stays within the cap.
		_, _ = tx.Exec(ctx, `
			UPDATE device_session SET revoked_at=now()
			WHERE id IN (
				SELECT id FROM device_session
				WHERE user_id=$1 AND revoked_at IS NULL AND expires_at > now()
				ORDER BY last_seen_at DESC
				OFFSET $2
			)`, userID, maxDevices-1)
	}

	id := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO device_session(id,user_id,device_name,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)`,
		id, userID, deviceName, tokenHash, expires); err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func (s *Store) SessionAuth(ctx context.Context, tokenHash []byte) (uuid.UUID, uuid.UUID, error) {
	var userID, deviceID uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		UPDATE device_session SET last_seen_at=now()
		WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at > now()
		RETURNING user_id, id`, tokenHash).Scan(&userID, &deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, ErrNotFound
	}
	return userID, deviceID, err
}

func (s *Store) RevokeSession(ctx context.Context, tokenHash []byte) (uuid.UUID, uuid.UUID, error) {
	var userID, deviceID uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		UPDATE device_session SET revoked_at=now()
		WHERE token_hash=$1 AND revoked_at IS NULL
		RETURNING user_id, id`, tokenHash).Scan(&userID, &deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, ErrNotFound
	}
	return userID, deviceID, err
}

func (s *Store) RevokeDevice(ctx context.Context, userID, deviceID uuid.UUID) error {
	result, err := s.Pool.Exec(ctx, `
		UPDATE device_session SET revoked_at=now()
		WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, deviceID, userID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Devices(ctx context.Context, userID, currentDeviceID uuid.UUID) ([]models.Device, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, device_name, created_at, last_seen_at
		FROM device_session
		WHERE user_id=$1 AND revoked_at IS NULL AND expires_at > now()
		ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := make([]models.Device, 0)
	for rows.Next() {
		var device models.Device
		if err := rows.Scan(&device.ID, &device.DeviceName, &device.CreatedAt, &device.LastSeenAt); err != nil {
			return nil, err
		}
		device.Current = currentDeviceID != uuid.Nil && device.ID == currentDeviceID.String()
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (s *Store) Sync(
	ctx context.Context,
	userID uuid.UUID,
	incoming []models.Blob,
	cursor int64,
	maxBlobsPerUser int,
) ([]models.Blob, int64, bool, [][]byte, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, cursor, false, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Read remote changes that existed prior to this push (version > cursor), bounded by count & memory.
	rows, err := tx.Query(ctx, `
		SELECT entity_type, entity_id, envelope, version, deleted_at, updated_at
		FROM sync_blob
		WHERE user_id=$1 AND version>$2
		ORDER BY version ASC
		LIMIT $3`, userID, cursor, maxPullBatchItems+1)
	if err != nil {
		return nil, cursor, false, nil, err
	}

	remoteChanges := make([]models.Blob, 0)
	newest := cursor
	hasMore := false
	accumulatedBytes := 0

	for rows.Next() {
		var entityType, entityID string
		var envelope []byte
		var version int64
		var deletedAt *time.Time
		var updatedAt time.Time
		if err := rows.Scan(&entityType, &entityID, &envelope, &version, &deletedAt, &updatedAt); err != nil {
			rows.Close()
			return nil, cursor, false, nil, err
		}
		if len(remoteChanges) >= maxPullBatchItems || (len(remoteChanges) > 0 && accumulatedBytes+len(envelope) > maxPullBatchBytes) {
			hasMore = true
			break
		}
		accumulatedBytes += len(envelope)
		remoteChanges = append(remoteChanges, models.Blob{
			EntityType: entityType,
			EntityID:   entityID,
			Envelope:   string(envelope),
			Version:    version,
			Deleted:    deletedAt != nil,
			UpdatedAt:  updatedAt.UTC().Format(time.RFC3339Nano),
		})
		if version > newest {
			newest = version
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, cursor, false, nil, err
	}
	rows.Close()

	// 2. If there are incoming changes, enforce user quota and upsert atomically.
	var notifications [][]byte
	if len(incoming) > 0 {
		if maxBlobsPerUser > 0 {
			var currentCount int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM sync_blob WHERE user_id=$1`, userID).Scan(&currentCount); err != nil {
				return nil, cursor, false, nil, err
			}
			if currentCount+len(incoming) > maxBlobsPerUser {
				return nil, cursor, false, nil, ErrQuotaExceeded
			}
		}

		for _, change := range incoming {
			var version int64
			err := tx.QueryRow(ctx, `
				INSERT INTO sync_blob(user_id,entity_type,entity_id,envelope,version,deleted_at)
				VALUES($1,$2,$3,$4,nextval('sync_revision_seq'),CASE WHEN $5 THEN now() ELSE NULL END)
				ON CONFLICT(user_id,entity_type,entity_id) DO UPDATE SET
					envelope=EXCLUDED.envelope,
					version=EXCLUDED.version,
					deleted_at=EXCLUDED.deleted_at,
					updated_at=now()
				RETURNING version`,
				userID, change.EntityType, change.EntityID, []byte(change.Envelope), change.Deleted,
			).Scan(&version)
			if err != nil {
				return nil, cursor, false, nil, err
			}
			// Only advance the returned cursor if we didn't truncate the pull batch;
			// otherwise the client still needs to pull the remaining pages before advancing past them.
			if !hasMore && version > newest {
				newest = version
			}
			notif, _ := json.Marshal(map[string]any{
				"entityType": change.EntityType,
				"entityId":   change.EntityID,
				"version":    version,
			})
			notifications = append(notifications, notif)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, cursor, false, nil, err
	}
	return remoteChanges, newest, hasMore, notifications, nil
}

func (s *Store) CleanupExpiredSessions(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `
		DELETE FROM device_session
		WHERE expires_at < now()
		   OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '7 days')`)
	return err
}
