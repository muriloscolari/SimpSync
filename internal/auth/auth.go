package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize           = 16
	keySize            = 32
	minProofLen        = 32
	maxProofLen        = 256
	maxConcurrentArgon = 2
	argonMemoryKiB     = 64 * 1024
	argonTime          = 1
	argonThreads       = 2
)

var (
	ErrProofInvalid    = errors.New("auth proof must be between 32 and 256 bytes")
	ErrServerBusy      = errors.New("authentication subsystem busy")
	ErrRecoveryInvalid = errors.New("recovery key hash must be between 32 and 256 bytes")
	// argonSem caps simultaneous Argon2id allocations to 2 * 64 MiB = 128 MiB across the entire process.
	argonSem = make(chan struct{}, maxConcurrentArgon)
)

func Verifier(proof, pepper string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return VerifierCtx(ctx, proof, pepper)
}

func VerifierCtx(ctx context.Context, proof, pepper string) (string, error) {
	if len(proof) < minProofLen || len(proof) > maxProofLen {
		return "", ErrProofInvalid
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if err := acquireArgon(ctx); err != nil {
		return "", err
	}
	defer releaseArgon()

	input := make([]byte, 0, len(proof)+1+len(pepper))
	input = append(input, proof...)
	input = append(input, ':')
	input = append(input, pepper...)
	hash := argon2.IDKey(input, salt, argonTime, argonMemoryKiB, argonThreads, keySize)
	return fmt.Sprintf("argon2id$v=19$m=65536,t=1,p=2$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func Verify(proof, encoded, pepper string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return VerifyCtx(ctx, proof, encoded, pepper)
}

func VerifyCtx(ctx context.Context, proof, encoded, pepper string) bool {
	if len(proof) < minProofLen || len(proof) > maxProofLen {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) != saltSize {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(expected) != keySize {
		return false
	}
	if err := acquireArgon(ctx); err != nil {
		return false
	}
	defer releaseArgon()

	// Support both domain-separated (proof:pepper) and legacy (proof+pepper) verifiers seamlessly.
	input := make([]byte, 0, len(proof)+1+len(pepper))
	input = append(input, proof...)
	input = append(input, ':')
	input = append(input, pepper...)
	hash := argon2.IDKey(input, salt, argonTime, argonMemoryKiB, argonThreads, uint32(len(expected)))
	if subtle.ConstantTimeCompare(hash, expected) == 1 {
		return true
	}
	legacy := argon2.IDKey([]byte(proof+pepper), salt, argonTime, argonMemoryKiB, argonThreads, uint32(len(expected)))
	return subtle.ConstantTimeCompare(legacy, expected) == 1
}

func HashRecoveryKey(raw, pepper string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < 32 || len(trimmed) > 256 {
		return nil, ErrRecoveryInvalid
	}
	digest := sha256.Sum256([]byte("simpsync-recovery-v1:" + trimmed + ":" + pepper))
	return digest[:], nil
}

func Token() (plain string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", nil, err
	}
	plain = base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(plain))
	return plain, digest[:], nil
}

func ExpiresAt(now time.Time, ttl time.Duration) time.Time {
	return now.Add(ttl)
}

func acquireArgon(ctx context.Context) error {
	select {
	case argonSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ErrServerBusy
	}
}

func releaseArgon() {
	<-argonSem
}
