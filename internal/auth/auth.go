package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize = 16
	keySize  = 32
)

func Verifier(proof, pepper string) (string, error) {
	if len(proof) < 32 {
		return "", errors.New("auth proof is too short")
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	input := []byte(proof + pepper)
	hash := argon2.IDKey(input, salt, 1, 64*1024, 2, keySize)
	return fmt.Sprintf("argon2id$v=19$m=65536,t=1,p=2$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func Verify(proof, encoded, pepper string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}
	var salt, expected []byte
	var err error
	if salt, err = base64.RawStdEncoding.DecodeString(parts[3]); err != nil {
		return false
	}
	if expected, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return false
	}
	hash := argon2.IDKey([]byte(proof+pepper), salt, 1, 64*1024, 2, uint32(len(expected)))
	return strings.EqualFold(base64.RawStdEncoding.EncodeToString(hash), base64.RawStdEncoding.EncodeToString(expected))
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
