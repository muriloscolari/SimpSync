package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

const DefaultInsecurePepper = "replace-with-a-long-random-secret"

type Config struct {
	Port               string
	DatabaseURL        string
	SessionTTL         time.Duration
	AuthPepper         string
	AllowedOrigins     []string
	AllowRegistration  bool
	MaxUsers           int
	MaxBlobsPerUser    int
	MaxDevicesPerUser  int
	TrustLoopbackProxy bool
}

func Load() Config {
	ttl := 30 * 24 * time.Hour
	if raw := os.Getenv("SESSION_TTL"); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			ttl = parsed
		}
	}
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8787"
	}
	return Config{
		Port:               port,
		DatabaseURL:        strings.TrimSpace(os.Getenv("DATABASE_URL")),
		SessionTTL:         ttl,
		AuthPepper:         os.Getenv("AUTH_PEPPER"),
		AllowedOrigins:     splitCSV(os.Getenv("ALLOWED_ORIGINS")),
		AllowRegistration:  BoolEnv("ALLOW_REGISTRATION", true),
		MaxUsers:           IntEnv("MAX_USERS", 5),
		MaxBlobsPerUser:    IntEnv("MAX_BLOBS_PER_USER", 50000),
		MaxDevicesPerUser:  IntEnv("MAX_DEVICES_PER_USER", 10),
		TrustLoopbackProxy: BoolEnv("TRUST_LOOPBACK_PROXY", true),
	}
}

func (c Config) Validate() error {
	if c.DatabaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	if len(c.AuthPepper) < 32 || c.AuthPepper == DefaultInsecurePepper {
		return errors.New("AUTH_PEPPER must be set to a random secret of at least 32 characters")
	}
	return nil
}

func splitCSV(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func IntEnv(name string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func BoolEnv(name string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	val, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return val
}
