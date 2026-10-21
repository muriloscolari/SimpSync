package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port           string
	DatabaseURL    string
	SessionTTL     time.Duration
	AuthPepper     string
	AllowedOrigins []string
}

func Load() Config {
	ttl := 30 * 24 * time.Hour
	if raw := os.Getenv("SESSION_TTL"); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			ttl = parsed
		}
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return Config{
		Port:           port,
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		SessionTTL:     ttl,
		AuthPepper:     os.Getenv("AUTH_PEPPER"),
		AllowedOrigins: splitCSV(os.Getenv("ALLOWED_ORIGINS")),
	}
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
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return fallback
	}
	return value
}
