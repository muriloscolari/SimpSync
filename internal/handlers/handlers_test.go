package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/muriloscolari/SimpSync/internal/config"
	syncws "github.com/muriloscolari/SimpSync/internal/websocket"
)

func TestRateLimiterBoundsMemory(t *testing.T) {
	rl := NewRateLimiter(60, 2, 10*time.Minute)
	for i := 0; i < maxTrackedIPs+500; i++ {
		rl.Allow(fmt.Sprintf("192.0.2.%d", i))
	}
	if len(rl.buckets) > maxTrackedIPs {
		t.Fatalf("rate limiter exceeded maxTrackedIPs: got %d, max %d", len(rl.buckets), maxTrackedIPs)
	}
}

func TestMethodEnforcementAndRateLimit(t *testing.T) {
	h := &Handler{
		Config: config.Config{
			AuthPepper:         "0123456789abcdef0123456789abcdef",
			AllowRegistration:  false,
			TrustLoopbackProxy: true,
		},
		Hub: syncws.NewHub(),
	}
	router := h.Routes()

	// Health check works on GET and includes security headers.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on GET /healthz, got %d", rec.Code)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options header")
	}

	// GET on POST-only endpoint must be rejected with 405 Method Not Allowed.
	req = httptest.NewRequest(http.MethodGet, "/v1/auth/login", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET /v1/auth/login, got %d", rec.Code)
	}

	// Registration disabled returns 403 Forbidden.
	body := `{"email":"user@example.com","authProof":"0123456789abcdef0123456789abcdef","deviceName":"PC"}`
	req = httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Real-IP", "203.0.113.10")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when registration disabled, got %d", rec.Code)
	}

	// Exhaust burst (6 requests) from the same client IP and verify 429 Too Many Requests.
	for i := 0; i < 6; i++ {
		req = httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Real-IP", "203.0.113.10")
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests after exhausting burst, got %d", rec.Code)
	}
}
