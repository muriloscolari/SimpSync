package handlers

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/muriloscolari/SimpSync/internal/auth"
	"github.com/muriloscolari/SimpSync/internal/config"
	"github.com/muriloscolari/SimpSync/internal/database"
	"github.com/muriloscolari/SimpSync/internal/models"
	syncws "github.com/muriloscolari/SimpSync/internal/websocket"
)

const (
	maxAuthBodyBytes   = 16 << 10  // 16 KiB
	maxSyncBodyBytes   = 4 << 20   // 4 MiB
	maxEnvelopeBytes   = 512 << 10 // 512 KiB per entity blob
	maxChangesPerBatch = 200
	maxEmailLen        = 254
	maxDeviceNameLen   = 128
	maxEntityTypeLen   = 64
	maxEntityIDLen     = 256
)

type Handler struct {
	Store       *database.Store
	Config      config.Config
	Hub         *syncws.Hub
	initOnce    sync.Once
	authLimiter *RateLimiter
	syncLimiter *RateLimiter
}

func (h *Handler) ensureLimiters() {
	h.initOnce.Do(func() {
		// Auth: 12 requests/minute per IP with burst of 6.
		h.authLimiter = NewRateLimiter(12, 6, 10*time.Minute)
		// Sync: 120 requests/minute per IP with burst of 30.
		h.syncLimiter = NewRateLimiter(120, 30, 10*time.Minute)
		if h.Hub != nil && h.Config.MaxDevicesPerUser > 0 {
			h.Hub.SetMaxConnsPerUser(h.Config.MaxDevicesPerUser)
		}
	})
}

func (h *Handler) Routes() http.Handler {
	h.ensureLimiters()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("POST /v1/auth/register", h.withRateLimit(h.authLimiter, h.register))
	mux.HandleFunc("POST /v1/auth/login", h.withRateLimit(h.authLimiter, h.login))
	mux.HandleFunc("POST /v1/auth/recover", h.withRateLimit(h.authLimiter, h.recover))
	mux.HandleFunc("POST /v1/auth/logout", h.logout)
	mux.HandleFunc("GET /v1/devices", h.devices)
	mux.HandleFunc("DELETE /v1/devices/{id}", h.revokeDevice)
	mux.HandleFunc("POST /v1/sync", h.withRateLimit(h.syncLimiter, h.sync))
	mux.HandleFunc("GET /v1/ws", h.ws)
	return securityHeaders(logging(mux))
}

func (h *Handler) withRateLimit(limiter *RateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, h.Config.TrustLoopbackProxy)
		if !limiter.Allow(ip) {
			w.Header().Set("Retry-After", "10")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next(w, r)
	}
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	h.authenticate(w, r, true)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	h.authenticate(w, r, false)
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request, create bool) {
	var input models.Credentials
	if err := decodeStrictJSON(w, r, maxAuthBodyBytes, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.DeviceName = strings.TrimSpace(input.DeviceName)
	input.RecoveryKeyHash = strings.TrimSpace(input.RecoveryKeyHash)

	if !isValidEmail(input.Email) || input.AuthProof == "" || input.DeviceName == "" || len(input.DeviceName) > maxDeviceNameLen {
		writeError(w, http.StatusBadRequest, "valid email, authProof and deviceName are required")
		return
	}

	var userID uuid.UUID
	var err error
	if create {
		if !h.Config.AllowRegistration {
			writeError(w, http.StatusForbidden, "registration is disabled on this server")
			return
		}
		var recoveryDigest []byte
		if input.RecoveryKeyHash != "" {
			recoveryDigest, err = auth.HashRecoveryKey(input.RecoveryKeyHash, h.Config.AuthPepper)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		verifier, verifierErr := auth.VerifierCtx(r.Context(), input.AuthProof, h.Config.AuthPepper)
		if verifierErr != nil {
			status := http.StatusBadRequest
			if errors.Is(verifierErr, auth.ErrServerBusy) {
				status = http.StatusServiceUnavailable
			}
			writeError(w, status, verifierErr.Error())
			return
		}
		userID, err = h.Store.RegisterUser(
			r.Context(),
			input.Email,
			verifier,
			recoveryDigest,
			h.Config.AllowRegistration,
			h.Config.MaxUsers,
		)
		if errors.Is(err, database.ErrRegistrationClosed) {
			writeError(w, http.StatusForbidden, "registration limit reached")
			return
		}
	} else {
		var verifier string
		userID, verifier, err = h.Store.UserByEmail(r.Context(), input.Email)
		if err == nil && !auth.VerifyCtx(r.Context(), input.AuthProof, verifier, h.Config.AuthPepper) {
			err = database.ErrNotFound
		}
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, tokenHash, err := auth.Token()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	expires := time.Now().Add(h.Config.SessionTTL)
	sessionID, err := h.Store.CreateSession(r.Context(), userID, input.DeviceName, tokenHash, expires, h.Config.MaxDevicesPerUser)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	writeJSON(w, http.StatusOK, models.Session{Token: token, ExpiresAt: expires, DeviceID: sessionID.String()})
}

func (h *Handler) recover(w http.ResponseWriter, r *http.Request) {
	var input models.RecoveryRequest
	if err := decodeStrictJSON(w, r, maxAuthBodyBytes, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.RecoveryKeyHash = strings.TrimSpace(input.RecoveryKeyHash)
	input.DeviceName = strings.TrimSpace(input.DeviceName)
	if !isValidEmail(input.Email) || input.RecoveryKeyHash == "" || len(input.NewAuthProof) < 32 || input.DeviceName == "" || len(input.DeviceName) > maxDeviceNameLen {
		writeError(w, http.StatusBadRequest, "email, recoveryKeyHash, newAuthProof and deviceName are required")
		return
	}
	recoveryDigest, err := auth.HashRecoveryKey(input.RecoveryKeyHash, h.Config.AuthPepper)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	verifier, err := auth.VerifierCtx(r.Context(), input.NewAuthProof, h.Config.AuthPepper)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, auth.ErrServerBusy) {
			status = http.StatusServiceUnavailable
		}
		writeError(w, status, "invalid authentication proof")
		return
	}
	userID, err := h.Store.RecoverUser(r.Context(), input.Email, recoveryDigest, []byte(input.RecoveryKeyHash), verifier)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid recovery credentials")
		return
	}
	if h.Hub != nil {
		h.Hub.DisconnectUser(userID)
	}
	token, tokenHash, err := auth.Token()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	expires := time.Now().Add(h.Config.SessionTTL)
	deviceID, err := h.Store.CreateSession(r.Context(), userID, input.DeviceName, tokenHash, expires, h.Config.MaxDevicesPerUser)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	writeJSON(w, http.StatusOK, models.Session{Token: token, ExpiresAt: expires, DeviceID: deviceID.String()})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if raw == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	digest := sha256.Sum256([]byte(raw))
	userID, deviceID, err := h.Store.RevokeSession(r.Context(), digest[:])
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.Hub != nil {
		h.Hub.DisconnectDevice(userID, deviceID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) devices(w http.ResponseWriter, r *http.Request) {
	userID, currentDeviceID, ok := h.session(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	devices, err := h.Store.Devices(r.Context(), userID, currentDeviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list devices")
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (h *Handler) revokeDevice(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := h.session(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rawID := strings.TrimSpace(r.PathValue("id"))
	targetDeviceID, err := uuid.Parse(rawID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	if err := h.Store.RevokeDevice(r.Context(), userID, targetDeviceID); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not revoke device")
		return
	}
	if h.Hub != nil {
		h.Hub.DisconnectDevice(userID, targetDeviceID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) sync(w http.ResponseWriter, r *http.Request) {
	userID, deviceID, ok := h.session(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var input models.SyncRequest
	if err := decodeStrictJSON(w, r, maxSyncBodyBytes, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if input.Cursor < 0 || len(input.Changes) > maxChangesPerBatch {
		writeError(w, http.StatusBadRequest, "invalid cursor or too many changes in a single batch")
		return
	}
	for i := range input.Changes {
		change := &input.Changes[i]
		change.EntityType = strings.TrimSpace(change.EntityType)
		change.EntityID = strings.TrimSpace(change.EntityID)
		if !isValidEntityType(change.EntityType) || change.EntityID == "" || len(change.EntityID) > maxEntityIDLen {
			writeError(w, http.StatusBadRequest, "invalid entityType or entityId")
			return
		}
		if !change.Deleted && change.Envelope == "" {
			writeError(w, http.StatusBadRequest, "envelope is required for non-deleted entities")
			return
		}
		if len(change.Envelope) > maxEnvelopeBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "envelope exceeds maximum allowed size")
			return
		}
	}

	changes, newCursor, hasMore, notifications, err := h.Store.Sync(
		r.Context(),
		userID,
		input.Changes,
		input.Cursor,
		h.Config.MaxBlobsPerUser,
	)
	if err != nil {
		if errors.Is(err, database.ErrQuotaExceeded) {
			writeError(w, http.StatusInsufficientStorage, "user storage quota exceeded")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not synchronize changes")
		return
	}

	if h.Hub != nil {
		for _, notif := range notifications {
			h.Hub.Broadcast(userID, notif, deviceID)
		}
	}

	writeJSON(w, http.StatusOK, models.SyncResponse{
		Changes: changes,
		Cursor:  newCursor,
		HasMore: hasMore,
	})
}

func (h *Handler) ws(w http.ResponseWriter, r *http.Request) {
	userID, deviceID, ok := h.session(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(request *http.Request) bool {
			origin := request.Header.Get("Origin")
			if origin == "" {
				return true
			}
			for _, allowed := range h.Config.AllowedOrigins {
				if origin == allowed {
					return true
				}
			}
			return false
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	client := syncws.NewClient(userID, deviceID, conn)
	client.Serve(h.Hub)
}

func (h *Handler) session(r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	raw := bearerToken(r)
	if raw == "" || len(raw) > 128 {
		return uuid.Nil, uuid.Nil, false
	}
	digest := sha256.Sum256([]byte(raw))
	userID, deviceID, err := h.Store.SessionAuth(r.Context(), digest[:])
	return userID, deviceID, err == nil
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if len(value) < len("Bearer ") || !strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(value[len("Bearer "):])
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	reader := http.MaxBytesReader(w, r.Body, maxBytes)
	defer func() { _ = reader.Close() }()
	dec := json.NewDecoder(reader)
	return dec.Decode(dst)
}

func isValidEmail(email string) bool {
	if len(email) < 3 || len(email) > maxEmailLen {
		return false
	}
	at := strings.IndexByte(email, '@')
	dot := strings.LastIndexByte(email, '.')
	return at > 0 && dot > at+1 && dot < len(email)-1 && !strings.ContainsAny(email, " \t\r\n")
}

func isValidEntityType(entityType string) bool {
	if len(entityType) == 0 || len(entityType) > maxEntityTypeLen {
		return false
	}
	for i := 0; i < len(entityType); i++ {
		c := entityType[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}
