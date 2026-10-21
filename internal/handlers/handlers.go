package handlers

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/muriloscolari/SimpSync/internal/auth"
	"github.com/muriloscolari/SimpSync/internal/config"
	"github.com/muriloscolari/SimpSync/internal/database"
	"github.com/muriloscolari/SimpSync/internal/models"
	syncws "github.com/muriloscolari/SimpSync/internal/websocket"
)

type Handler struct {
	Store  *database.Store
	Config config.Config
	Hub    *syncws.Hub
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.health)
	mux.HandleFunc("/v1/auth/register", h.register)
	mux.HandleFunc("/v1/auth/login", h.login)
	mux.HandleFunc("/v1/auth/logout", h.logout)
	mux.HandleFunc("/v1/devices", h.devices)
	mux.HandleFunc("/v1/sync", h.sync)
	mux.HandleFunc("/v1/ws", h.ws)
	return logging(mux)
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.DeviceName = strings.TrimSpace(input.DeviceName)
	if input.Email == "" || input.AuthProof == "" || input.DeviceName == "" {
		writeError(w, http.StatusBadRequest, "email, authProof and deviceName are required")
		return
	}
	var userID uuid.UUID
	var err error
	if create {
		verifier, verifierErr := auth.Verifier(input.AuthProof, h.Config.AuthPepper)
		if verifierErr != nil {
			writeError(w, http.StatusBadRequest, verifierErr.Error())
			return
		}
		userID, err = h.Store.CreateUser(r.Context(), input.Email, verifier)
	} else {
		var verifier string
		userID, verifier, err = h.Store.UserByEmail(r.Context(), input.Email)
		if err == nil && !auth.Verify(input.AuthProof, verifier, h.Config.AuthPepper) {
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
	sessionID, err := h.Store.CreateSession(r.Context(), userID, input.DeviceName, tokenHash, expires)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	writeJSON(w, http.StatusOK, models.Session{Token: token, ExpiresAt: expires, DeviceID: sessionID.String()})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if raw == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	digest := sha256.Sum256([]byte(raw))
	if err := h.Store.RevokeSession(r.Context(), digest[:]); err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) devices(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.user(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	devices, err := h.Store.Devices(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list devices")
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (h *Handler) sync(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.user(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var input models.SyncRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	for _, change := range input.Changes {
		if change.EntityType == "" || change.EntityID == "" || change.Envelope == "" {
			writeError(w, http.StatusBadRequest, "invalid change")
			return
		}
		if len(change.Envelope) > 4<<20 {
			writeError(w, http.StatusRequestEntityTooLarge, "envelope too large")
			return
		}
		version, err := h.Store.UpsertBlob(r.Context(), userID, change.EntityType, change.EntityID, []byte(change.Envelope), change.Deleted)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not store change")
			return
		}
		change.Version = version
		notification, _ := json.Marshal(map[string]any{
			"entityType": change.EntityType,
			"entityId":   change.EntityID,
			"version":    version,
		})
		h.Hub.Broadcast(userID, notification, nil)
	}
	rows, cursor, err := h.Store.Changes(r.Context(), userID, input.Cursor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read changes")
		return
	}
	response := models.SyncResponse{Cursor: cursor}
	for _, row := range rows {
		response.Changes = append(response.Changes, models.Blob{
			EntityType: row[0].(string), EntityID: row[1].(string), Envelope: string(row[2].([]byte)),
			Version: row[3].(int64), Deleted: row[4].(bool), UpdatedAt: row[5].(time.Time).UTC().Format(time.RFC3339Nano),
		})
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) ws(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.user(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(request *http.Request) bool {
		if len(h.Config.AllowedOrigins) == 0 {
			return request.Header.Get("Origin") == ""
		}
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
	}}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	h.Hub.Join(userID, conn)
	defer func() { h.Hub.Leave(userID, conn); _ = conn.Close() }()
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (h *Handler) user(r *http.Request) (uuid.UUID, bool) {
	raw := bearerToken(r)
	if raw == "" {
		return uuid.Nil, false
	}
	digest := sha256.Sum256([]byte(raw))
	id, err := h.Store.SessionUser(r.Context(), digest[:])
	return id, err == nil
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if len(value) < len("Bearer ") || !strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(value[len("Bearer "):])
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
