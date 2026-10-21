package models

import "time"

type Credentials struct {
	Email      string `json:"email"`
	AuthProof  string `json:"authProof"`
	DeviceName string `json:"deviceName"`
}

type Session struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Blob struct {
	EntityType string `json:"entityType"`
	EntityID   string `json:"entityId"`
	Envelope   string `json:"envelope"`
	Version    int64  `json:"version"`
	Deleted    bool   `json:"deleted"`
	UpdatedAt  string `json:"updatedAt,omitempty"`
}

type SyncRequest struct {
	Changes []Blob `json:"changes"`
	Cursor  int64  `json:"cursor"`
}

type SyncResponse struct {
	Changes []Blob `json:"changes"`
	Cursor  int64  `json:"cursor"`
}

type Device struct {
	ID         string    `json:"id"`
	DeviceName string    `json:"deviceName"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}
