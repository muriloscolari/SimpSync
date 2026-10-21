package websocket

import (
	"sync"

	"github.com/gorilla/websocket"
	"github.com/google/uuid"
)

type Hub struct {
	mu    sync.RWMutex
	rooms map[uuid.UUID]map[*websocket.Conn]struct{}
}

func NewHub() *Hub { return &Hub{rooms: make(map[uuid.UUID]map[*websocket.Conn]struct{})} }

func (h *Hub) Join(userID uuid.UUID, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rooms[userID] == nil {
		h.rooms[userID] = make(map[*websocket.Conn]struct{})
	}
	h.rooms[userID][conn] = struct{}{}
}

func (h *Hub) Leave(userID uuid.UUID, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.rooms[userID], conn)
	if len(h.rooms[userID]) == 0 {
		delete(h.rooms, userID)
	}
}

func (h *Hub) Broadcast(userID uuid.UUID, payload []byte, except *websocket.Conn) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for conn := range h.rooms[userID] {
		if conn == except {
			continue
		}
		_ = conn.WriteMessage(websocket.TextMessage, payload)
	}
}
