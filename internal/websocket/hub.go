package websocket

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	writeWait       = 10 * time.Second
	pongWait        = 65 * time.Second
	pingPeriod      = 30 * time.Second
	maxMessageSize  = 4096
	sendBufferSize  = 16
	defaultMaxConns = 10
)

type Client struct {
	UserID    uuid.UUID
	DeviceID  uuid.UUID
	conn      *websocket.Conn
	send      chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func NewClient(userID, deviceID uuid.UUID, conn *websocket.Conn) *Client {
	return &Client{
		UserID:   userID,
		DeviceID: deviceID,
		conn:     conn,
		send:     make(chan []byte, sendBufferSize),
		done:     make(chan struct{}),
	}
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
}

type Hub struct {
	mu              sync.RWMutex
	rooms           map[uuid.UUID][]*Client
	maxConnsPerUser int
}

func NewHub() *Hub {
	return &Hub{
		rooms:           make(map[uuid.UUID][]*Client),
		maxConnsPerUser: defaultMaxConns,
	}
}

func (h *Hub) SetMaxConnsPerUser(limit int) {
	if limit > 0 {
		h.mu.Lock()
		h.maxConnsPerUser = limit
		h.mu.Unlock()
	}
}

func (h *Hub) Join(client *Client) {
	var evicted []*Client
	h.mu.Lock()
	clients := h.rooms[client.UserID]
	// Evict existing connection for the exact same deviceID or excess connections beyond maxConnsPerUser.
	filtered := make([]*Client, 0, len(clients)+1)
	for _, existing := range clients {
		if existing.DeviceID != uuid.Nil && existing.DeviceID == client.DeviceID {
			evicted = append(evicted, existing)
			continue
		}
		filtered = append(filtered, existing)
	}
	for len(filtered) >= h.maxConnsPerUser {
		evicted = append(evicted, filtered[0])
		filtered = filtered[1:]
	}
	filtered = append(filtered, client)
	h.rooms[client.UserID] = filtered
	h.mu.Unlock()

	for _, old := range evicted {
		old.Close()
	}
}

func (h *Hub) Leave(client *Client) {
	h.mu.Lock()
	clients := h.rooms[client.UserID]
	for i, existing := range clients {
		if existing == client {
			clients = append(clients[:i], clients[i+1:]...)
			break
		}
	}
	if len(clients) == 0 {
		delete(h.rooms, client.UserID)
	} else {
		h.rooms[client.UserID] = clients
	}
	h.mu.Unlock()
	client.Close()
}

func (h *Hub) DisconnectDevice(userID, deviceID uuid.UUID) {
	var target *Client
	h.mu.RLock()
	for _, c := range h.rooms[userID] {
		if c.DeviceID == deviceID {
			target = c
			break
		}
	}
	h.mu.RUnlock()
	if target != nil {
		h.Leave(target)
	}
}

func (h *Hub) DisconnectUser(userID uuid.UUID) {
	h.mu.Lock()
	clients := h.rooms[userID]
	delete(h.rooms, userID)
	h.mu.Unlock()
	for _, c := range clients {
		c.Close()
	}
}

// Broadcast enqueues payload to all connected devices of userID except exceptDeviceID.
// Never performs blocking network I/O while holding locks.
func (h *Hub) Broadcast(userID uuid.UUID, payload []byte, exceptDeviceID uuid.UUID) {
	var slow []*Client
	h.mu.RLock()
	for _, client := range h.rooms[userID] {
		if exceptDeviceID != uuid.Nil && client.DeviceID == exceptDeviceID {
			continue
		}
		select {
		case client.send <- payload:
		default:
			slow = append(slow, client)
		}
	}
	h.mu.RUnlock()

	for _, client := range slow {
		h.Leave(client)
	}
}

func (c *Client) Serve(hub *Hub) {
	hub.Join(c)
	go c.writePump(hub)
	c.readPump(hub)
}

func (c *Client) readPump(hub *Hub) {
	defer hub.Leave(c)
	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (c *Client) writePump(hub *Hub) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		hub.Leave(c)
	}()
	// Clear any inherited HTTP server WriteTimeout before starting the pump.
	_ = c.conn.SetWriteDeadline(time.Time{})

	for {
		select {
		case <-c.done:
			return
		case msg := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
