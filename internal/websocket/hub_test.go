package websocket

import (
	"testing"

	"github.com/google/uuid"
)

func TestHubMaxConnectionsAndBroadcast(t *testing.T) {
	hub := NewHub()
	hub.SetMaxConnsPerUser(3)
	userID := uuid.New()

	c1 := NewClient(userID, uuid.New(), nil)
	c2 := NewClient(userID, uuid.New(), nil)
	c3 := NewClient(userID, uuid.New(), nil)
	c4 := NewClient(userID, uuid.New(), nil)

	hub.Join(c1)
	hub.Join(c2)
	hub.Join(c3)
	hub.Join(c4)

	// c1 should have been evicted when c4 joined.
	select {
	case <-c1.done:
	default:
		t.Fatal("expected oldest client c1 to be closed and evicted")
	}

	// Broadcast excluding c2's deviceID.
	hub.Broadcast(userID, []byte(`{"version":1}`), c2.DeviceID)

	select {
	case <-c2.send:
		t.Fatal("did not expect excluded device c2 to receive broadcast")
	default:
	}

	select {
	case msg := <-c3.send:
		if string(msg) != `{"version":1}` {
			t.Fatalf("unexpected message: %s", string(msg))
		}
	default:
		t.Fatal("expected c3 to receive broadcast")
	}

	hub.DisconnectUser(userID)
	select {
	case <-c4.done:
	default:
		t.Fatal("expected c4 to be closed on DisconnectUser")
	}
}
