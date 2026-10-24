package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/muriloscolari/SimpSync/internal/config"
	"github.com/muriloscolari/SimpSync/internal/database"
	"github.com/muriloscolari/SimpSync/internal/handlers"
	syncws "github.com/muriloscolari/SimpSync/internal/websocket"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("config: %v", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer store.Pool.Close()

	if err := store.Migrate(ctx, "migrations"); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	// Periodic cleanup of expired/revoked device sessions so the table never grows unboundedly.
	go func() {
		_ = store.CleanupExpiredSessions(ctx)
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupCtx, cleanupCancel := context.WithTimeout(ctx, 30*time.Second)
				_ = store.CleanupExpiredSessions(cleanupCtx)
				cleanupCancel()
			}
		}
	}()

	hub := syncws.NewHub()
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           (&handlers.Handler{Store: store, Config: cfg, Hub: hub}).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("SimpSync listening on %s (registration=%v, maxUsers=%d)", server.Addr, cfg.AllowRegistration, cfg.MaxUsers)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
