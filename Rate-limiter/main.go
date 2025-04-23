package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	rt "github.com/DonyMagRony/Rate-limiter/rate"
)

func main() {
	// Create rate limiter with custom configuration
	config := rt.rate.DefaultConfig()
	config.MaxRequests = 100  // 100 requests
	config.WindowSize = 60000 // 60 seconds

	rl, err := rt.rate.NewRateLimiter("localhost:6379", "", config)
	if err != nil {
		rt.utils.LogError("failed to initialize rate limiter: %v", err)
		os.Exit(1)
	}
	defer rl.Close()

	// Create HTTP server
	mux := http.NewServeMux()

	// Register API handlers
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message":"Hello, API"}`))
	})

	// Another endpoint for testing
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":["user1","user2","user3"]}`))
	})

	// Apply rate limiter middleware
	handler := rt.rate.RateLimiterMiddleware(rl, utils.GenerateKey)(mux)

	// Create and configure the server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		rt.utils.LogInfo("starting server on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			rt.utils.LogError("server failed: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	rt.utils.LogInfo("shutting down server...")

	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		rt.utils.LogError("server shutdown failed: %v", err)
	}

	rt.utils.LogInfo("server stopped")
}
