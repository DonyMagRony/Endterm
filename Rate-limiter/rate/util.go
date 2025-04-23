package rate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Logger levels
const (
	INFO  = "INFO"
	ERROR = "ERROR"
	DEBUG = "DEBUG"
)

// LogInfo logs an info message
func LogInfo(format string, v ...interface{}) {
	logWithLevel(INFO, format, v...)
}

// LogError logs an error message
func LogError(format string, v ...interface{}) {
	logWithLevel(ERROR, format, v...)
}

// LogDebug logs a debug message
func LogDebug(format string, v ...interface{}) {
	logWithLevel(DEBUG, format, v...)
}

// logWithLevel logs a message with the specified level
func logWithLevel(level, format string, v ...interface{}) {
	message := fmt.Sprintf(format, v...)
	log.Printf("[%s] [%s] %s", level, time.Now().Format(time.RFC3339), message)
}

// GenerateKey generates a unique key for a request based on IP and path
func GenerateKey(r *http.Request) string {
	// Get client IP
	ip := getClientIP(r)

	// Generate a key based on IP and request path
	key := fmt.Sprintf("%s:%s", ip, r.URL.Path)

	// For more granular control, you might want to include the HTTP method
	// key = fmt.Sprintf("%s:%s:%s", ip, r.Method, r.URL.Path)

	// If you need to handle high-traffic scenarios with long keys, hash the key
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

// getClientIP extracts the client's real IP address
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header first
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// X-Forwarded-For might contain multiple IPs, we want the first one
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			return clientIP
		}
	}

	// Try X-Real-IP header next
	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		return xRealIP
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, return RemoteAddr as is
		return r.RemoteAddr
	}
	return ip
}
