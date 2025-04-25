package rate

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

const (
	DefaultMaxRequests = 100
	DefaultWindowSize = 60 * 1000
	DefaultCacheTTL = 500
	KeyPrefix = "ratelimit:"
	ScriptSHAKey = "ratelimit:script:sha"
	SlidingWindowScript = `local current_time = redis.call('TIME')
local current_timestamp = tonumber(current_time[1]) * 1000 + tonumber(current_time[2]) / 1000
local trim_time = current_timestamp - ARGV[2]
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, trim_time)
local request_count = redis.call('ZCARD', KEYS[1])
if request_count < tonumber(ARGV[1]) then
    redis.call('ZADD', KEYS[1], current_timestamp, current_timestamp)
    redis.call('EXPIRE', KEYS[1], math.ceil(ARGV[2]/1000))
    return { 1, request_count + 1, tostring(current_timestamp + tonumber(ARGV[2])) }
end
return { 0, request_count, 0 }
`
)


type Config struct {
	MaxRequests int
	WindowSize int
	CacheTTL int
	KeyPrefix string
}

func DefaultConfig() Config {
	return Config{
		MaxRequests: DefaultMaxRequests,
		WindowSize:  DefaultWindowSize,
		CacheTTL:    DefaultCacheTTL,
		KeyPrefix:   KeyPrefix,
	}
}

type RateLimiter interface {
	AllowRequest(ctx context.Context, key string) (bool, RateLimitInfo, error)
	Close() error
}

type RateLimitInfo struct {
	Allowed bool
	CurrentCount int
	ResetTime int64
}

type cacheEntry struct {
	info      RateLimitInfo
	expiresAt time.Time
}

type RedisRateLimiter struct {
	client    *redis.Client
	scriptSHA string
	config    Config
	cache     map[string]cacheEntry
	cacheMu   sync.RWMutex
	cleanupStopCh chan struct{}
	cleanupDone   chan struct{}
}

func NewRateLimiter(redisAddr, redisPass string, config ...Config) (RateLimiter, error) {
	cfg := DefaultConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	client := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Password:     redisPass,
		DB:           0,
		PoolSize:     10,
		MinIdleConns: 2,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolTimeout:  4 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	sha, err := loadScript(ctx, client)
	if err != nil {
		return nil, err
	}

	rl := &RedisRateLimiter{
		client:        client,
		scriptSHA:     sha,
		config:        cfg,
		cache:         make(map[string]cacheEntry),
		cleanupStopCh: make(chan struct{}),
		cleanupDone:   make(chan struct{}),
	}

	go rl.cleanupCache()
	return rl, nil
}

func loadScript(ctx context.Context, client *redis.Client) (string, error) {
	sha, err := client.Get(ctx, ScriptSHAKey).Result()
	if err == nil && sha != "" {
		exists, err := client.ScriptExists(ctx, sha).Result()
		if err == nil && len(exists) > 0 && exists[0] {
			return sha, nil
		}
	}

	sha, err = client.ScriptLoad(ctx, SlidingWindowScript).Result()
	if err != nil {
		return "", fmt.Errorf("failed to load script: %w", err)
	}

	if err := client.Set(ctx, ScriptSHAKey, sha, 0).Err(); err != nil {
		return "", fmt.Errorf("failed to store script SHA: %w", err)
	}

	return sha, nil
}

func (rl *RedisRateLimiter) cleanupCache() {
	ticker := time.NewTicker(time.Duration(rl.config.CacheTTL) * time.Millisecond)
	defer ticker.Stop()
	defer close(rl.cleanupDone)

	for {
		select {
		case <-ticker.C:
			rl.cacheMu.Lock()
			now := time.Now()
			for key, entry := range rl.cache {
				if entry.expiresAt.Before(now) {
					delete(rl.cache, key)
				}
			}
			rl.cacheMu.Unlock()
		case <-rl.cleanupStopCh:
			return
		}
	}
}

func (rl *RedisRateLimiter) AllowRequest(ctx context.Context, key string) (bool, RateLimitInfo, error) {
	redisKey := rl.config.KeyPrefix + key

	rl.cacheMu.RLock()
	entry, exists := rl.cache[key]
	if exists && entry.expiresAt.After(time.Now()) {
		rl.cacheMu.RUnlock()
		return entry.info.Allowed, entry.info, nil
	}
	rl.cacheMu.RUnlock()

	keys := []string{redisKey}
	args := []interface{}{rl.config.MaxRequests, rl.config.WindowSize}

	result, err := rl.client.EvalSha(ctx, rl.scriptSHA, keys, args...).Result()
	if err != nil {
		if err == redis.Nil || redis.IsErr(err) {
			sha, loadErr := loadScript(ctx, rl.client)
			if loadErr != nil {
				return false, RateLimitInfo{}, fmt.Errorf("failed to reload script: %w", loadErr)
			}
			rl.scriptSHA = sha
			result, err = rl.client.EvalSha(ctx, rl.scriptSHA, keys, args...).Result()
			if err != nil {
				return false, RateLimitInfo{}, fmt.Errorf("script execution error: %w", err)
			}
		} else {
			return false, RateLimitInfo{}, fmt.Errorf("script execution error: %w", err)
		}
	}

	resultArray, ok := result.([]interface{})
	if !ok || len(resultArray) < 3 {
		return false, RateLimitInfo{}, fmt.Errorf("invalid script result: %v", result)
	}

	allowed := resultArray[0].(int64) == 1
	count := int(resultArray[1].(int64))

	var resetTime int64
	if s, ok := resultArray[2].(string); ok && s != "0" {
		resetTime, _ = parseInt64(s)
	}

	info := RateLimitInfo{
		Allowed:      allowed,
		CurrentCount: count,
		ResetTime:    resetTime,
	}

	rl.cacheMu.Lock()
	rl.cache[key] = cacheEntry{
		info:      info,
		expiresAt: time.Now().Add(time.Duration(rl.config.CacheTTL) * time.Millisecond),
	}
	rl.cacheMu.Unlock()

	return allowed, info, nil
}

func parseInt64(s string) (int64, error) {
	var i int64
	_, err := fmt.Sscanf(s, "%d", &i)
	return i, err
}

func (rl *RedisRateLimiter) Close() error {
	close(rl.cleanupStopCh)
	<-rl.cleanupDone 
	return rl.client.Close()
}

func RateLimiterMiddleware(rl RateLimiter, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			allowed, info, err := rl.AllowRequest(r.Context(), key)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", DefaultMaxRequests))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", DefaultMaxRequests-info.CurrentCount))
			if info.ResetTime > 0 {
				w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", info.ResetTime))
			}
			if !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", rl.(*RedisRateLimiter).config.WindowSize/1000))
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
