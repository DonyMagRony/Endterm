import time
import redis
import hashlib
import threading
from typing import Dict, Tuple, Optional, Callable, Any, Union
from functools import wraps

from fastapi import FastAPI, Request, Response, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


DEFAULT_MAX_REQUESTS = 100
DEFAULT_WINDOW_SIZE = 60 * 1000
DEFAULT_CACHE_TTL = 500
KEY_PREFIX = "ratelimit:"
SCRIPT_SHA_KEY = "ratelimit:script:sha"

SLIDING_WINDOW_SCRIPT = """
local current_time = redis.call('TIME')
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
"""


class RateLimitInfo:
    def __init__(self, allowed: bool, current_count: int, reset_time: int):
        self.allowed = allowed
        self.current_count = current_count
        self.reset_time = reset_time


class CacheEntry:
    def __init__(self, info: RateLimitInfo, expires_at: float):
        self.info = info
        self.expires_at = expires_at


class Config:
    def __init__(
            self,
            max_requests: int = DEFAULT_MAX_REQUESTS,
            window_size: int = DEFAULT_WINDOW_SIZE,
            cache_ttl: int = DEFAULT_CACHE_TTL,
            key_prefix: str = KEY_PREFIX
    ):
        self.max_requests = max_requests
        self.window_size = window_size
        self.cache_ttl = cache_ttl
        self.key_prefix = key_prefix


class RedisRateLimiter:
    def __init__(self, redis_addr: str, redis_pass: str = "", config: Optional[Config] = None):
        self.config = config or Config()

        # Parse Redis address
        host, port = redis_addr.split(':')
        self.client = redis.Redis(
            host=host,
            port=int(port),
            password=redis_pass,
            db=0,
            socket_timeout=5,
            socket_connect_timeout=5,
            max_connections=10
        )


        if not self.client.ping():
            raise ConnectionError("Failed to connect to Redis")

        self.script_sha = self._load_script()

        self.cache: Dict[str, CacheEntry] = {}
        self.cache_lock = threading.RLock()


        self.cleanup_stop = threading.Event()
        self.cleanup_thread = threading.Thread(target=self._cleanup_cache)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()

    def _load_script(self) -> str:
        sha = self.client.get(SCRIPT_SHA_KEY)
        if sha:
            if self.client.script_exists(sha)[0]:
                return sha.decode('utf-8')
        sha = self.client.script_load(SLIDING_WINDOW_SCRIPT)
        self.client.set(SCRIPT_SHA_KEY, sha)
        return sha.decode('utf-8')

    def _cleanup_cache(self):
        while not self.cleanup_stop.is_set():
            time.sleep(self.config.cache_ttl / 1000)
            now = time.time()
            with self.cache_lock:
                keys_to_delete = [
                    key for key, entry in self.cache.items()
                    if entry.expires_at < now
                ]
                for key in keys_to_delete:
                    del self.cache[key]

    def allow_request(self, key: str) -> Tuple[bool, RateLimitInfo]:
        redis_key = f"{self.config.key_prefix}{key}"

        with self.cache_lock:
            if key in self.cache and self.cache[key].expires_at > time.time():
                return self.cache[key].info.allowed, self.cache[key].info

        try:

            result = self.client.evalsha(
                self.script_sha,
                1,
                redis_key,
                self.config.max_requests,
                self.config.window_size
            )

            allowed = bool(result[0])
            count = int(result[1])
            reset_time = int(result[2]) if result[2] != b'0' else 0

            info = RateLimitInfo(allowed, count, reset_time)

            with self.cache_lock:
                self.cache[key] = CacheEntry(
                    info=info,
                    expires_at=time.time() + (self.config.cache_ttl / 1000)
                )

            return allowed, info

        except redis.exceptions.NoScriptError:
            self.script_sha = self._load_script()
            result = self.client.evalsha(
                self.script_sha,
                1,
                redis_key,
                self.config.max_requests,
                self.config.window_size
            )

            allowed = bool(result[0])
            count = int(result[1])
            reset_time = int(result[2]) if result[2] != b'0' else 0

            info = RateLimitInfo(allowed, count, reset_time)

            with self.cache_lock:
                self.cache[key] = CacheEntry(
                    info=info,
                    expires_at=time.time() + (self.config.cache_ttl / 1000)
                )

            return allowed, info

    def close(self):
        self.cleanup_stop.set()
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=1.0)
        self.client.close()


def generate_key(request: Request) -> str:
    ip = get_client_ip(request)
    key = f"{ip}:{request.url.path}"
    hasher = hashlib.sha256()
    hasher.update(key.encode('utf-8'))
    return hasher.hexdigest()


def get_client_ip(request: Request) -> str:
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        ips = x_forwarded_for.split(',')
        if ips:
            return ips[0].strip()

    x_real_ip = request.headers.get('X-Real-IP')
    if x_real_ip:
        return x_real_ip

    client_host = request.client.host if request.client else None
    if client_host:
        return client_host
    return "0.0.0.0"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
            self,
            app: ASGIApp,
            limiter: RedisRateLimiter,
            key_func: Callable[[Request], str] = generate_key
    ):
        super().__init__(app)
        self.limiter = limiter
        self.key_func = key_func

    async def dispatch(self, request: Request, call_next):
        key = self.key_func(request)
        allowed, info = self.limiter.allow_request(key)
        headers = {
            'X-RateLimit-Limit': str(self.limiter.config.max_requests),
            'X-RateLimit-Remaining': str(self.limiter.config.max_requests - info.current_count),
        }
        if info.reset_time > 0:
            headers['X-RateLimit-Reset'] = str(info.reset_time)
        if not allowed:
            headers['Retry-After'] = str(self.limiter.config.window_size // 1000)
            return JSONResponse(
                status_code=429,
                content={"error": "Too Many Requests"},
                headers=headers
            )
        response = await call_next(request)
        for header_name, header_value in headers.items():
            response.headers[header_name] = header_value

        return response


def rate_limit_dependency(
        limiter: RedisRateLimiter,
        key_func: Callable[[Request], str] = generate_key
):
    def _rate_limit(request: Request):
        key = key_func(request)
        allowed, info = limiter.allow_request(key)

        if not allowed:
            headers = {
                'X-RateLimit-Limit': str(limiter.config.max_requests),
                'X-RateLimit-Remaining': '0',
                'Retry-After': str(limiter.config.window_size // 1000)
            }

            if info.reset_time > 0:
                headers['X-RateLimit-Reset'] = str(info.reset_time)

            raise RateLimitExceeded(headers)
        request.state.rate_limit_info = info

        return request

    return _rate_limit


class RateLimitExceeded(Exception):
    def __init__(self, headers: Dict[str, str]):
        self.headers = headers


def create_rate_limiter_middleware(app: FastAPI, limiter: RedisRateLimiter):
    app.add_middleware(RateLimitMiddleware, limiter=limiter)
    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
        return JSONResponse(
            status_code=429,
            content={"error": "Too Many Requests"},
            headers=exc.headers
        )