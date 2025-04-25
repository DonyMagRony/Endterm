import uvicorn
import logging
import signal
import sys
from fastapi import FastAPI, Depends, Request

from rate import (
    RedisRateLimiter,
    Config,
    create_rate_limiter_middleware,
    rate_limit_dependency,
    generate_key
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Rate Limited API", version="1.0.0")
limiter = None
try:
    limiter = RedisRateLimiter(
        redis_addr="localhost:6379",
        config=Config(
            max_requests=100,
            window_size=60000
        )
    )
    logger.info("Rate limiter initialized successfully")

    create_rate_limiter_middleware(app, limiter)

except Exception as e:
    logger.error(f"Failed to initialize rate limiter: {e}")
    sys.exit(1)



def custom_rate_limit():
    if not limiter:
        return None
    return rate_limit_dependency(limiter)


@app.get("/api")
async def api_endpoint():
    return {"message": "Hello, API"}


@app.get("/api/users")
async def users_endpoint():
    return {"users": ["user1", "user2", "user3"]}


@app.get("/api/sensitive", dependencies=[Depends(custom_rate_limit())])
async def sensitive_endpoint(request: Request):
    info = getattr(request.state, "rate_limit_info", None)
    remaining = 0
    if info:
        remaining = limiter.config.max_requests - info.current_count

    return {
        "message": "This is a sensitive endpoint",
        "rate_limit_remaining": remaining
    }


@app.get("/health")
async def health_check():
    return {"status": "ok"}


def signal_handler(sig, frame):
    logger.info("Shutting down server...")
    if limiter:
        limiter.close()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    try:
        logger.info("Starting server on port 8000")
        uvicorn.run(
            "app:app",
            host="0.0.0.0",
            port=8000,
            log_level="info",
            reload=False
        )
    finally:
        if limiter:
            limiter.close()
        logger.info("Server stopped")