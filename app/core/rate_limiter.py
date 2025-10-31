import time
import asyncio
from collections import defaultdict
from core.config import LOGIN_RATE_LIMIT, LOGIN_RATE_PERIOD, UPLOAD_RATE_LIMIT, UPLOAD_RATE_PERIOD

class RateLimiter:
    def __init__(self, limit: int, period: int):
        self.limit = limit
        self.period = period
        self.attempts = defaultdict(list)
        self.lock = asyncio.Lock()

    async def is_allowed(self, key: str) -> bool:
        now = time.time()
        async with self.lock:
            timestamps = self.attempts[key]

            self.attempts[key] = [t for t in timestamps if now - t < self.period]

            if len(self.attempts[key]) >= self.limit:
                return False

            self.attempts[key].append(now)
            return True

    async def cleanup(self):
        now = time.time()
        async with self.lock:
            to_delete = [
                key for key, timestamps in self.attempts.items()
                if all(now - t > self.period for t in timestamps)
            ]
            for key in to_delete:
                del self.attempts[key]

login_rate_limiter = RateLimiter(limit=LOGIN_RATE_LIMIT, period=LOGIN_RATE_PERIOD)
upload_rate_limiter = RateLimiter(limit=UPLOAD_RATE_LIMIT, period=UPLOAD_RATE_PERIOD)