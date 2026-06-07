# micropki/ratelimit.py
import time
import threading
from collections import defaultdict

class TokenBucket:
    """Токен-бакет для одного клиента."""
    def __init__(self, rate: float, burst: int):
        self.rate = rate          # токенов в секунду
        self.burst = burst
        self.tokens = burst
        self.last_update = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

class RateLimiter:
    """Ограничитель частоты запросов по IP-адресу."""
    def __init__(self, rate_per_sec: float, burst: int):
        self.rate = rate_per_sec
        self.burst = burst
        self.buckets = defaultdict(lambda: TokenBucket(rate_per_sec, burst))
        self.lock = threading.Lock()

    def allow(self, client_ip: str) -> bool:
        # Если rate <= 0, ограничение отключено
        if self.rate <= 0:
            return True
        return self.buckets[client_ip].consume()