"""
Redis and In-Memory Cache Manager for AgentTrust Framework.
Provides fast key-value caching for backend API endpoints, agent lookups, policy decisions,
and audit statistics, featuring automatic fallback to in-memory caching if Redis server is offline.
"""

import json
import logging
import os
import time
from functools import wraps
from typing import Any, Callable

logger = logging.getLogger("agenttrust.cache_manager")

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None  # type: ignore
    REDIS_AVAILABLE = False


class CacheManager:
    """
    Unified Cache Manager supporting Redis backend with an in-memory dictionary fallback.
    """

    def __init__(
        self,
        redis_host: str | None = None,
        redis_port: int | None = None,
        redis_db: int = 0,
        default_ttl: int = 300
    ):
        self.host = redis_host or os.environ.get("REDIS_HOST", "localhost")
        self.port = redis_port or int(os.environ.get("REDIS_PORT", 6379))
        self.db = redis_db
        self.default_ttl = default_ttl
        
        self._redis_client: Any | None = None
        self._in_memory_cache: dict[str, tuple[Any, float]] = {}
        self.is_redis_connected = False
        
        self._init_redis()

    def _init_redis(self) -> None:
        if not REDIS_AVAILABLE:
            logger.info("redis-py module not installed. Operating in in-memory fallback mode.")
            return

        try:
            client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                socket_connect_timeout=0.5,
                socket_timeout=0.5,
                decode_responses=True
            )
            # Test ping
            client.ping()
            self._redis_client = client
            self.is_redis_connected = True
            logger.info(f"Connected to Redis server at {self.host}:{self.port}")
        except Exception as e:
            self._redis_client = None
            self.is_redis_connected = False
            logger.info(f"Redis not available ({e}). Operating in low-latency in-memory fallback cache mode.")

    def get(self, key: str) -> Any | None:
        """Retrieves cached value by key."""
        if self.is_redis_connected and self._redis_client:
            try:
                val = self._redis_client.get(key)
                if val is not None:
                    return json.loads(val)
                return None
            except Exception as e:
                logger.warning(f"Redis GET failed for key {key}: {e}. Falling back to memory.")

        # In-memory fallback
        if key in self._in_memory_cache:
            data, expires_at = self._in_memory_cache[key]
            if expires_at == 0 or expires_at > time.time():
                return data
            else:
                del self._in_memory_cache[key]
        return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> bool:
        """Sets a key-value pair in cache with optional TTL (seconds)."""
        ttl_val = ttl if ttl is not None else self.default_ttl
        json_val = json.dumps(value)

        success = False
        if self.is_redis_connected and self._redis_client:
            try:
                if ttl_val > 0:
                    self._redis_client.setex(key, ttl_val, json_val)
                else:
                    self._redis_client.set(key, json_val)
                success = True
            except Exception as e:
                logger.warning(f"Redis SET failed for key {key}: {e}.")

        # Always maintain in-memory cache as secondary layer
        expires_at = (time.time() + ttl_val) if ttl_val != 0 else 0
        self._in_memory_cache[key] = (value, expires_at)
        return success or True

    def delete(self, key: str) -> bool:
        """Deletes a key from cache."""
        if self.is_redis_connected and self._redis_client:
            try:
                self._redis_client.delete(key)
            except Exception:
                pass

        if key in self._in_memory_cache:
            del self._in_memory_cache[key]
        return True

    def clear(self) -> bool:
        """Clears all cached entries."""
        if self.is_redis_connected and self._redis_client:
            try:
                self._redis_client.flushdb()
            except Exception:
                pass
        self._in_memory_cache.clear()
        return True


# Global cache instance
cache_manager = CacheManager()
