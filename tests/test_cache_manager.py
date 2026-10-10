"""
Tests for CacheManager (Redis & In-Memory Fallback)
"""

from cache_manager import CacheManager


def test_cache_manager_basic_get_set():
    cache = CacheManager(default_ttl=10)
    
    # Set and Get
    assert cache.set("test_key_1", {"foo": "bar"}, ttl=5) is True
    val = cache.get("test_key_1")
    assert val == {"foo": "bar"}

    # Delete
    cache.delete("test_key_1")
    assert cache.get("test_key_1") is None


def test_cache_manager_clear():
    cache = CacheManager()
    cache.set("k1", "v1")
    cache.set("k2", "v2")
    
    assert cache.get("k1") == "v1"
    assert cache.get("k2") == "v2"
    
    cache.clear()
    assert cache.get("k1") is None
    assert cache.get("k2") is None


def test_cache_manager_ttl_expiry():
    cache = CacheManager()
    cache.set("short_key", "expiring_val", ttl=-1) # Already expired
    assert cache.get("short_key") is None
