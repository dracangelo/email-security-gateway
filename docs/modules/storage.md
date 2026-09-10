# Module: storage — KV Abstraction

## Purpose

Provides a uniform `KeyValueStore` interface with two implementations: `InMemoryStore` (single-process, zero setup) and `RedisStore` (shared across instances). Backs rate limiting, webhook deduplication, and reputation/domain-age caching throughout the gateway.

---

## Module Structure

```
storage/
├── __init__.py        # Exports KeyValueStore, InMemoryStore, RedisStore
└── (implementations inside __init__.py)
```

---

## Interface

```python
class KeyValueStore(Protocol):
    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None: ...
    async def set_if_not_exists(self, key: str, value: str, ttl_seconds: int | None = None) -> bool: ...
    async def incr(self, key: str, ttl_seconds: int | None = None) -> int: ...
    async def delete(self, key: str) -> None: ...
    async def ping(self) -> bool: ...
```

---

## Implementations

### `InMemoryStore`

- Thread-safe in-process dictionary with TTL tracking
- Zero configuration required — used by default (`USE_REDIS=false`)
- **Limitation**: Per-process only. Rate limits and deduplication do not work correctly across multiple gateway instances with in-memory storage. Use Redis for any multi-replica deployment.

```python
from storage import InMemoryStore

store = InMemoryStore()
await store.set("key", "value", ttl_seconds=300)
result = await store.get("key")  # "value"
```

### `RedisStore`

- Wraps `redis.asyncio` client
- Supports `redis://`, `rediss://` (TLS), and Sentinel URLs
- Automatically falls back to `InMemoryStore` behavior if Redis is unreachable (with a warning log)

```python
from storage import RedisStore

store = RedisStore(redis_url="rediss://clustercfg.prod-redis:6379/0")
await store.set("rate:1.2.3.4", "1", ttl_seconds=60)
count = await store.incr("rate:1.2.3.4")  # atomic increment
```

---

## Usage Across the Gateway

| Use Case | Key Pattern | TTL | Store Operation |
|---|---|---|---|
| Webhook deduplication | `dedupe:<sha256_hash>` | 24 hours | `set_if_not_exists` |
| Rate limiting (per-IP counter) | `rate:<ip>` | 60 seconds | `incr` |
| URL reputation cache | `rep:<url_hash>` | 30 minutes | `get` / `set` |
| Domain age cache (RDAP) | `age:<domain>` | 6 hours | `get` / `set` |
| Sender baseline history | `baseline:<domain>` | 30 days | `get` / `set` |

---

## Redis Configuration

```bash
# Local dev (plain TCP)
REDIS_URL=redis://localhost:6379/0

# Production (TLS + AUTH)
REDIS_URL=rediss://:password@clustercfg.prod-redis.internal:6379/0

# AWS ElastiCache Cluster (TLS, no password, IAM auth via IRSA)
REDIS_URL=rediss://clustercfg.email-gateway.abc123.use1.cache.amazonaws.com:6379/0
```

In production, configure ElastiCache with:
- `transit-encryption-enabled = true`
- `at-rest-encryption-enabled = true`
- `maxmemory-policy = volatile-lru` (so old cache entries are purged automatically rather than blocking writes)

---

## Known Limitations

- **`incr()` non-atomicity**: `RedisStore.incr()` executes `INCR` followed by a separate `EXPIRE` call on initial creation. There is a small race window where the key could expire between the two calls. This is a deliberate tradeoff for testability against `fakeredis` (which doesn't support Lua/`EVAL`). Acceptable for rate limiting; revisit with a Lua script for stricter requirements.

- **Failover**: The `RedisStore` fails open to in-memory behavior on connection errors. This is logged but does not raise an exception — the gateway continues operating with degraded cross-instance coordination.

---

## Testing

Storage tests run identically against both `InMemoryStore` and `RedisStore` (via `fakeredis`) using parametrize:

```bash
python3 -m pytest tests/test_storage.py -v
```
