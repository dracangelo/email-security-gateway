# Module: multi_tenancy — Tenant Isolation

## Purpose

Provides strict data isolation between tenants: isolated quarantine directories with per-tenant Fernet encryption keys, per-tenant rate limiting, tenant-scoped admin APIs, and an MSP (Managed Service Provider) view for managing multiple customer tenants.

---

## Module Structure

| File | Responsibility |
|---|---|
| `tenant_manager.py` | Tenant registry; create, retrieve, list tenants |
| `isolation.py` | `TenantIsolatedQuarantine` — per-tenant quarantine storage |
| `rate_limiter.py` | `TenantRateLimiter` — per-tenant rate limit enforcement |
| `msp_view.py` | `MSPAdminView` — aggregate view across all tenants |
| `models.py` | `Tenant` data model |

---

## Tenant Model

```python
@dataclass
class Tenant:
    tenant_id: str
    name: str
    domain: str
    quarantine_dir: str          # Isolated directory path
    encryption_key: str          # Per-tenant Fernet key
    warn_threshold: int          # Decision engine threshold override
    quarantine_threshold: int    # Decision engine threshold override
    rate_limit_max_requests: int
    created_at: datetime
```

---

## Tenant Isolation (`isolation.py`)

`TenantIsolatedQuarantine` ensures:

1. **Isolated storage paths**: Each tenant's quarantine files are in `<QUARANTINE_DIR>/<tenant_id>/`, not shared with other tenants.
2. **Per-tenant encryption keys**: Each tenant's messages are encrypted with that tenant's Fernet key. Tenant A's encryption key cannot decrypt Tenant B's quarantined mail.
3. **Scoped list/get/release operations**: All quarantine management API calls are scoped to the requesting tenant — cross-tenant access is impossible by construction.

```python
from multi_tenancy import TenantIsolatedQuarantine, TenantManager

manager = TenantManager()
q = TenantIsolatedQuarantine(base_quarantine_dir="/quarantine", tenant_manager=manager)

# Store for tenant A — uses tenant A's key, stored in /quarantine/tenant_a/
await q.store(tenant_id="tenant_a", message_id="msg_1", raw_message=bytes(...), metadata={})

# Tenant B listing cannot see tenant A's items
items = await q.list_pending(tenant_id="tenant_b")  # empty
```

---

## Per-Tenant Rate Limiting (`rate_limiter.py`)

`TenantRateLimiter` wraps the base `RateLimiter` with a tenant-aware key:

```
rate key = "rate:<tenant_id>:<client_ip>"
```

This means Tenant A and Tenant B's rate limits are independent — one tenant flooding the gateway does not affect another.

The `TenantRateLimiter` falls back to the base rate limiter for unregistered tenants:

```python
from multi_tenancy import TenantRateLimiter

limiter = TenantRateLimiter(fallback_rate_limiter=base_limiter)
await limiter.check(tenant_id="tenant_a", client_ip="1.2.3.4")
```

---

## MSP Admin View (`msp_view.py`)

`MSPAdminView` provides a cross-tenant aggregate view for MSP operators:

```python
from multi_tenancy import MSPAdminView

view = MSPAdminView(tenant_manager=manager, isolated_quarantine=q)

# List all tenants
tenants = view.list_tenants()

# Aggregate quarantine dashboard across all tenants
pending = await view.list_all_pending()

# List pending for a specific managed tenant
tenant_pending = await view.list_pending_for_tenant("tenant_acme")
```

MSP operations are subject to additional audit logging with the MSP operator's identity.

---

## Threat Model Considerations

- **Tenant data isolation** is a **Critical** control in the STRIDE threat model (Information Disclosure — `Tenant A accessing Tenant B's quarantined mail`). The `TenantIsolatedQuarantine` addresses this with separate storage paths and separate encryption keys.
- Per-tenant encryption key rotation is supported — rotating one tenant's key does not affect other tenants.
- The MSP view exposes cross-tenant data only to authenticated operators with the `msp_admin` RBAC role.

---

## Onboarding a New Tenant

```bash
# Via Admin API
curl -X POST http://localhost:8000/admin/tenants \
  -H "Authorization: Bearer $ADMIN_SHARED_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant_acme",
    "name": "Acme Corp",
    "domain": "acme.com",
    "warn_threshold": 25,
    "quarantine_threshold": 60,
    "rate_limit_max_requests": 200
  }'
```

A Fernet encryption key is automatically generated and stored securely for the new tenant.
