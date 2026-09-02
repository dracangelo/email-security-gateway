# Runbook: Redis Cluster Down / Unreachable

**Severity**: SEV-2 (High) — Gateway operates in degraded in-memory fallback mode.  
**Trigger**: Alert `RedisConnectionError`, `RedisTimeout`, or `StorageFallbackActivated`.

---

## 1. Symptoms & Initial Impact
- Gateway pods log: `[WARNING] Redis connection failed. Falling back to local in-memory store`.
- **Degraded Mode Behavior**:
  - Webhook deduplication falls back to local pod memory (pod restarts or multi-pod load may allow duplicate webhook processing if SendGrid retries).
  - Rate limiting operates on a per-pod basis instead of a cluster-wide token bucket.
  - Domain reputation & RDAP lookups are cached locally in memory rather than shared across pods.
- **Mail Flow is NOT Halted**: The system is designed with built-in resilience and fails open to in-memory storage so inbound mail is never dropped due to Redis outages.

---

## 2. Immediate Diagnostic Steps

### Step 1: Check Redis Cluster Health in AWS Console / CLI
```bash
aws elasticache describe-replication-groups \
  --replication-group-id email-gateway-prod-redis \
  --query "ReplicationGroups[0].Status"
```

### Step 2: Test Redis Ping from Gateway Pod
```bash
kubectl exec -it -n email-security-prod deployment/email-auth-gateway -- \
  python3 -c "
import redis
r = redis.Redis.from_url('$REDIS_URL', socket_timeout=3.0)
try:
    print('Redis Ping:', r.ping())
except Exception as e:
    print('Redis Ping FAILED:', e)
"
```

---

## 3. Resolution Procedures

### Scenario A: ElastiCache Primary Node Failed
If primary node is unresponsive, trigger an immediate manual failover to replica:
```bash
aws elasticache test-failover \
  --replication-group-id email-gateway-prod-redis \
  --node-group-id 0001
```

### Scenario B: Redis Out of Memory (OOM)
If Redis is refusing writes with `OOM command not allowed when used memory > 'maxmemory'`:
1. Check maxmemory policy:
   ```bash
   aws elasticache describe-cache-parameters \
     --cache-parameter-group-name email-gateway-prod-redis-params \
     --query "Parameters[?ParameterName=='maxmemory-policy'].ParameterValue"
   ```
2. Ensure eviction policy is set to `volatile-lru` or `allkeys-lru` (so old cache entries are automatically purged).
3. If memory is exhausted by deduplication keys, clear expired keys or vertically scale the instance type:
   ```bash
   aws elasticache modify-replication-group \
     --replication-group-id email-gateway-prod-redis \
     --cache-node-type cache.m7g.xlarge \
     --apply-immediately
   ```

### Scenario C: Network Security Group / Subnet Misconfiguration
Verify security group allows TCP port 6379 from the EKS worker nodes:
```bash
aws ec2 describe-security-group-rules \
  --filters "Name=group-id,Values=$REDIS_SG_ID"
```

---

## 4. Post-Recovery Verification

1. Verify gateway pods automatically reconnect to Redis:
   ```bash
   kubectl logs -n email-security-prod -l app.kubernetes.io/name=email-auth-gateway --tail=100 | grep -i "Connected to Redis"
   ```
2. Trigger Cache Warmer script to pre-populate threat intelligence and VIP baselines:
   ```bash
   kubectl exec -it -n email-security-prod deployment/email-auth-gateway -- \
     python3 -m content_analysis.cache_warmer
   ```
3. Confirm `/healthz` reports Redis as healthy.
