# Runbook: Downstream SMTP Relay Down / Unreachable

**Severity**: SEV-1 (Critical) if mail delivery is blocked; SEV-2 if queued in dead-letter buffer.  
**Trigger**: Alert `RelayConnectionRefused`, `RelayAuthenticationFailed`, or `DeliveryDeliveryRateDrop`.

---

## 1. Symptoms & Initial Impact
- Legitimate cleaned inbound messages (verdict `FORWARD` or `WARN_AND_STRIP`) cannot be forwarded to recipient destination mailboxes.
- Webhook receiver responds with HTTP 200/202 to inbound provider (preventing sender drop), but delivery pipeline logs `[CRITICAL] Failed to relay message to SMTP host`.
- Outbound retry queue buffer begins building up in Redis/local spool.

---

## 2. Immediate Mitigation (First 5 Minutes)

### Step 1: Check Current Relay Connectivity from Within Pod
```bash
kubectl exec -it -n email-security-prod deployment/email-auth-gateway -- \
  python3 -c "
import socket
s = socket.socket()
s.settimeout(5.0)
try:
    s.connect(('$RELAY_HOST', int('$RELAY_PORT')))
    print('TCP Connection SUCCESS')
except Exception as e:
    print('TCP Connection FAILED:', e)
"
```

### Step 2: Switch to Backup SMTP Relay (If Primary is Down)
If AWS SES or primary MTA is experiencing an outage, switch to the standby secondary relay:

```bash
# Update ConfigMap with Secondary Relay Host
kubectl set env deployment/email-auth-gateway -n email-security-prod \
  RELAY_HOST="smtp-backup.us-west-2.amazonaws.com" \
  RELAY_PORT="587"
```

### Step 3: Emergency Tag-Only Mode (If No Relays Reachable)
If downstream destination MTA is offline and cannot accept mail, enable Tag-Only mode to avoid dropping or failing mail:
```bash
kubectl set env deployment/email-auth-gateway -n email-security-prod \
  ENABLE_TAG_ONLY_MODE="true"
```

---

## 3. Root Cause Investigation

### Check 1: Authentication & Credentials
Inspect recent authentication rejections in logs:
```bash
kubectl logs -n email-security-prod -l app.kubernetes.io/name=email-auth-gateway --tail=200 | grep -i -E "auth|535|authentication credentials invalid"
```
*Action*: If AWS SES SMTP credentials expired, rotate via Secrets Manager (see [Key Rotation Runbook](file:///home/drac/Documents/coding/email-auth-gateway/docs/runbooks/key_rotation.md)).

### Check 2: TLS Handshake / Certificate Issues
If `RELAY_START_TLS=true` is failing:
```bash
kubectl logs -n email-security-prod -l app.kubernetes.io/name=email-auth-gateway --tail=200 | grep -i -E "ssl|tls|certificate verify failed"
```
*Action*: Check certificate validity on relay server.

### Check 3: Provider Sending Rate / Quota Limit
If destination relay returns `421 4.7.0 Too many connections` or `454 4.7.0 Rate limit exceeded`:
*Action*: Check AWS SES / SendGrid sending quotas in AWS Console. Temporarily increase `rate_limit_window_seconds`.

---

## 4. Post-Recovery Verification

1. Verify TCP connectivity and successful relay transactions:
   ```bash
   kubectl logs -n email-security-prod -l app.kubernetes.io/name=email-auth-gateway --tail=50 | grep -i "Relayed message successfully"
   ```
2. Verify Redis / dead-letter queue is draining:
   ```bash
   kubectl exec -it -n email-security-prod deployment/email-auth-gateway -- \
     python3 -c "from delivery.queue import check_queue_depth; print('Pending Spool Depth:', check_queue_depth())"
   ```
3. Revert `ENABLE_TAG_ONLY_MODE="false"` if temporarily enabled.
