# Runbook: ClamAV Daemon Unreachable / Malware Scan Timeout

**Severity**: SEV-2 (High) — Malware attachment inspection degraded.  
**Trigger**: Alert `ClamAVConnectionRefused`, `ClamAVScanTimeout`, or `AntivirusCircuitBreakerOpen`.

---

## 1. Symptoms & Initial Impact
- Gateway logs: `[WARNING] ClamAV clamd daemon unreachable at ${CLAMD_HOST}:${CLAMD_PORT}. Circuit breaker opened.`
- Inbound messages with attachments skip local antimalware scanning and rely solely on static heuristic checks (macro detection, dangerous double-extensions, zero-width characters) and third-party threat intel (VirusTotal hash lookups).
- Mail delivery is NOT blocked (fail-open for operational availability), but security protection is operating in a degraded tier.

---

## 2. Immediate Diagnostic Steps

### Step 1: Check ClamAV Daemon Status
```bash
# Check if ClamAV pod / daemon is running
kubectl get pods -n email-security-prod -l app.kubernetes.io/name=clamav

# View ClamAV daemon logs
kubectl logs -n email-security-prod -l app.kubernetes.io/name=clamav --tail=100
```

### Step 2: Test ClamAV TCP PING Command
```bash
kubectl exec -it -n email-security-prod deployment/email-auth-gateway -- \
  python3 -c "
import socket
s = socket.socket()
s.settimeout(3.0)
try:
    s.connect(('$CLAMD_HOST', int('$CLAMD_PORT')))
    s.sendall(b'zPING\0')
    resp = s.recv(1024)
    print('ClamAV Ping Response:', resp)
except Exception as e:
    print('ClamAV Ping FAILED:', e)
"
```

---

## 3. Resolution Procedures

### Scenario A: ClamAV OOMKilled (Out of Memory)
ClamAV signature databases (main.cvd, daily.cvd) typically require at least 1.5–2.5 GB of RAM. If memory limit is exceeded, Linux kernel will OOM-kill the daemon.
1. Check pod termination reasons:
   ```bash
   kubectl describe pod -n email-security-prod -l app.kubernetes.io/name=clamav | grep -i "OOMKilled"
   ```
2. Increase ClamAV memory request & limit to `4Gi`:
   ```bash
   kubectl set resources deployment/clamav -n email-security-prod --limits=memory=4Gi --requests=memory=2Gi
   ```

### Scenario B: Database Corrupted or Stale Signatures
If ClamAV crashes during database reload:
1. Trigger freshclam manual signature update:
   ```bash
   kubectl exec -it -n email-security-prod deployment/clamav -- freshclam
   ```
2. Restart the daemon:
   ```bash
   kubectl rollout restart deployment/clamav -n email-security-prod
   ```

### Scenario C: Emergency Fallback / Bypass
If ClamAV cannot be restored immediately and you wish to explicitly silence alerts while relying on cloud Threat Intel:
```bash
kubectl set env deployment/email-auth-gateway -n email-security-prod CLAMD_HOST=""
```
*(Remember to restore `CLAMD_HOST` once ClamAV is fixed!)*

---

## 4. Post-Recovery Verification

1. Verify ClamAV responds with `PONG`:
   ```bash
   kubectl exec -it -n email-security-prod deployment/email-auth-gateway -- \
     python3 -c "import socket; s = socket.create_connection(('$CLAMD_HOST', int('$CLAMD_PORT'))); s.sendall(b'zPING\0'); print(s.recv(1024))"
   ```
2. Confirm gateway circuit breaker resets to CLOSED and logs clean scans:
   ```bash
   kubectl logs -n email-security-prod -l app.kubernetes.io/name=email-auth-gateway --tail=50 | grep -i "ClamAV scan clean"
   ```
