# Runbook: Quarantine & Raw Mail Disk Space Full

**Severity**: SEV-2 (High)  
**Trigger**: Alert `DiskSpaceUtilizationWarning` (> 80%) or `DiskSpaceUtilizationCritical` (> 90%) on `/app/quarantine` or `/app/logs`.

---

## 1. Symptoms & Initial Impact
- Storage subsystem logs `[ERROR] No space left on device` when saving quarantined malicious `.eml` files or raw mail audit logs.
- New quarantined messages cannot be written to disk; admin release API may fail to locate files.

---

## 2. Immediate Emergency Cleanup (Free Space in 2 Minutes)

### Step 1: Check Current Disk Usage on Pods
```bash
kubectl exec -it -n email-security-prod deployment/email-auth-gateway -- df -h /app/quarantine /app/logs
```

### Step 2: Emergency Prune of Quarantined Files Older Than 14 Days
Run the pruning command directly inside the container to purge oldest expired quarantine files:
```bash
kubectl exec -it -n email-security-prod deployment/email-auth-gateway -- \
  find /app/quarantine -type f -name "*.eml" -mtime +14 -delete
```

### Step 3: Archive & Offload Raw Mail to S3 Bucket
Offload raw audit emails to cold S3 storage and remove local copies:
```bash
kubectl exec -it -n email-security-prod deployment/email-auth-gateway -- \
  python3 -c "
import os, glob
from storage.s3_sync import sync_to_s3
synced_count = sync_to_s3('/app/quarantine/raw', '$RAW_MAIL_S3_BUCKET', delete_after_sync=True)
print(f'Successfully offloaded {synced_count} files to S3')
"
```

---

## 3. Persistent Volume Expansion (Zero Downtime)

If organic mail volume growth requires larger PersistentVolumes, expand the Kubernetes PVC:

### Step 1: Update PVC Requested Storage Size
```bash
kubectl patch pvc email-auth-gateway-quarantine-pvc -n email-security-prod \
  -p '{"spec":{"resources":{"requests":{"storage":"500Gi"}}}}'
```

### Step 2: Monitor Volume Expansion Status
AWS EBS `gp3` volumes expand dynamically in-place without pod restarts:
```bash
kubectl get pvc -n email-security-prod email-auth-gateway-quarantine-pvc -w
```
Wait until status shows `FileSystemResizeSuccessful`.

---

## 4. Long-Term Prevention & Retention Tuning

1. Update Terraform retention variables (`raw_mail_retention_days` and `quarantine_retention_days` in `terraform/environments/prod.tfvars`).
2. Verify Kubernetes cron job or automatic lifecycle daemon is actively running daily pruning:
   ```bash
   kubectl get cronjobs -n email-security-prod
   ```
3. Check Prometheus alert thresholds in Grafana.
