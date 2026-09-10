# Deployment: Helm Chart

## Overview

The `helm/email-auth-gateway/` chart packages the full gateway deployment for reproducible, parameterized installation into Kubernetes. Suitable for both internal deployment and multi-tenant SaaS delivery.

---

## Chart Structure

```
helm/email-auth-gateway/
├── Chart.yaml           # Chart metadata (name, version, appVersion)
├── values.yaml          # Default configurable values
├── templates/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── ingress.yaml
│   ├── configmap.yaml
│   ├── hpa.yaml
│   ├── pdb.yaml
│   ├── networkpolicy.yaml
│   └── _helpers.tpl
```

---

## Installation

### Add chart (if published to a Helm registry)

```bash
helm repo add email-security https://charts.your-org.com
helm repo update
```

### Install from local source

```bash
# Dry run first
helm upgrade --install email-auth-gateway ./helm/email-auth-gateway \
  --namespace email-security-prod \
  --create-namespace \
  --dry-run --debug

# Install
helm upgrade --install email-auth-gateway ./helm/email-auth-gateway \
  --namespace email-security-prod \
  --create-namespace \
  --values ./helm/email-auth-gateway/values.yaml \
  --values ./helm/email-auth-gateway/values.prod.yaml \
  --set secrets.webhookSharedSecret="$WEBHOOK_SHARED_SECRET" \
  --set secrets.rawMailEncryptionKey="$RAW_MAIL_ENCRYPTION_KEY" \
  --set secrets.adminSharedSecret="$ADMIN_SHARED_SECRET"
```

> **Security**: Never commit secrets to `values.yaml` files or pass them via `--set` in CI logs. Use `--set-string` with a secrets manager or Helm Secrets plugin.

---

## Key Values

### Image

```yaml
image:
  repository: your-registry/email-auth-gateway
  tag: "1.0.0"          # appVersion from Chart.yaml
  pullPolicy: IfNotPresent
```

### Replica & Autoscaling

```yaml
replicaCount: 5

autoscaling:
  enabled: true
  minReplicas: 5
  maxReplicas: 25
  targetCPUUtilizationPercentage: 60
  targetMemoryUtilizationPercentage: 70
```

### Redis

```yaml
redis:
  enabled: true           # Deploy bundled Redis (dev only)
  external:
    url: ""               # Set for production ElastiCache
```

### Ingress

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  hosts:
    - host: gateway.email.yourcompany.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: email-gateway-tls
      hosts:
        - gateway.email.yourcompany.com
```

### Security & Encryption

```yaml
config:
  enableTagOnlyMode: false
  warnThreshold: 30
  quarantineThreshold: 70
  rateLimitMaxRequests: 120
  clusterBreakerResetTimeoutSeconds: 30

secrets:
  # These should come from an external secrets manager, not values.yaml
  webhookSharedSecret: ""
  rawMailEncryptionKey: ""
  adminSharedSecret: ""
  vtApiKey: ""
  gsbApiKey: ""
```

### Resources

```yaml
resources:
  requests:
    cpu: "250m"
    memory: "512Mi"
  limits:
    cpu: "2000m"
    memory: "2Gi"
```

---

## Environment Overrides

Use separate values files per environment:

```bash
# Staging deployment
helm upgrade --install email-auth-gateway ./helm/email-auth-gateway \
  --namespace email-security-staging \
  -f values.yaml \
  -f values.staging.yaml

# Production deployment
helm upgrade --install email-auth-gateway ./helm/email-auth-gateway \
  --namespace email-security-prod \
  -f values.yaml \
  -f values.prod.yaml
```

Example `values.staging.yaml`:
```yaml
config:
  enableTagOnlyMode: true    # Never drop mail in staging
  logLevel: DEBUG

ingress:
  hosts:
    - host: gateway.staging.yourcompany.com
```

Example `values.prod.yaml`:
```yaml
config:
  enableTagOnlyMode: false
  logLevel: WARN

autoscaling:
  minReplicas: 5
  maxReplicas: 25

ingress:
  hosts:
    - host: gateway.email.yourcompany.com
```

---

## Upgrades & Rollbacks

```bash
# Upgrade to new chart version
helm upgrade email-auth-gateway ./helm/email-auth-gateway \
  --namespace email-security-prod \
  -f values.prod.yaml

# Check rollout status
kubectl rollout status deployment/email-auth-gateway -n email-security-prod

# Rollback if needed
helm rollback email-auth-gateway 1 --namespace email-security-prod

# View release history
helm history email-auth-gateway --namespace email-security-prod
```

---

## Uninstall

```bash
helm uninstall email-auth-gateway --namespace email-security-prod
```

> **Warning**: This deletes all Kubernetes resources created by the chart, but does **not** delete PersistentVolumeClaims (quarantine storage). Retained intentionally to prevent accidental data loss.
