# Deployment: Kubernetes

## Overview

The gateway ships with a complete set of Kubernetes manifests in `k8s/`. This guide covers deploying to a production Kubernetes cluster with high availability, autoscaling, and security hardening.

---

## Manifest Inventory

| File | Kind | Description |
|---|---|---|
| `k8s/deployment.yaml` | `Deployment` | Gateway pods with resource limits, liveness/readiness probes |
| `k8s/service.yaml` | `Service` | ClusterIP service exposing port 8000 |
| `k8s/ingress.yaml` | `Ingress` | TLS ingress with cert-manager annotation |
| `k8s/configmap.yaml` | `ConfigMap` | Non-secret environment configuration |
| `k8s/secret.yaml` | `Secret` | Placeholder for sealed secrets / ESO |
| `k8s/hpa.yaml` | `HorizontalPodAutoscaler` | Autoscaling 5–25 replicas |
| `k8s/pdb.yaml` | `PodDisruptionBudget` | Minimum 2 pods available during maintenance |
| `k8s/networkpolicy.yaml` | `NetworkPolicy` | Restricts egress/ingress traffic |
| `k8s/kustomization.yaml` | `Kustomization` | Kustomize entry point |

---

## Prerequisites

- Kubernetes 1.28+
- `kubectl` configured for your cluster
- `cert-manager` installed (for TLS certificate issuance)
- Redis (AWS ElastiCache recommended for production)
- ClamAV daemon service

---

## Deployment

### 1. Configure Secrets

> **Never commit real secrets to source control.** Use ExternalSecretsOperator, Sealed Secrets, or the CSI Secret Store Driver.

With ExternalSecretsOperator (recommended):

```yaml
# k8s/external-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: email-auth-gateway
  namespace: email-security-prod
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: email-auth-gateway
  data:
    - secretKey: WEBHOOK_SHARED_SECRET
      remoteRef:
        key: prod/email-gateway
        property: webhook_shared_secret
    - secretKey: RAW_MAIL_ENCRYPTION_KEY
      remoteRef:
        key: prod/email-gateway
        property: encryption_key
    - secretKey: ADMIN_SHARED_SECRET
      remoteRef:
        key: prod/email-gateway
        property: admin_secret
```

### 2. Apply with Kustomize

```bash
# Staging
kubectl apply -k k8s/ -n email-security-staging

# Production
kubectl apply -k k8s/ -n email-security-prod
```

### 3. Verify Deployment

```bash
# Check pod status
kubectl get pods -n email-security-prod -l app.kubernetes.io/name=email-auth-gateway

# Check readiness
kubectl exec -it deployment/email-auth-gateway -n email-security-prod -- \
  curl -s http://localhost:8000/readyz

# Check HPA status
kubectl get hpa -n email-security-prod

# View logs
kubectl logs -n email-security-prod -l app.kubernetes.io/name=email-auth-gateway --tail=100 -f
```

---

## Horizontal Pod Autoscaler (HPA)

```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
spec:
  minReplicas: 5
  maxReplicas: 25
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 60
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 70
```

The HPA scales up when CPU exceeds 60% average across all pods. With 25 maximum replicas, the gateway can handle significant traffic spikes without manual intervention.

---

## Pod Disruption Budget (PDB)

```yaml
# k8s/pdb.yaml
spec:
  minAvailable: 2
```

Ensures at least 2 gateway pods remain available during voluntary disruptions (node drains, rolling updates). Prevents a single `kubectl drain` from taking down the entire gateway.

---

## Network Policy

The `NetworkPolicy` restricts traffic to only expected paths:

**Ingress allowed:**
- From the Ingress controller (port 8000) — inbound webhooks and health checks
- From internal admin clients (port 8000) — admin API

**Egress allowed:**
- Redis (port 6379) — rate limiting, caching, dedup
- ClamAV (port 3310) — malware scanning
- SMTP relay (port 587) — outbound mail relay
- External HTTPS (port 443) — VirusTotal, RDAP, Google Safe Browsing
- DNS (port 53) — SPF/DKIM/DMARC resolution

**Egress denied:**
- All other internal cluster services (prevents SSRF from phishing URLs in the body)

---

## Resource Limits

```yaml
resources:
  requests:
    cpu: "250m"
    memory: "512Mi"
  limits:
    cpu: "2000m"
    memory: "2Gi"
```

ClamAV requires separate resourcing — allocate at least 2.5 Gi of memory for signature databases:

```yaml
# clamav deployment
resources:
  requests:
    memory: "2Gi"
  limits:
    memory: "4Gi"
```

---

## Liveness & Readiness Probes

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 30
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /readyz
    port: 8000
  initialDelaySeconds: 15
  periodSeconds: 10
  failureThreshold: 2
```

The `readyz` probe returns `503` if Redis is unreachable (when `USE_REDIS=true`), triggering automatic removal from the load balancer until connectivity is restored.

---

## Rolling Update Strategy

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 2
    maxUnavailable: 0
```

Zero-downtime rolling updates: new pods start before old ones terminate. The `PodDisruptionBudget` ensures minimum availability is maintained during the transition.

---

## Ingress & TLS

```yaml
# k8s/ingress.yaml
annotations:
  cert-manager.io/cluster-issuer: "letsencrypt-prod"
  nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
    - hosts:
        - gateway.email.yourcompany.com
      secretName: email-gateway-tls
  rules:
    - host: gateway.email.yourcompany.com
      http:
        paths:
          - path: /
            pathType: Prefix
```

Place a WAF (AWS WAF, Cloudflare) in front of the Ingress for additional DDoS protection.

---

## Namespace & RBAC

```bash
# Create production namespace
kubectl create namespace email-security-prod

# Apply resource quotas
kubectl apply -f - <<EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: email-security-quota
  namespace: email-security-prod
spec:
  hard:
    pods: "50"
    requests.cpu: "20"
    requests.memory: "40Gi"
    limits.memory: "100Gi"
EOF
```

---

## Multi-Region / DR Considerations

For disaster recovery:

1. Deploy to two regions with identical Kubernetes clusters
2. Use a global load balancer (AWS Global Accelerator, Cloudflare) for failover
3. Redis: Use ElastiCache Global Datastore for multi-region replication
4. Quarantine storage: Use S3 with cross-region replication enabled
5. Audit logs: Ship to a centralized aggregator accessible from both regions
