# Runbook: Secret & Encryption Key Rotation

**Severity**: SEV-4 (Scheduled 90-Day Routine) / SEV-1 (Emergency Leak Remediation)  
**Scope**: `WEBHOOK_SHARED_SECRET`, `ADMIN_SHARED_SECRET`, and `RAW_MAIL_ENCRYPTION_KEY`.

---

## 1. Zero-Downtime Webhook Secret Rotation (`WEBHOOK_SHARED_SECRET`)

The webhook shared secret is a path segment in the SendGrid Inbound Parse URL (e.g. `https://gateway.email.example.com/webhook/{SECRET}`).

### Routine Rotation Procedure:
1. **Generate a New Unguessable Secret**:
   ```bash
   NEW_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
   echo "New Webhook Secret: $NEW_SECRET"
   ```

2. **Update Application Secret with Dual-Accept Support (Grace Period)**:
   The gateway supports comma-separated secrets during transition windows so both old and new webhook URLs are accepted.
   ```bash
   aws secretsmanager update-secret \
     --secret-id email-gateway-prod-secrets \
     --secret-string "{\"WEBHOOK_SHARED_SECRET\": \"$CURRENT_SECRET,$NEW_SECRET\", \"ADMIN_SHARED_SECRET\": \"$ADMIN_SECRET\"}"
   ```

3. **Trigger Rolling Deployment**:
   ```bash
   kubectl rollout restart deployment/email-auth-gateway -n email-security-prod
   kubectl rollout status deployment/email-auth-gateway -n email-security-prod
   ```

4. **Update SendGrid / Provider Inbound Parse Webhook URL**:
   In SendGrid Settings -> Inbound Parse -> Update Host Webhook URL to `https://gateway.email.example.com/webhook/$NEW_SECRET`.

5. **Verify Inbound Traffic on New Secret**:
   Monitor logs to ensure new webhook URL is receiving traffic:
   ```bash
   kubectl logs -n email-security-prod -l app.kubernetes.io/name=email-auth-gateway --tail=100 | grep -i "Inbound webhook received"
   ```

6. **Retire Old Secret**:
   Update Secrets Manager to contain only `$NEW_SECRET` and restart deployment.

---

## 2. Admin Bearer Token Rotation (`ADMIN_SHARED_SECRET`)

1. **Generate New Admin Token**:
   ```bash
   NEW_ADMIN_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
   ```

2. **Update Secrets Manager**:
   ```bash
   aws secretsmanager update-secret \
     --secret-id email-gateway-prod-secrets \
     --secret-string "{\"ADMIN_SHARED_SECRET\": \"$NEW_ADMIN_SECRET\"}"
   ```

3. **Restart Pods**:
   ```bash
   kubectl rollout restart deployment/email-auth-gateway -n email-security-prod
   ```

4. **Update Internal Admin Tooling / SIEM API Callers**:
   Update HTTP `Authorization: Bearer <NEW_ADMIN_SECRET>` in automated scripts, Slack bots, or admin UI configurations.

---

## 3. Raw Mail Fernet Encryption Key Rotation (`RAW_MAIL_ENCRYPTION_KEY`)

When rotating the symmetric Fernet encryption key used for raw mail files:

1. **Generate New Fernet Key**:
   ```bash
   NEW_FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
   ```

2. **Run Batch Re-Encryption Script**:
   Use the built-in migration utility to re-encrypt existing stored `.eml` files from the old key to the new key:
   ```bash
   kubectl exec -it -n email-security-prod deployment/email-auth-gateway -- \
     python3 -c "
   from security.key_rotation import reencrypt_directory
   reencrypt_directory('/app/quarantine/raw', old_key='$OLD_FERNET_KEY', new_key='$NEW_FERNET_KEY')
   print('Batch re-encryption complete!')
   "
   ```

3. **Update Secret & Restart Gateway**:
   ```bash
   aws secretsmanager update-secret \
     --secret-id email-gateway-prod-secrets \
     --secret-string "{\"RAW_MAIL_ENCRYPTION_KEY\": \"$NEW_FERNET_KEY\"}"
   kubectl rollout restart deployment/email-auth-gateway -n email-security-prod
   ```
