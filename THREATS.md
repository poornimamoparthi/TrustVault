# TrustVault – Security Threat Model

## 1. Unauthorized Access
**Threat:** An unauthenticated or unauthorized user may try to view or download confidential documents.
**Mitigation:** Require authentication and verify document permissions on protected operations.

## 2. Weak Password Security
**Threat:** Attackers may try to obtain user passwords.
**Mitigation:** Hash passwords securely before storing them and validate registration and login inputs.

## 3. Cross-Site Request Forgery (CSRF)
**Threat:** A malicious website may attempt to trigger actions using an authenticated session.
**Mitigation:** Use CSRF tokens for state-changing requests and configure session cookies appropriately.

## 4. Broken Access Control
**Threat:** A user may try to access another user's documents or perform actions beyond their role.
**Mitigation:** Enforce server-side authorization checks for document operations and permission changes.

## 5. Malicious File Uploads
**Threat:** An attacker may upload unexpected or excessively large files.
**Mitigation:** Restrict allowed file types and enforce an upload size limit. Additional file-content scanning may be required for production.

## 6. Session Theft or Misuse
**Threat:** A stolen or improperly managed session may allow unauthorized actions.
**Mitigation:** Use HTTP-only session cookies, HTTPS in production, and clear sessions during authentication transitions.

## 7. Audit Log Tampering
**Threat:** An attacker may attempt to alter activity records.
**Mitigation:** Link audit entries using SHA-256 hashes. Hash chaining can help detect changes but does not by itself prevent tampering.

## 8. Sensitive Configuration Exposure
**Threat:** Secret keys or credentials may be exposed through source control or logs.
**Mitigation:** Store secrets in environment variables and never commit real credentials to the repository.

## 9. Database Loss or Corruption
**Threat:** Application data may be lost or corrupted, especially when using temporary deployment storage.
**Mitigation:** Configure persistent storage and regular backups before relying on the application for confidential documents.

## 10. Testing and Limitations
These are identified risks and intended mitigations, not proof that every control has been fully tested. Before production use, test role-based access, document ownership, access revocation, unauthorized downloads, file validation, and audit logging. Configure persistent storage, backups, and production monitoring as needed.
