# Security Documentation
## Marks Moderation System - Security Analysis

---

## 1. Encoding Techniques Implementation

### 1.1 Base64 Encoding

Our application uses **Base64 encoding** in the following scenarios:

| Use Case | Location | Purpose |
|----------|----------|---------|
| AES Ciphertext Storage | `encryption_service.py` | Store encrypted data as readable strings |
| Digital Signatures | `signature_service.py` | Encode RSA signatures for transmission |
| OTP Hashing | `otp_service.py` | Hash storage format |

#### Example Implementation:
```python
# From encryption_service.py
encrypted = base64.b64encode(iv + ciphertext).decode('utf-8')

# From signature_service.py
signature = base64.b64encode(signature_bytes).decode('utf-8')
```

---

## 2. Security Levels & Risks

### 2.1 Encoding Security Levels

| Level | Technique | Security | Use Case |
|-------|-----------|----------|----------|
| **Level 0** (No Security) | Base64 | ❌ None - easily reversible | Data format transformation only |
| **Level 1** (Obfuscation) | URL Encoding, Hex | ❌ Minimal | Character escaping |
| **Level 2** (Integrity) | SHA-256 Hash | ✅ One-way | Password verification |
| **Level 3** (Confidentiality) | AES-256-CBC | ✅ Strong | Sensitive data encryption |
| **Level 4** (Non-repudiation) | RSA Digital Signature | ✅ Very Strong | Approval authenticity |

### 2.2 Critical Understanding

> ⚠️ **IMPORTANT**: Base64 is NOT encryption!

| Property | Encoding (Base64) | Encryption (AES) |
|----------|-------------------|------------------|
| Reversible | ✅ By anyone | ✅ Only with key |
| Key Required | ❌ No | ✅ Yes |
| Security | ❌ None | ✅ Confidentiality |
| Purpose | Data format conversion | Data protection |

### 2.3 Risk Analysis

| Risk Level | Description | Example in Our System |
|------------|-------------|----------------------|
| **HIGH** | Transmitting sensitive data with only Base64 | ❌ We encrypt BEFORE encoding |
| **MEDIUM** | Weak encryption keys | ✅ We use 256-bit AES keys |
| **LOW** | Encoding format exposure | ✅ Acceptable - format visibility doesn't compromise security |

---

## 3. Possible Attacks & Countermeasures

### 3.1 Authentication Attacks

| Attack | Description | Our Countermeasure |
|--------|-------------|-------------------|
| **Brute Force** | Repeated password guessing | Rate limiting (5 attempts/min), Account lockout |
| **Credential Stuffing** | Using leaked passwords | NIST password policy, common password blocklist |
| **Session Hijacking** | Stealing JWT tokens | Short token expiry, HTTPS enforcement |
| **Replay Attack** | Reusing captured OTPs | OTP single-use flag, 5-minute expiry |

### 3.2 Encoding/Encryption Attacks

| Attack | Description | Our Countermeasure |
|--------|-------------|-------------------|
| **Base64 Decode** | Decoding encoded data to reveal information | Sensitive data is encrypted BEFORE Base64 encoding |
| **Known Plaintext** | Guessing encryption from patterns | Random IV for each encryption operation |
| **Key Extraction** | Extracting encryption key | Keys stored in environment variables, not in code |
| **Padding Oracle** | Exploiting decryption error messages | Generic error responses |

### 3.3 Access Control Attacks

| Attack | Description | Our Countermeasure |
|--------|-------------|-------------------|
| **Privilege Escalation** | Accessing higher role functions | JWT role claims verified on each request |
| **IDOR** | Accessing other users' data | Department-based access checks |
| **Token Manipulation** | Modifying JWT claims | JWT signature verification |

### 3.4 Digital Signature Attacks

| Attack | Description | Our Countermeasure |
|--------|-------------|-------------------|
| **Signature Forgery** | Creating fake approvals | RSA-2048 with SHA-256 (cryptographically secure) |
| **Key Compromise** | Stealing private key | Per-user key pairs, encrypted storage |
| **Man-in-the-Middle** | Intercepting and modifying data | Signature includes timestamp and approver ID |

---

## 4. Security Implementation Summary

### 4.1 Defense in Depth

```
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 1: Network                         │
│                    HTTPS/TLS Encryption                     │
├─────────────────────────────────────────────────────────────┤
│                    LAYER 2: Authentication                  │
│                    Password + OTP (MFA)                     │
├─────────────────────────────────────────────────────────────┤
│                    LAYER 3: Authorization                   │
│                    Role-based Access Control                │
├─────────────────────────────────────────────────────────────┤
│                    LAYER 4: Data Protection                 │
│                    AES-256 Encryption + Digital Signatures  │
├─────────────────────────────────────────────────────────────┤
│                    LAYER 5: Audit                           │
│                    Complete Activity Logging                │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 OWASP Top 10 Coverage

| OWASP Risk | Status | Implementation |
|------------|--------|----------------|
| A01: Broken Access Control | ✅ Mitigated | Role-based middleware, JWT validation |
| A02: Cryptographic Failures | ✅ Mitigated | AES-256, bcrypt, RSA-2048 |
| A03: Injection | ✅ Mitigated | MongoDB ODM, parameterized queries |
| A04: Insecure Design | ✅ Mitigated | Defense in depth architecture |
| A05: Security Misconfiguration | ✅ Mitigated | Environment-based config |
| A07: Auth Failures | ✅ Mitigated | MFA, rate limiting, lockout |

---

## 5. Conclusion

This Marks Moderation System implements a comprehensive security architecture that:

1. **Protects user credentials** with salted bcrypt hashing
2. **Ensures authentication integrity** with multi-factor authentication (Password + OTP)
3. **Enforces access control** through role-based permissions (Faculty, HOD, Admin)
4. **Secures sensitive data** with AES-256-CBC encryption
5. **Guarantees non-repudiation** with RSA digital signatures for mark approvals
6. **Maintains auditability** with comprehensive logging

The use of Base64 encoding is appropriate and secure as it is only used for **data format transformation** of already-encrypted or signed content, not as a security mechanism itself.

---

*Document Version: 1.0*  
*Last Updated: February 2026*
