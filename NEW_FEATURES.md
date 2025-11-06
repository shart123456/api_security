# New Security Checks Added to API Scanner

This document outlines the new security checks that have been added to the API security scanner to address OWASP API Security Top 10 issues.

## Summary of Added Checks

### 1. JWT Security Enhancements

#### JWT Expired Token Check (API2:2023 - HIGH)
- **Type**: `JWT_EXPIRED`
- **Detection**: Checks if JWT tokens have expired by comparing the `exp` claim with current time
- **Location**: api_security.py:358-371

#### JWT Audience Cross-Service Relay Attack (API2:2023 - HIGH)
- **Type**: `JWT_MISSING_AUDIENCE`
- **Detection**: Checks if JWT tokens are missing the `aud` (audience) claim
- **Impact**: Tokens without audience claims can be reused across different services
- **Location**: api_security.py:373-381

### 2. Secrets Leak Detection (API8:2023 - HIGH)
- **Type**: `SECRETS_LEAK`
- **Detection**: Comprehensive pattern matching for various types of secrets:
  - Database connection strings (MongoDB, PostgreSQL, MySQL, Redis)
  - Private keys (RSA, EC, OpenSSH)
  - Passwords in configuration files
  - OAuth/Client secrets
  - JWT/Token secrets
  - Environment variables (DATABASE_URL, SECRET_KEY, etc.)
  - Encryption keys
  - AWS Secret Access Keys
  - Slack tokens
  - Stripe live keys
  - Twilio API keys
  - Discord bot tokens
- **Location**: api_security.py:633-701

### 3. Directory Listing Detection (API8:2023 - MEDIUM)
- **Type**: `DIRECTORY_LISTING`
- **Detection**: Identifies common directory listing patterns:
  - "Index of /" in title or headers
  - "Directory listing for" messages
  - Parent directory links
  - Apache-style directory listings
  - Table-based file listings
- **Location**: api_security.py:603-631

### 4. Private IP Disclosure (API8:2023 - LOW)
- **Type**: `PRIVATE_IP_DISCLOSURE`
- **Detection**: Identifies private IP addresses in responses:
  - 10.x.x.x (Class A private)
  - 172.16-31.x.x (Class B private)
  - 192.168.x.x (Class C private)
  - 127.x.x.x (Loopback)
- **Location**: api_security.py:617-661

### 5. SSL/TLS Security Checks

#### SSL Certificate Not Trusted (API8:2023 - MEDIUM)
- **Type**: `SSL_CERT_NOT_TRUSTED`
- **Detection**: Catches SSL certificate errors during requests
- **Indicators**: Invalid certificates, expired certificates, untrusted CA
- **Location**: api_security.py:118-126

#### SSL Not Enforced (API8:2023 - MEDIUM)
- **Type**: `SSL_NOT_ENFORCED`
- **Detection**: Checks if URLs are using insecure HTTP instead of HTTPS
- **Location**: api_security.py:664-675

### 6. Directory Traversal Detection (API10:2023 - HIGH)
- **Type**: `DIRECTORY_TRAVERSAL`
- **Detection**: Identifies directory traversal indicators:
  - Path traversal sequences (../)
  - Windows absolute path disclosure
  - Unix absolute path disclosure
  - File operation errors with traversal patterns
- **Location**: api_security.py:677-714

### 7. Broken Object Level Authorization - BOLA (API1:2023 - MEDIUM)
- **Type**: `POTENTIAL_BOLA`
- **Detection**: Analyzes OpenAPI specs for endpoints with:
  - ID parameters in the path ({id}, {user_id}, {uuid}, etc.)
  - Missing or disabled security on GET/PUT/PATCH/DELETE methods
- **Impact**: Endpoints that access/modify resources by ID without proper authorization
- **Location**: api_security.py:310-341

### 8. Private Field Access (API1:2023 - MEDIUM)
- **Type**: `PRIVATE_FIELD_ACCESS`
- **Detection**: Recursively scans JSON responses for sensitive field names:
  - password, passwd, pwd
  - secret, token, api_key
  - private_key, access_token, refresh_token
  - auth_token, session_token, csrf_token
  - salt, hash, credit_card, ssn
  - internal_id, system_id, db_password
  - encryption_key, private, confidential
- **Location**: api_security.py:703-766

### 9. Mass Assignment Vulnerability (API1:2023 - MEDIUM)
- **Type**: `POTENTIAL_MASS_ASSIGNMENT`
- **Detection**: Analyzes OpenAPI specs for endpoints that:
  - Accept input (POST/PUT/PATCH) without request schema
  - Have schemas that allow additionalProperties
- **Impact**: Attackers may be able to modify unintended object properties
- **Location**: api_security.py:262-308

## Updated Test Flow

The scanner now performs these checks in the following order:

1. **Before Request**: SSL enforcement check
2. **During Request**: SSL certificate validation
3. **After Response**:
   - JWT token extraction and analysis (including expiration and audience checks)
   - Security headers validation
   - API key exposure detection
   - Secrets leak detection
   - Directory listing detection
   - Private IP disclosure
   - Directory traversal detection
   - Private field access detection

4. **During OpenAPI Spec Analysis**:
   - Mass assignment risk analysis
   - BOLA risk analysis
   - Unauthenticated endpoint detection

## Coverage Summary

The scanner now supports the following OWASP API Security issues:

| Name | OWASP | Severity | Status |
|------|-------|----------|--------|
| Broken Object Level Authorization (BOLA) | API1:2023 | Medium | ✅ |
| Private Field Access | API1:2023 | Medium | ✅ |
| Mass Assignment | API1:2023 | Medium | ✅ |
| Authentication Bypass | API2:2023 | High | ✅ |
| JWT none algorithm | API2:2023 | High | ✅ |
| JWT blank secret | API2:2023 | High | ✅ |
| JWT weak secret | API2:2023 | High | ✅ |
| JWT Audience cross service relay attack | API2:2023 | High | ✅ |
| JWT Null Signature | API2:2023 | High | ✅ |
| JWT Algorithm Confusion | API2:2023 | High | ✅ |
| JWT Signature not verified | API2:2023 | High | ✅ |
| JWT Expired | API2:2023 | High | ✅ |
| Discoverable OpenAPI | API7:2023 | Info | ✅ |
| Discoverable GraphQL Endpoint | API7:2023 | Info | ✅ |
| GraphQL Introspection Enabled | API8:2023 | Info | ✅ |
| Secrets Leak | API8:2023 | High | ✅ |
| Directory Listing | API8:2023 | Medium | ✅ |
| Private IP Disclosure | API8:2023 | Low | ✅ |
| Not HTTP-only Cookie | API8:2023 | Info | ✅ |
| Not Secure Cookie | API8:2023 | Info | ✅ |
| Not SameSite Cookie | API8:2023 | Info | ✅ |
| No Cookie expiration | API8:2023 | Info | ✅ |
| No CORS Headers | API8:2023 | Info | ✅ |
| Permissive CORS Headers | API8:2023 | Info | ✅ |
| HTTP Method Override Enabled | API8:2023 | Info - High | ✅ |
| X-Content-Type-Options Header Not Set | API8:2023 | Info | ✅ |
| X-Frame-Options Header Not Set | API8:2023 | Info | ✅ |
| CSP Header Not Set | API8:2023 | Info | ✅ |
| CSP Frame Ancestors Not Set | API8:2023 | Info | ✅ |
| HSTS Header Not Set | API8:2023 | Info | ✅ |
| HTTP TRACE Method Enabled | API8:2023 | Info | ✅ |
| HTTP TRACK Method Enabled | API8:2023 | Info | ✅ |
| Server Signature Leak | API8:2023 | Info | ✅ |
| SSL Certificate Not Trusted | API8:2023 | Medium | ✅ |
| SSL Not Enforced | API8:2023 | Medium | ✅ |
| Directory Traversal | API10:2023 | High | ✅ |

## Usage

Run the scanner as before:

```bash
# Basic scan
python3 api_security.py https://api.example.com

# Full scan with all options
python3 api_security.py https://api.example.com --test-endpoints --json-report --verbose

# Scan with authentication
python3 api_security.py https://api.example.com -H "Authorization: Bearer YOUR_TOKEN"
```

The new checks will automatically run as part of the standard scanning process.
