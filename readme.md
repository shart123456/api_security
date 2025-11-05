# 🧠 API Security Standalone Tool

A **standalone Python script** that performs comprehensive API security testing — extracted from **BBOT's `api_security` module**.

---

## 🚀 Features

### ✅ OpenAPI / Swagger Discovery
- Probes **18 common endpoints** for API specifications  
- Parses and extracts all endpoints from discovered specs  
- Saves specifications to disk for offline analysis  

### ✅ JWT Security Analysis
- Detects `"none"` algorithm vulnerabilities  
- Identifies weak symmetric algorithms (`HS256`, `HS384`, `HS512`)  
- Checks for **missing expiration claims**  
- Finds **sensitive data** in JWT payloads  

### ✅ Security Misconfiguration Detection
- APIs with **no security schemes**  
- **Unauthenticated endpoints**  
- **Unrestricted CORS** headers  
- **Missing security headers**  

### ✅ Exposed Secrets Detection
- AWS Access Keys  
- GitHub Tokens  
- OpenAI API Keys  
- Google API Keys  
- Generic API keys  

---

## ⚙️ Installation

```bash
# Install core dependency
pip install aiohttp

# Or install all dependencies
pip install -r requirements.txt



🧪 Examples
1. Quick Scan

Test for API spec exposure and JWT vulnerabilities:

./api_security_standalone.py https://api.target.com

2. Comprehensive Scan

Discover APIs, test endpoints, and save results:

./api_security_standalone.py https://api.target.com \
  --test-endpoints \
  --json-report \
  --verbose \
  -o ./scan-results

3. Authenticated Scan
./api_security_standalone.py https://api.target.com \
  -H "Authorization: Bearer eyJhbGc..." \
  --test-endpoints

4. Disable JWT Testing
./api_security_standalone.py https://api.target.com --no-jwt
🧪 Examples
1. Quick Scan

Test for API spec exposure and JWT vulnerabilities:

./api_security_standalone.py https://api.target.com

2. Comprehensive Scan

Discover APIs, test endpoints, and save results:

./api_security_standalone.py https://api.target.com \
  --test-endpoints \
  --json-report \
  --verbose \
  -o ./scan-results

3. Authenticated Scan
./api_security_standalone.py https://api.target.com \
  -H "Authorization: Bearer eyJhbGc..." \
  --test-endpoints

4. Disable JWT Testing
./api_security_standalone.py https://api.target.com --no-jwt
