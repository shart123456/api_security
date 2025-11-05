API Security Standalone Tool
A standalone Python script that performs comprehensive API security testing, extracted from BBOT's api_security module.

Features
✅ OpenAPI/Swagger Discovery

Probes 18 common endpoints for API specifications
Parses and extracts all endpoints from discovered specs
Saves specifications to disk for analysis
✅ JWT Security Analysis

Detects "none" algorithm vulnerabilities
Identifies weak symmetric algorithms (HS256/384/512)
Checks for missing expiration claims
Finds sensitive data in JWT payloads
✅ Security Misconfiguration Detection

APIs with no security schemes
Unauthenticated endpoints
Unrestricted CORS headers
Missing security headers
✅ Exposed Secrets Detection

AWS Access Keys
GitHub Tokens
OpenAI API Keys
Google API Keys
Generic API keys
Installation
# Install required dependency
pip install aiohttp

# Or using requirements
pip install -r requirements.txt
Usage
Basic Scan
./api_security_standalone.py https://api.example.com
Scan with All Features
./api_security_standalone.py https://api.example.com \
  --test-endpoints \
  --json-report \
  --verbose
Scan with Custom Headers
./api_security_standalone.py https://api.example.com \
  -H "Authorization: Bearer token123" \
  -H "X-API-Key: mykey" \
  --test-endpoints
Custom Output Directory
./api_security_standalone.py https://api.example.com \
  -o ./my-scan-results \
  --json-report
Command-Line Options
Option	Description
target	Target URL to scan (required)
-v, --verbose	Enable verbose output
--test-jwt	Analyze JWT tokens (enabled by default)
--no-jwt	Disable JWT analysis
--test-endpoints	Test discovered API endpoints
--json-report	Save report as JSON file
--no-save-specs	Don't save discovered API specs
-o, --output-folder	Output folder (default: ./api-security-output)
-H, --header	Custom HTTP headers (can be used multiple times)
Examples
1. Quick Scan
Test a target for API spec exposure and JWT vulnerabilities:

./api_security_standalone.py https://api.target.com
2. Comprehensive Scan
Discover APIs, test endpoints, and save all results:

./api_security_standalone.py https://api.target.com \
  --test-endpoints \
  --json-report \
  --verbose \
  -o ./scan-results
3. Authenticated Scan
Scan with authentication headers:

./api_security_standalone.py https://api.target.com \
  -H "Authorization: Bearer eyJhbGc..." \
  --test-endpoints
4. Disable JWT Testing
Skip JWT analysis (faster scan):

./api_security_standalone.py https://api.target.com \
  --no-jwt
Output
Console Output
The tool provides color-coded output:

🔴 RED [VULN] - High severity vulnerabilities
🟡 YELLOW [!] - Medium severity findings
🟢 GREEN [+] - Successful discoveries
🔵 BLUE [*] - Informational messages
File Output
API Specifications (when --save-specs is enabled):

api-security-output/
└── api-specs/
    └── spec-api.example.com_openapi.json
JSON Report (when --json-report is enabled):

api-security-output/
└── report_20250104_143022.json
Report Structure
{
  "target": "https://api.example.com",
  "scan_time": "2025-01-04T14:30:22",
  "summary": {
    "vulnerabilities": 2,
    "findings": 5,
    "discovered_endpoints": 15
  },
  "vulnerabilities": [...],
  "findings": [...],
  "discovered_endpoints": [...]
}
Vulnerability Types Detected
High Severity
JWT_NONE_ALGORITHM - JWT with "none" algorithm
EXPOSED_API_KEY - Exposed API keys or tokens
Medium Severity
NO_SECURITY_SCHEMES - API with no security defined
UNAUTHENTICATED_ENDPOINT - Endpoints allowing unauth access
JWT_WEAK_ALGORITHM - Weak JWT algorithms
JWT_NO_EXPIRATION - JWTs without expiration
JWT_SENSITIVE_DATA - Sensitive data in JWT payload
Low Severity
UNRESTRICTED_CORS - Unrestricted CORS policy
API_SPEC_DISCOVERED - Exposed API specification
Differences from BBOT Module
Feature	BBOT Module	Standalone
Event System	Uses BBOT events	Direct function calls
Dependencies	BBOT framework	Only aiohttp
Output	BBOT events/findings	Console + JSON reports
Integration	Part of BBOT scan	Standalone tool
Rate Limiting	BBOT's rate limiting	None (manual throttling)
Deduplication	BBOT's dedup system	URL-based dedup
Security Considerations
⚠️ Authorization Required This tool performs active security testing. Only use it on:

Systems you own
Systems you have written permission to test
Bug bounty programs (following their scope)
⚠️ Rate Limiting The --test-endpoints option can generate many requests. Use responsibly to avoid:

Overwhelming target servers
Triggering rate limits
Creating noise in production systems
Troubleshooting
"aiohttp is required"
pip install aiohttp
SSL Certificate Errors
If you encounter SSL errors with self-signed certificates, you may need to modify the script to disable SSL verification (not recommended for production):

# In init_session method
connector = aiohttp.TCPConnector(ssl=False)
self.session = ClientSession(timeout=timeout, connector=connector)
No Results
Verify the target URL is accessible
Check if API specs use non-standard paths
Try --verbose for debugging output
Ensure you have network connectivity
Performance Tips
Faster scans: Disable endpoint testing

./api_security_standalone.py https://target.com
Targeted scans: Test specific endpoints manually

./api_security_standalone.py https://target.com/api/v1
Parallel execution: Run multiple instances for different subdomains

./api_security_standalone.py https://api1.target.com &
./api_security_standalone.py https://api2.target.com &
Integration
As a Python Module
from api_security_standalone import APISecurityScanner
import asyncio

async def scan():
    scanner = APISecurityScanner(
        "https://api.example.com",
        verbose=True,
        test_endpoints=True,
        json_report=True
    )
    await scanner.scan()

asyncio.run(scan())
In CI/CD Pipeline
# GitHub Actions example
- name: API Security Scan
  run: |
    python api_security_standalone.py ${{ env.API_URL }} \
      --json-report \
      -o ./security-reports

- name: Upload Results
  uses: actions/upload-artifact@v2
  with:
    name: api-security-report
    path: ./security-reports/
License
Same as BBOT - See main project for license details.

Credits
Based on BBOT's api_security module by shart123456. Converted to standalone tool for independent usage.
