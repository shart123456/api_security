#!/usr/bin/env python3
"""
Standalone API Security Testing Tool

Performs comprehensive API security testing including:
- OpenAPI/Swagger specification discovery
- JWT token analysis
- Security misconfiguration detection
- Exposed API key detection
- Endpoint enumeration
"""

import json
import base64
import re
import asyncio
import argparse
from pathlib import Path
from urllib.parse import urljoin, urlparse
from datetime import datetime
from typing import List, Dict, Set, Optional
import sys

try:
    import aiohttp
    from aiohttp import ClientSession, ClientTimeout
except ImportError:
    print("Error: aiohttp is required. Install it with: pip install aiohttp")
    sys.exit(1)


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


class APISecurityScanner:
    """Main API security scanner class"""

    DEFAULT_OPENAPI_ENDPOINTS = [
        "/openapi.json",
        "/swagger.json",
        "/api/openapi.json",
        "/api/swagger.json",
        "/api/v1/openapi.json",
        "/api/v1/swagger.json",
        "/api/v2/openapi.json",
        "/api/v2/swagger.json",
        "/api/v3/openapi.json",
        "/api/v3/swagger.json",
        "/swagger/v1/swagger.json",
        "/api-docs",
        "/api/docs",
        "/docs",
        "/v1/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/.well-known/openapi.json",
    ]

    def __init__(self, target_url: str, **options):
        self.target_url = target_url.rstrip("/")
        self.options = options
        self.processed_urls: Set[str] = set()
        self.jwt_tokens: Set[int] = set()
        self.findings: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        self.discovered_endpoints: List[str] = []
        self.session: Optional[ClientSession] = None

    def log_info(self, msg: str):
        """Log informational message"""
        if self.options.get('verbose', False):
            print(f"{Colors.BLUE}[*]{Colors.END} {msg}")

    def log_success(self, msg: str):
        """Log success message"""
        print(f"{Colors.GREEN}[+]{Colors.END} {msg}")

    def log_warning(self, msg: str):
        """Log warning message"""
        print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")

    def log_error(self, msg: str):
        """Log error message"""
        print(f"{Colors.RED}[-]{Colors.END} {msg}")

    def log_vuln(self, msg: str):
        """Log vulnerability"""
        print(f"{Colors.RED}{Colors.BOLD}[VULN]{Colors.END} {msg}")

    async def init_session(self):
        """Initialize aiohttp session"""
        timeout = ClientTimeout(total=30)
        self.session = ClientSession(timeout=timeout)

    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()

    async def request(self, url: str, method: str = "GET") -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request"""
        try:
            headers = self.options.get('headers', {})
            async with self.session.request(method, url, headers=headers, allow_redirects=True) as response:
                # Read response body
                response._body = await response.read()
                return response
        except Exception as e:
            self.log_info(f"Request failed for {url}: {e}")
            return None

    async def discover_api_spec(self, spec_url: str):
        """Try to discover and parse OpenAPI/Swagger specifications"""
        self.log_info(f"Checking for API spec at {spec_url}")

        response = await self.request(spec_url)

        if not response or response.status != 200:
            return

        # Try to parse as JSON
        try:
            spec_data = json.loads(response._body)
        except json.JSONDecodeError:
            return

        # Check if it looks like an OpenAPI/Swagger spec
        is_openapi = "openapi" in spec_data or "swagger" in spec_data

        if not is_openapi:
            return

        self.log_success(f"Discovered API specification at {spec_url}")

        # Save the spec if configured
        if self.options.get('save_specs', True):
            await self.save_api_spec(spec_url, spec_data)

        # Add finding
        self.findings.append({
            "type": "API_SPEC_DISCOVERED",
            "url": spec_url,
            "description": "OpenAPI/Swagger specification discovered",
            "severity": "INFO"
        })

        # Parse and analyze the spec
        await self.analyze_api_spec(spec_url, spec_data)

    async def save_api_spec(self, spec_url: str, spec_data: Dict):
        """Save API specification to file"""
        output_dir = Path(self.options.get('output_folder', './api-security-output')) / "api-specs"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create filename from URL
        parsed = urlparse(spec_url)
        filename = f"spec-{parsed.netloc}{parsed.path.replace('/', '_')}.json"
        filepath = output_dir / filename

        with open(filepath, "w") as f:
            json.dump(spec_data, f, indent=2)

        self.log_info(f"Saved API spec to {filepath}")

    async def analyze_api_spec(self, spec_url: str, spec_data: Dict):
        """Analyze OpenAPI spec for endpoints and security issues"""

        # Extract version
        spec_version = spec_data.get("openapi") or spec_data.get("swagger", "unknown")
        self.log_info(f"Analyzing API spec version {spec_version}")

        # Get base URL
        parsed_spec_url = urlparse(spec_url)
        base_url = f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"

        # Extract server URLs if present (OpenAPI 3.x)
        servers = spec_data.get("servers", [])
        if servers and isinstance(servers, list):
            for server in servers:
                server_url = server.get("url", "")
                if server_url.startswith("http"):
                    base_url = server_url
                    break

        # Extract basePath (Swagger 2.0)
        base_path = spec_data.get("basePath", "")
        if base_path:
            base_url = base_url.rstrip("/") + base_path

        # Check for security definitions/schemes
        security_schemes = spec_data.get("securityDefinitions") or spec_data.get("components", {}).get("securitySchemes", {})

        if not security_schemes:
            # No security defined - potential vulnerability
            self.log_warning(f"API specification has no security schemes defined")
            self.findings.append({
                "type": "NO_SECURITY_SCHEMES",
                "url": spec_url,
                "description": "API specification has no security schemes defined - endpoints may be unprotected",
                "severity": "MEDIUM"
            })

        # Parse paths and collect endpoints
        paths = spec_data.get("paths", {})
        endpoint_count = 0

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            # Construct full endpoint URL
            endpoint_url = urljoin(base_url, path.lstrip("/"))
            self.discovered_endpoints.append(endpoint_url)
            endpoint_count += 1

            # Check for security requirements on each method
            for method in ["get", "post", "put", "patch", "delete"]:
                if method in methods:
                    operation = methods[method]
                    if isinstance(operation, dict):
                        # Check if this specific operation has security
                        op_security = operation.get("security")

                        # If security is explicitly set to empty array, it's unauthenticated
                        if op_security == []:
                            self.log_warning(f"Unauthenticated endpoint: {method.upper()} {endpoint_url}")
                            self.findings.append({
                                "type": "UNAUTHENTICATED_ENDPOINT",
                                "url": endpoint_url,
                                "method": method.upper(),
                                "description": f"API endpoint {method.upper()} {path} explicitly allows unauthenticated access",
                                "severity": "MEDIUM"
                            })

        self.log_success(f"Discovered {endpoint_count} API endpoints from spec")

    async def extract_and_analyze_jwt(self, url: str, response: aiohttp.ClientResponse):
        """Extract JWT tokens from HTTP responses and analyze them"""
        if not self.options.get('test_jwt', True):
            return

        # Get response body and headers
        try:
            resp_body = response._body.decode('utf-8', errors='ignore')
        except:
            resp_body = ""

        resp_headers = dict(response.headers)

        # Common JWT locations
        jwt_candidates = []

        # Check Authorization header
        auth_header = resp_headers.get("authorization", "") or resp_headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            jwt_candidates.append(auth_header[7:])

        # Check for JWTs in body (common in login responses)
        # JWT pattern: xxx.yyy.zzz where each part is base64url
        jwt_pattern = r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

        if resp_body:
            # Look for JSON with common token field names
            try:
                body_json = json.loads(resp_body)
                for key in ["token", "access_token", "id_token", "refresh_token", "jwt"]:
                    if key in body_json:
                        token = body_json[key]
                        if isinstance(token, str) and re.match(jwt_pattern, token):
                            jwt_candidates.append(token)
            except:
                # Not JSON, try regex on body
                matches = re.finditer(jwt_pattern, resp_body)
                for match in matches:
                    jwt_candidates.append(match.group(0))

        # Analyze each JWT candidate
        for token in jwt_candidates:
            # Skip if already analyzed
            token_hash = hash(token)
            if token_hash in self.jwt_tokens:
                continue
            self.jwt_tokens.add(token_hash)

            await self.analyze_jwt_token(token, url)

    async def analyze_jwt_token(self, token: str, url: str):
        """Analyze a JWT token for security vulnerabilities"""

        try:
            # Split JWT into parts
            parts = token.split(".")
            if len(parts) != 3:
                return  # Not a valid JWT structure

            header_b64, payload_b64, signature = parts

            # Decode header (add padding if needed)
            header_b64_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
            try:
                header_json = base64.urlsafe_b64decode(header_b64_padded).decode("utf-8")
                header = json.loads(header_json)
            except:
                return  # Can't decode header

            # Decode payload
            payload_b64_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
            try:
                payload_json = base64.urlsafe_b64decode(payload_b64_padded).decode("utf-8")
                payload = json.loads(payload_json)
            except:
                return  # Can't decode payload

            alg = header.get("alg", "").lower()
            self.log_success(f"Analyzing JWT token: alg={alg}")

            # Check for 'none' algorithm vulnerability
            if alg == "none":
                self.log_vuln('JWT token uses "none" algorithm - signature can be bypassed')
                self.vulnerabilities.append({
                    "type": "JWT_NONE_ALGORITHM",
                    "url": url,
                    "description": 'JWT token uses "none" algorithm - signature can be bypassed',
                    "severity": "HIGH",
                    "algorithm": alg
                })

            # Check for weak algorithms
            weak_algs = ["hs256", "hs384", "hs512"]
            if alg in weak_algs:
                self.log_warning(f"JWT token uses potentially weak symmetric algorithm: {alg.upper()}")
                self.findings.append({
                    "type": "JWT_WEAK_ALGORITHM",
                    "url": url,
                    "description": f"JWT token uses potentially weak symmetric algorithm: {alg.upper()}",
                    "severity": "MEDIUM",
                    "algorithm": alg
                })

            # Check for missing expiration
            if "exp" not in payload:
                self.log_warning("JWT token does not have an expiration claim (exp)")
                self.findings.append({
                    "type": "JWT_NO_EXPIRATION",
                    "url": url,
                    "description": "JWT token does not have an expiration claim (exp) - tokens never expire",
                    "severity": "MEDIUM"
                })

            # Check for sensitive data in payload
            sensitive_keys = ["password", "secret", "api_key", "apikey", "private_key", "credit_card", "ssn"]
            for key in payload.keys():
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    self.log_warning(f"JWT token contains potentially sensitive data in claim: {key}")
                    self.findings.append({
                        "type": "JWT_SENSITIVE_DATA",
                        "url": url,
                        "description": f"JWT token contains potentially sensitive data in claim: {key}",
                        "severity": "MEDIUM",
                        "claim": key
                    })

        except Exception as e:
            self.log_info(f"Error analyzing JWT token: {e}")

    async def check_api_security_headers(self, url: str, response: aiohttp.ClientResponse):
        """Check for missing API security headers"""

        resp_headers = dict(response.headers)

        # Check if this looks like an API response (JSON content-type)
        content_type = resp_headers.get("content-type", "") or resp_headers.get("Content-Type", "")
        if "json" not in content_type.lower():
            return

        # Check for CORS misconfigurations
        cors_origin = resp_headers.get("access-control-allow-origin", "") or resp_headers.get("Access-Control-Allow-Origin", "")
        if cors_origin == "*":
            self.log_warning(f"API endpoint allows unrestricted CORS: {url}")
            self.findings.append({
                "type": "UNRESTRICTED_CORS",
                "url": url,
                "description": "API endpoint allows unrestricted CORS (Access-Control-Allow-Origin: *)",
                "severity": "LOW"
            })

        # Check for missing security headers
        if not resp_headers.get("x-content-type-options") and not resp_headers.get("X-Content-Type-Options"):
            self.log_info(f"Missing X-Content-Type-Options header at {url}")

        if not resp_headers.get("x-frame-options") and not resp_headers.get("X-Frame-Options"):
            self.log_info(f"Missing X-Frame-Options header at {url}")

    async def detect_exposed_api_keys(self, url: str, response: aiohttp.ClientResponse):
        """Detect exposed API keys in responses"""

        try:
            resp_body = response._body.decode('utf-8', errors='ignore')
        except:
            return

        if not resp_body:
            return

        # Common API key patterns
        api_key_patterns = [
            (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Generic API Key"),
            (r'["\']?apikey["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Generic API Key"),
            (r'sk-[A-Za-z0-9]{20,}', "OpenAI API Key"),
            (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token"),
            (r'gho_[A-Za-z0-9]{36}', "GitHub OAuth Token"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'AIza[0-9A-Za-z_\-]{35}', "Google API Key"),
        ]

        for pattern, key_type in api_key_patterns:
            matches = re.finditer(pattern, resp_body, re.IGNORECASE)
            for match in matches:
                key_value = match.group(1) if match.groups() else match.group(0)

                # Truncate for display
                display_key = key_value[:30] + "..." if len(key_value) > 30 else key_value

                self.log_vuln(f"Exposed {key_type} found: {display_key}")
                self.vulnerabilities.append({
                    "type": "EXPOSED_API_KEY",
                    "url": url,
                    "description": f"Exposed {key_type} found in API response",
                    "severity": "HIGH",
                    "key_type": key_type,
                    "key_preview": display_key
                })

    async def test_endpoint(self, url: str):
        """Test a single endpoint for security issues"""
        if url in self.processed_urls:
            return

        self.processed_urls.add(url)
        self.log_info(f"Testing endpoint: {url}")

        response = await self.request(url)
        if not response:
            return

        # Extract and analyze JWT tokens
        await self.extract_and_analyze_jwt(url, response)

        # Check API security headers
        await self.check_api_security_headers(url, response)

        # Look for exposed API keys
        await self.detect_exposed_api_keys(url, response)

    async def scan(self):
        """Main scanning function"""
        print(f"\n{Colors.BOLD}=== API Security Scanner ==={Colors.END}")
        print(f"Target: {self.target_url}\n")

        await self.init_session()

        try:
            # Step 1: Discover API specifications
            print(f"{Colors.BOLD}[1] Discovering API Specifications{Colors.END}")
            openapi_endpoints = self.options.get('openapi_endpoints', self.DEFAULT_OPENAPI_ENDPOINTS)

            tasks = []
            for endpoint in openapi_endpoints:
                spec_url = f"{self.target_url}{endpoint}"
                if spec_url not in self.processed_urls:
                    self.processed_urls.add(spec_url)
                    tasks.append(self.discover_api_spec(spec_url))

            await asyncio.gather(*tasks)

            # Step 2: Test discovered endpoints
            if self.discovered_endpoints and self.options.get('test_endpoints', False):
                print(f"\n{Colors.BOLD}[2] Testing Discovered Endpoints{Colors.END}")
                tasks = []
                for endpoint in self.discovered_endpoints[:20]:  # Limit to first 20 to avoid overwhelming
                    tasks.append(self.test_endpoint(endpoint))

                await asyncio.gather(*tasks)

            # Step 3: Test the main target URL
            print(f"\n{Colors.BOLD}[3] Testing Target URL{Colors.END}")
            await self.test_endpoint(self.target_url)

        finally:
            await self.close_session()

        # Generate report
        self.generate_report()

    def generate_report(self):
        """Generate final security report"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}SECURITY SCAN REPORT{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")

        print(f"Target: {self.target_url}")
        print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Summary
        vuln_count = len(self.vulnerabilities)
        finding_count = len(self.findings)
        endpoint_count = len(self.discovered_endpoints)

        print(f"{Colors.BOLD}Summary:{Colors.END}")
        print(f"  Vulnerabilities: {Colors.RED}{vuln_count}{Colors.END}")
        print(f"  Findings: {Colors.YELLOW}{finding_count}{Colors.END}")
        print(f"  Discovered Endpoints: {endpoint_count}\n")

        # Vulnerabilities
        if self.vulnerabilities:
            print(f"{Colors.BOLD}{Colors.RED}VULNERABILITIES (HIGH SEVERITY):{Colors.END}")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{i}. {Colors.BOLD}{vuln['type']}{Colors.END}")
                print(f"   URL: {vuln['url']}")
                print(f"   Description: {vuln['description']}")
                print(f"   Severity: {vuln['severity']}")

        # Findings
        if self.findings:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}FINDINGS:{Colors.END}")
            for i, finding in enumerate(self.findings, 1):
                print(f"\n{i}. {Colors.BOLD}{finding['type']}{Colors.END}")
                print(f"   URL: {finding['url']}")
                print(f"   Description: {finding['description']}")
                print(f"   Severity: {finding.get('severity', 'INFO')}")

        # Discovered endpoints
        if self.discovered_endpoints:
            print(f"\n{Colors.BOLD}DISCOVERED API ENDPOINTS:{Colors.END}")
            for endpoint in self.discovered_endpoints[:10]:  # Show first 10
                print(f"  - {endpoint}")
            if len(self.discovered_endpoints) > 10:
                print(f"  ... and {len(self.discovered_endpoints) - 10} more")

        # Save JSON report
        if self.options.get('json_report', False):
            self.save_json_report()

        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}\n")

    def save_json_report(self):
        """Save report as JSON file"""
        output_dir = Path(self.options.get('output_folder', './api-security-output'))
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = output_dir / f"report_{timestamp}.json"

        report = {
            "target": self.target_url,
            "scan_time": datetime.now().isoformat(),
            "summary": {
                "vulnerabilities": len(self.vulnerabilities),
                "findings": len(self.findings),
                "discovered_endpoints": len(self.discovered_endpoints)
            },
            "vulnerabilities": self.vulnerabilities,
            "findings": self.findings,
            "discovered_endpoints": self.discovered_endpoints
        }

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        self.log_success(f"JSON report saved to {report_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Standalone API Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://api.example.com
  %(prog)s https://example.com --test-endpoints --json-report
  %(prog)s https://api.example.com --no-jwt --verbose
  %(prog)s https://example.com -o ./output --test-endpoints
        """
    )

    parser.add_argument('target', help='Target URL to scan (e.g., https://api.example.com)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--test-jwt', action='store_true', default=True, help='Analyze JWT tokens (default: enabled)')
    parser.add_argument('--no-jwt', action='store_false', dest='test_jwt', help='Disable JWT analysis')
    parser.add_argument('--test-endpoints', action='store_true', help='Test discovered API endpoints')
    parser.add_argument('--json-report', action='store_true', help='Save report as JSON file')
    parser.add_argument('--no-save-specs', action='store_false', dest='save_specs', help='Do not save discovered API specs')
    parser.add_argument('-o', '--output-folder', default='./api-security-output', help='Output folder for reports and specs')
    parser.add_argument('-H', '--header', action='append', dest='headers', help='Custom HTTP headers (e.g., "Authorization: Bearer token")')

    args = parser.parse_args()

    # Parse custom headers
    headers = {}
    if args.headers:
        for header in args.headers:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()

    # Validate URL
    if not args.target.startswith(('http://', 'https://')):
        print(f"{Colors.RED}Error: Target URL must start with http:// or https://{Colors.END}")
        sys.exit(1)

    # Create scanner options
    options = {
        'verbose': args.verbose,
        'test_jwt': args.test_jwt,
        'test_endpoints': args.test_endpoints,
        'json_report': args.json_report,
        'save_specs': args.save_specs,
        'output_folder': args.output_folder,
        'headers': headers
    }

    # Run scanner
    scanner = APISecurityScanner(args.target, **options)

    try:
        asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
        sys.exit(1)


if __name__ == "__main__":
    main()
