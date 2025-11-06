#!/usr/bin/env python3
"""
Enhanced API Security Testing Tool

Performs comprehensive API security testing with improved security,
modularity, and error handling.

Features:
- OpenAPI/Swagger specification discovery
- JWT token analysis (expiration, audience, weak algorithms)
- Security misconfiguration detection
- Exposed API key and secrets detection
- SSL/TLS security validation
- Directory traversal detection
- Private IP disclosure detection
- BOLA (Broken Object Level Authorization) risk analysis
- Mass Assignment vulnerability detection
- Rate limiting and connection pooling
- Comprehensive error handling
- Input validation
"""

import json
import base64
import re
import asyncio
import argparse
import time
import logging
import sys
import ipaddress
import hashlib
from pathlib import Path
from urllib.parse import urljoin, urlparse
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from abc import ABC, abstractmethod

try:
    import aiohttp
    from aiohttp import ClientSession, ClientTimeout, ClientError, ClientSSLError
except ImportError:
    print("Error: aiohttp is required. Install it with: pip install aiohttp")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("Warning: PyYAML not installed. Install with: pip install pyyaml")
    yaml = None


# ============================================================================
# Configuration and Constants
# ============================================================================

class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Security finding data structure"""
    type: str
    url: str
    description: str
    severity: Severity
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['severity'] = self.severity.value
        return data


class Config:
    """Configuration management"""

    DEFAULT_OPENAPI_ENDPOINTS = [
        "/openapi.json",
        "/swagger/index.html",  # Fixed: Added missing comma
        "/swagger.json",
        "/api/openapi.json",
        "/api/swagger.json",
        "/api/swagger/v1",
        "/api/swagger/v2",
        "/api/swagger/v3",
        "/api/docs",
        "/api/v1/openapi.json",
        "/api/v1/swagger.json",
        "/api/v2/openapi.json",
        "/api/v2/swagger.json",
        "/api/v3/openapi.json",
        "/api/v3/swagger.json",
        "/swagger/v1/swagger.json",
        "/api-docs",
        "/docs",
        "/v1/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/.well-known/openapi.json",
    ]

    # Regex patterns with ReDoS protection (possessive quantifiers)
    API_KEY_PATTERNS = {
        # Removed generic_api_key - too prone to false positives
        # Consider adding it back with more specific context requirements
        'openai': (
            r'sk-[A-Za-z0-9]{20,100}',
            "OpenAI API Key"
        ),
        'github_pat': (
            r'ghp_[A-Za-z0-9]{36}',
            "GitHub Personal Access Token"
        ),
        'github_oauth': (
            r'gho_[A-Za-z0-9]{36}',
            "GitHub OAuth Token"
        ),
        'aws_key': (
            r'AKIA[0-9A-Z]{16}',
            "AWS Access Key ID"
        ),
        'google_api': (
            r'AIza[0-9A-Za-z_\-]{35}',
            "Google API Key"
        ),
        'stripe_secret': (
            r'sk_live_[0-9a-zA-Z]{24,}',
            "Stripe Secret Key"
        ),
        'stripe_public': (
            r'pk_live_[0-9a-zA-Z]{24,}',
            "Stripe Public Key"
        ),
        'twilio': (
            r'SK[0-9a-fA-F]{32}',
            "Twilio API Key"
        ),
        'slack_token': (
            r'xox[baprs]-[0-9A-Za-z\-]{10,48}',
            "Slack Token"
        ),
        'discord_token': (
            r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
            "Discord Bot/User Token"
        ),
        'telegram_bot_token': (
            r'[0-9]{8,10}:AA[A-Za-z0-9_-]{33}',
            "Telegram Bot Token"
        ),
        # Removed cloudflare_api_key - pattern was too generic (any 37-40 char alphanumeric)
        # Real Cloudflare API keys should be detected via more specific patterns or context
        'sendgrid_api_key': (
            r'SG\.[A-Za-z0-9_\-]{16,64}\.[A-Za-z0-9_\-]{16,64}',
            "SendGrid API Key"
        ),
        # Removed heroku_api_key - UUID pattern is too generic and matches legitimate IDs
        # Heroku keys are just UUIDs which are commonly used for many legitimate purposes
        'digitalocean_token': (
            r'dop_v1_[A-Za-z0-9]{64}',
            "DigitalOcean API Token"
        ),
        'mailgun_api_key': (
            r'key-[0-9a-zA-Z]{32}',
            "Mailgun API Key"
        ),
        'algolia_api_key': (
            r'ALGOLIA_API_KEY_[A-Za-z0-9]{32,}',
            "Algolia API Key"
        ),
        'notion_token': (
            r'secret_[A-Za-z0-9]{43}',
            "Notion Integration Token"
        )
    }

    SECRET_PATTERNS = {
        'database_url': (
            r'(mongodb(\+srv)?|postgres|mysql|redis)://[^\s\'"]{10,200}',
            "Database Connection String"
        ),
        'private_key': (
            r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
            "Private Key"
        ),
        # Removed password_config - too prone to false positives in documentation,
        # examples, and test data. Real passwords in config should be caught by other means
        'oauth_secret': (
            r'["\']?(client_secret|oauth_secret|consumer_secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,100}?)["\']',
            "OAuth/Client Secret"
        ),
        'jwt_secret': (
            r'["\']?(jwt_secret|token_secret|secret_key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,100}?)["\']',
            "JWT/Token Secret"
        ),
        'aws_secret': (
            r'aws[_\-]?secret[_\-]?access[_\-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
            "AWS Secret Access Key"
        ),
        'slack_token': (
            r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}',
            "Slack Token"
        ),
        'stripe_live': (r'(sk|rk)_live_[A-Za-z0-9]{24,}', "Stripe Live Key"),
    }

    PRIVATE_IP_PATTERNS = {
        'private_10': (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', "Private IP (10.x.x.x)"),
        'private_172': (
            r'\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b',
            "Private IP (172.16-31.x.x)"
        ),
        'private_192': (r'\b192\.168\.\d{1,3}\.\d{1,3}\b', "Private IP (192.168.x.x)"),
        'loopback': (r'\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', "Loopback IP (127.x.x.x)"),
    }

    SENSITIVE_FIELD_NAMES = {
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "private_key", "privatekey", "access_token", "refresh_token",
        "auth_token", "session_token", "csrf_token", "jwt",
        "salt", "hash", "credit_card", "creditcard", "ssn", "social_security",
        "internal_id", "system_id", "db_password", "database_password",
        "encryption_key", "private", "confidential"
    }

    @classmethod
    def load_from_file(cls, config_path: Path) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if not yaml:
            return {}

        try:
            with open(config_path) as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            logging.warning(f"Config file not found: {config_path}")
            return {}
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return {}


# ============================================================================
# Security Utilities
# ============================================================================

class SecureString:
    """Secure string storage with hashing"""

    def __init__(self, value: str):
        self._hash = hashlib.sha256(value.encode()).hexdigest()
        self._preview = self._create_preview(value)

    @staticmethod
    def _create_preview(value: str, length: int = 10) -> str:
        """Create safe preview of sensitive data"""
        if len(value) <= length:
            return "*" * len(value)
        return value[:length] + "..." + f"[{len(value)} chars]"

    def get_hash(self) -> str:
        """Get hash of the value"""
        return self._hash

    def get_preview(self) -> str:
        """Get safe preview"""
        return self._preview


class URLValidator:
    """URL validation and sanitization"""

    BLOCKED_SCHEMES = {'file', 'ftp', 'data', 'javascript'}
    BLOCKED_HOSTS = {'localhost', '127.0.0.1', '0.0.0.0', '::1'}

    @classmethod
    def validate_url(cls, url: str, allow_private: bool = False) -> str:
        """Validate and sanitize URL"""
        if not url:
            raise ValueError("URL cannot be empty")

        # Parse URL
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"Invalid URL scheme: {parsed.scheme}")

        # Check for blocked hosts
        if parsed.hostname in cls.BLOCKED_HOSTS:
            raise ValueError(f"Blocked hostname: {parsed.hostname}")

        # Check for private IP addresses
        if not allow_private:
            try:
                ip = ipaddress.ip_address(parsed.hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    raise ValueError(f"Private/loopback IP not allowed: {parsed.hostname}")
            except ValueError:
                # Not an IP address, continue
                pass

        return url.rstrip("/")

    @classmethod
    def safe_url_join(cls, base: str, path: str) -> str:
        """Safely join URL components"""
        if not path.startswith('/'):
            path = '/' + path
        return urljoin(base, path)


class RateLimiter:
    """Token bucket rate limiter"""

    def __init__(self, rate: int, per: float = 1.0):
        """
        Initialize rate limiter

        Args:
            rate: Number of requests allowed
            per: Time period in seconds
        """
        self.rate = rate
        self.per = per
        self.allowance = float(rate)
        self.last_check = time.time()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Acquire permission to make a request"""
        async with self._lock:
            current = time.time()
            time_passed = current - self.last_check
            self.last_check = current

            # Replenish tokens
            self.allowance += time_passed * (self.rate / self.per)
            if self.allowance > self.rate:
                self.allowance = float(self.rate)

            # Check if we have tokens
            if self.allowance < 1.0:
                sleep_time = (1.0 - self.allowance) * (self.per / self.rate)
                await asyncio.sleep(sleep_time)
                self.allowance = 0.0
            else:
                self.allowance -= 1.0


class ResponseCache:
    """Simple in-memory response cache"""

    def __init__(self, max_size: int = 1000):
        self.cache: Dict[str, Tuple[int, bytes, Dict]] = {}
        self.max_size = max_size
        self._lock = asyncio.Lock()

    def _make_key(self, url: str, method: str) -> str:
        """Create cache key"""
        return hashlib.sha256(f"{method}:{url}".encode()).hexdigest()

    async def get(self, url: str, method: str = "GET") -> Optional[Tuple[int, bytes, Dict]]:
        """Get cached response"""
        async with self._lock:
            key = self._make_key(url, method)
            return self.cache.get(key)

    async def set(self, url: str, method: str, status: int, body: bytes, headers: Dict):
        """Cache response"""
        async with self._lock:
            if len(self.cache) >= self.max_size:
                # Remove oldest entry
                self.cache.pop(next(iter(self.cache)))

            key = self._make_key(url, method)
            self.cache[key] = (status, body, headers)


# ============================================================================
# Security Check Base Classes
# ============================================================================

class SecurityCheck(ABC):
    """Base class for security checks"""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    @abstractmethod
    async def check(self, url: str, response: aiohttp.ClientResponse) -> List[Finding]:
        """Perform security check"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Check name"""
        pass


# ============================================================================
# Security Check Implementations
# ============================================================================

class JWTSecurityCheck(SecurityCheck):
    """JWT token security analysis"""

    JWT_PATTERN = re.compile(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

    @property
    def name(self) -> str:
        return "JWT Security Check"

    async def check(self, url: str, response: aiohttp.ClientResponse) -> List[Finding]:
        """Extract and analyze JWT tokens"""
        findings = []

        # Get response body and headers
        try:
            resp_body = response._body.decode('utf-8', errors='ignore')
        except Exception:
            resp_body = ""

        resp_headers = dict(response.headers)

        # Collect JWT candidates
        jwt_candidates = set()

        # Check Authorization header
        auth_header = resp_headers.get("authorization", "") or resp_headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            jwt_candidates.add(auth_header[7:])

        # Check for JWTs in body
        if resp_body:
            try:
                body_json = json.loads(resp_body)
                for key in ["token", "access_token", "id_token", "refresh_token", "jwt"]:
                    if key in body_json and isinstance(body_json[key], str):
                        if self.JWT_PATTERN.match(body_json[key]):
                            jwt_candidates.add(body_json[key])
            except json.JSONDecodeError:
                # Try regex on body
                for match in self.JWT_PATTERN.finditer(resp_body):
                    jwt_candidates.add(match.group(0))

        # Analyze each token
        for token in jwt_candidates:
            findings.extend(await self._analyze_token(token, url))

        return findings

    async def _analyze_token(self, token: str, url: str) -> List[Finding]:
        """Analyze a single JWT token"""
        findings = []

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return findings

            header_b64, payload_b64, signature = parts

            # Decode header
            header_b64_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
            try:
                header_json = base64.urlsafe_b64decode(header_b64_padded).decode("utf-8")
                header = json.loads(header_json)
            except Exception:
                return findings

            # Decode payload
            payload_b64_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
            try:
                payload_json = base64.urlsafe_b64decode(payload_b64_padded).decode("utf-8")
                payload = json.loads(payload_json)
            except Exception:
                return findings

            alg = header.get("alg", "").lower()
            self.logger.info(f"Analyzing JWT token: alg={alg}")

            # Check for 'none' algorithm
            if alg == "none":
                findings.append(Finding(
                    type="JWT_NONE_ALGORITHM",
                    url=url,
                    description='JWT token uses "none" algorithm - signature can be bypassed',
                    severity=Severity.CRITICAL,
                    metadata={"algorithm": alg}
                ))

            # Check for weak algorithms
            weak_algs = ["hs256", "hs384", "hs512"]
            if alg in weak_algs:
                findings.append(Finding(
                    type="JWT_WEAK_ALGORITHM",
                    url=url,
                    description=f"JWT token uses potentially weak symmetric algorithm: {alg.upper()}",
                    severity=Severity.MEDIUM,
                    metadata={"algorithm": alg}
                ))

            # Check for missing expiration
            if "exp" not in payload:
                findings.append(Finding(
                    type="JWT_NO_EXPIRATION",
                    url=url,
                    description="JWT token does not have an expiration claim (exp) - tokens never expire",
                    severity=Severity.HIGH
                ))
            else:
                # Check if token is expired
                current_time = int(time.time())
                exp_time = payload.get("exp")
                if isinstance(exp_time, (int, float)) and exp_time < current_time:
                    findings.append(Finding(
                        type="JWT_EXPIRED",
                        url=url,
                        description=f"JWT token is expired - expiration time was {datetime.fromtimestamp(exp_time).isoformat()}",
                        severity=Severity.HIGH,
                        metadata={"expired_at": datetime.fromtimestamp(exp_time).isoformat()}
                    ))

            # Check for missing audience claim
            if "aud" not in payload:
                findings.append(Finding(
                    type="JWT_MISSING_AUDIENCE",
                    url=url,
                    description="JWT token missing audience (aud) claim - vulnerable to cross-service relay attacks",
                    severity=Severity.HIGH
                ))

            # Check for sensitive data in payload
            for key in payload.keys():
                if any(sensitive in key.lower() for sensitive in Config.SENSITIVE_FIELD_NAMES):
                    findings.append(Finding(
                        type="JWT_SENSITIVE_DATA",
                        url=url,
                        description=f"JWT token contains potentially sensitive data in claim: {key}",
                        severity=Severity.MEDIUM,
                        metadata={"claim": key}
                    ))

        except Exception as e:
            self.logger.debug(f"Error analyzing JWT token: {e}")

        return findings


class APIKeyDetectionCheck(SecurityCheck):
    """Detect exposed API keys"""

    # Common false positive patterns
    BASE64_IMAGE_PREFIXES = [
        'iVBORw0KGg',  # PNG
        '/9j/',         # JPEG
        'R0lGODlh',     # GIF
        'UklGR',        # WEBP
        'Qk',           # BMP
    ]

    # Common JavaScript/CSS patterns that aren't keys
    FALSE_POSITIVE_PATTERNS = [
        r'^[a-zA-Z]+[A-Z][a-z]+',  # CamelCase identifiers (e.g., "getUpdates", "scheduleTest")
        r'^[a-z]{3,}[A-Z]',         # camelCase starting with lowercase
    ]

    @property
    def name(self) -> str:
        return "API Key Detection"

    def _is_likely_false_positive(self, candidate: str) -> bool:
        """Check if the candidate is likely a false positive"""

        # Check if it's a base64-encoded image
        for prefix in self.BASE64_IMAGE_PREFIXES:
            if candidate.startswith(prefix):
                return True

        # Check if it matches common false positive patterns
        for pattern in self.FALSE_POSITIVE_PATTERNS:
            if re.match(pattern, candidate):
                return True

        # Check for common non-key words
        common_words = {
            'undefined', 'null', 'true', 'false', 'function', 'return',
            'object', 'string', 'number', 'boolean', 'array', 'document',
            'window', 'console', 'jquery', 'angular', 'react', 'vue'
        }
        if candidate.lower() in common_words:
            return True

        return False

    async def check(self, url: str, response: aiohttp.ClientResponse) -> List[Finding]:
        """Detect exposed API keys in response"""
        findings = []

        try:
            resp_body = response._body.decode('utf-8', errors='ignore')
        except Exception:
            return findings

        if not resp_body:
            return findings

        # Check each pattern
        for pattern_name, (pattern, key_type) in Config.API_KEY_PATTERNS.items():
            try:
                matches = re.finditer(pattern, resp_body, re.IGNORECASE)
                for match in matches:
                    key_value = match.group(1) if match.groups() else match.group(0)

                    # Filter out false positives
                    if self._is_likely_false_positive(key_value):
                        self.logger.debug(f"Filtered false positive for {key_type}: {key_value[:20]}...")
                        continue

                    secure_key = SecureString(key_value)

                    findings.append(Finding(
                        type="EXPOSED_API_KEY",
                        url=url,
                        description=f"Exposed {key_type} found in API response",
                        severity=Severity.CRITICAL,
                        metadata={
                            "key_type": key_type,
                            "key_hash": secure_key.get_hash(),
                            "key_preview": secure_key.get_preview()
                        }
                    ))
            except Exception as e:
                self.logger.debug(f"Error checking pattern {pattern_name}: {e}")

        return findings


class SecretDetectionCheck(SecurityCheck):
    """Detect various types of secrets"""

    # Common false positive indicators for secrets
    FALSE_POSITIVE_INDICATORS = [
        'example', 'sample', 'demo', 'test', 'placeholder', 'todo',
        'your_', 'my_', 'xxx', '***', '...', 'null', 'undefined'
    ]

    @property
    def name(self) -> str:
        return "Secret Detection"

    def _is_likely_false_positive(self, secret_value: str, context: str = "") -> bool:
        """Check if the secret is likely a false positive"""

        secret_lower = secret_value.lower()

        # Check for example/placeholder indicators
        for indicator in self.FALSE_POSITIVE_INDICATORS:
            if indicator in secret_lower:
                return True

        # Check if it's in a documentation context (look at surrounding text)
        if context:
            context_lower = context.lower()
            doc_indicators = ['example', 'documentation', 'docs', 'readme', 'tutorial', 'guide']
            for indicator in doc_indicators:
                if indicator in context_lower:
                    return True

        return False

    async def check(self, url: str, response: aiohttp.ClientResponse) -> List[Finding]:
        """Detect secrets leaking in responses"""
        findings = []

        try:
            resp_body = response._body.decode('utf-8', errors='ignore')
        except Exception:
            return findings

        if not resp_body:
            return findings

        found_secrets = set()

        for pattern_name, (pattern, secret_type) in Config.SECRET_PATTERNS.items():
            try:
                matches = re.finditer(pattern, resp_body, re.IGNORECASE)
                for match in matches:
                    secret_value = match.group(0)
                    secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()

                    if secret_hash in found_secrets:
                        continue

                    # Get context around the match (100 chars before and after)
                    start = max(0, match.start() - 100)
                    end = min(len(resp_body), match.end() + 100)
                    context = resp_body[start:end]

                    # Filter out false positives
                    if self._is_likely_false_positive(secret_value, context):
                        self.logger.debug(f"Filtered false positive for {secret_type}")
                        continue

                    found_secrets.add(secret_hash)

                    secure_secret = SecureString(secret_value)

                    findings.append(Finding(
                        type="SECRETS_LEAK",
                        url=url,
                        description=f"Exposed {secret_type} found in API response",
                        severity=Severity.CRITICAL,
                        metadata={
                            "secret_type": secret_type,
                            "secret_hash": secure_secret.get_hash(),
                            "secret_preview": secure_secret.get_preview()
                        }
                    ))
            except Exception as e:
                self.logger.debug(f"Error checking secret pattern {pattern_name}: {e}")

        return findings


class SecurityHeaderCheck(SecurityCheck):
    """Check for missing security headers"""

    @property
    def name(self) -> str:
        return "Security Header Check"

    async def check(self, url: str, response: aiohttp.ClientResponse) -> List[Finding]:
        """Check for missing API security headers"""
        findings = []
        resp_headers = dict(response.headers)

        # Check if this looks like an API response
        content_type = resp_headers.get("content-type", "") or resp_headers.get("Content-Type", "")
        if "json" not in content_type.lower():
            return findings

        # Check for CORS misconfigurations
        cors_origin = resp_headers.get("access-control-allow-origin", "") or \
                      resp_headers.get("Access-Control-Allow-Origin", "")

        if cors_origin == "*":
            findings.append(Finding(
                type="UNRESTRICTED_CORS",
                url=url,
                description="API endpoint allows unrestricted CORS (Access-Control-Allow-Origin: *)",
                severity=Severity.MEDIUM
            ))

        return findings


class PrivateFieldAccessCheck(SecurityCheck):
    """Detect exposure of private/sensitive fields"""

    @property
    def name(self) -> str:
        return "Private Field Access Check"

    async def check(self, url: str, response: aiohttp.ClientResponse) -> List[Finding]:
        """Detect exposure of private fields in API responses"""
        findings = []

        try:
            resp_body = response._body.decode('utf-8', errors='ignore')
        except Exception:
            return findings

        if not resp_body:
            return findings

        # Try to parse as JSON
        try:
            data = json.loads(resp_body)
        except json.JSONDecodeError:
            return findings

        sensitive_findings = self._check_fields(data)

        for field_path, field_name in sensitive_findings:
            findings.append(Finding(
                type="PRIVATE_FIELD_ACCESS",
                url=url,
                description=f"Potentially sensitive field '{field_path}' exposed in API response",
                severity=Severity.MEDIUM,
                metadata={"field": field_path}
            ))

        return findings

    def _check_fields(self, obj: Any, path: str = "") -> List[Tuple[str, str]]:
        """Recursively check for sensitive fields in JSON"""
        found = []

        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                key_lower = key.lower()

                # Check if key matches sensitive field
                for sensitive in Config.SENSITIVE_FIELD_NAMES:
                    if sensitive in key_lower:
                        found.append((current_path, key))
                        break

                # Recurse into nested structures
                found.extend(self._check_fields(value, current_path))

        elif isinstance(obj, list):
            for i, item in enumerate(obj[:5]):  # Check first 5 items
                found.extend(self._check_fields(item, f"{path}[{i}]"))

        return found


class DirectoryTraversalCheck(SecurityCheck):
    """Detect potential directory traversal vulnerabilities"""

    TRAVERSAL_PATTERNS = [
        (r'\.\.[\\/]', "Path traversal sequence found"),
        (r'[A-Za-z]:\\[^<>\n\r]{5,}', "Windows absolute path disclosed"),
        (r'/(?:home|root|etc|usr|var)/[^\s<>\'"]{5,}', "Unix absolute path disclosed"),
    ]

    @property
    def name(self) -> str:
        return "Directory Traversal Check"

    async def check(self, url: str, response: aiohttp.ClientResponse) -> List[Finding]:
        """Detect potential directory traversal vulnerabilities"""
        findings = []

        try:
            resp_body = response._body.decode('utf-8', errors='ignore')
        except Exception:
            return findings

        if not resp_body:
            return findings

        for pattern, description in self.TRAVERSAL_PATTERNS:
            try:
                matches = re.finditer(pattern, resp_body, re.IGNORECASE)
                for match in matches:
                    matched_text = match.group(0)
                    display_text = matched_text[:100] + "..." if len(matched_text) > 100 else matched_text

                    findings.append(Finding(
                        type="DIRECTORY_TRAVERSAL",
                        url=url,
                        description=f"{description}: {display_text}",
                        severity=Severity.HIGH
                    ))
                    break  # Only report once per pattern
            except Exception as e:
                self.logger.debug(f"Error checking traversal pattern: {e}")

        return findings


class PrivateIPDisclosureCheck(SecurityCheck):
    """Detect private IP addresses exposed in responses"""

    # Maximum number of private IPs to report per response to avoid noise
    MAX_IPS_PER_RESPONSE = 5

    @property
    def name(self) -> str:
        return "Private IP Disclosure Check"

    def _is_valid_ip(self, ip_str: str) -> bool:
        """Validate that the IP address octets are in valid ranges"""
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False

    async def check(self, url: str, response: aiohttp.ClientResponse) -> List[Finding]:
        """Detect private IP addresses in responses"""
        findings = []

        try:
            resp_body = response._body.decode('utf-8', errors='ignore')
        except Exception:
            return findings

        if not resp_body:
            return findings

        found_ips = set()

        for pattern_name, (pattern, ip_type) in Config.PRIVATE_IP_PATTERNS.items():
            try:
                matches = re.finditer(pattern, resp_body)
                for match in matches:
                    ip_address = match.group(0)

                    # Validate IP format
                    if not self._is_valid_ip(ip_address):
                        continue

                    if ip_address in found_ips:
                        continue
                    found_ips.add(ip_address)

                    # Limit the number of findings to avoid excessive noise
                    if len(findings) >= self.MAX_IPS_PER_RESPONSE:
                        self.logger.debug(f"Limiting private IP findings to {self.MAX_IPS_PER_RESPONSE} per response")
                        break

                    findings.append(Finding(
                        type="PRIVATE_IP_DISCLOSURE",
                        url=url,
                        description=f"{ip_type} disclosed in response: {ip_address}",
                        severity=Severity.LOW,
                        metadata={"ip_address": ip_address}
                    ))
            except Exception as e:
                self.logger.debug(f"Error checking IP pattern {pattern_name}: {e}")

        return findings


class DirectoryListingCheck(SecurityCheck):
    """Detect if directory listing is enabled"""

    DIR_LISTING_PATTERNS = [
        r'<title>Index of /',
        r'<h1>Index of /',
        r'Directory listing for',
        r'<title>Directory Listing',
        r'Parent Directory</a>',
    ]

    @property
    def name(self) -> str:
        return "Directory Listing Check"

    async def check(self, url: str, response: aiohttp.ClientResponse) -> List[Finding]:
        """Detect if directory listing is enabled"""
        findings = []

        try:
            resp_body = response._body.decode('utf-8', errors='ignore')
        except Exception:
            return findings

        if not resp_body:
            return findings

        for pattern in self.DIR_LISTING_PATTERNS:
            if re.search(pattern, resp_body, re.IGNORECASE | re.DOTALL):
                findings.append(Finding(
                    type="DIRECTORY_LISTING",
                    url=url,
                    description="Directory listing is enabled - exposes file and directory structure",
                    severity=Severity.MEDIUM
                ))
                break

        return findings


# ============================================================================
# OpenAPI Spec Analysis
# ============================================================================

class OpenAPIAnalyzer:
    """Analyze OpenAPI/Swagger specifications"""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    async def analyze_spec(self, spec_url: str, spec_data: Dict) -> Tuple[List[str], List[Finding]]:
        """
        Analyze OpenAPI spec for endpoints and security issues

        Returns:
            Tuple of (discovered_endpoints, findings)
        """
        findings = []
        discovered_endpoints = []

        # Extract version
        spec_version = spec_data.get("openapi") or spec_data.get("swagger", "unknown")
        self.logger.info(f"Analyzing API spec version {spec_version}")

        # Get base URL
        parsed_spec_url = urlparse(spec_url)
        base_url = f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"

        # Extract server URLs (OpenAPI 3.x)
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

        # Check for security definitions
        security_schemes = spec_data.get("securityDefinitions") or \
                           spec_data.get("components", {}).get("securitySchemes", {})

        if not security_schemes:
            findings.append(Finding(
                type="NO_SECURITY_SCHEMES",
                url=spec_url,
                description="API specification has no security schemes defined - endpoints may be unprotected",
                severity=Severity.MEDIUM
            ))

        # Parse paths
        paths = spec_data.get("paths", {})

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            # Construct full endpoint URL
            endpoint_url = URLValidator.safe_url_join(base_url, path.lstrip("/"))
            discovered_endpoints.append(endpoint_url)

            # Check for security on each method
            for method in ["get", "post", "put", "patch", "delete"]:
                if method in methods:
                    operation = methods[method]
                    if isinstance(operation, dict):
                        op_security = operation.get("security")

                        if op_security == []:
                            findings.append(Finding(
                                type="UNAUTHENTICATED_ENDPOINT",
                                url=endpoint_url,
                                description=f"API endpoint {method.upper()} {path} explicitly allows unauthenticated access",
                                severity=Severity.MEDIUM,
                                metadata={"method": method.upper()}
                            ))

        self.logger.info(f"Discovered {len(discovered_endpoints)} API endpoints from spec")

        # Additional analysis
        findings.extend(await self._analyze_mass_assignment(spec_url, spec_data, paths))
        findings.extend(await self._analyze_bola_risks(spec_url, spec_data, paths))

        return discovered_endpoints, findings

    async def _analyze_mass_assignment(self, spec_url: str, spec_data: Dict, paths: Dict) -> List[Finding]:
        """Analyze for potential Mass Assignment vulnerabilities"""
        findings = []

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            for method in ["post", "put", "patch"]:
                if method not in methods:
                    continue

                operation = methods[method]
                if not isinstance(operation, dict):
                    continue

                request_body = operation.get("requestBody", {})
                content = request_body.get("content", {})
                json_content = content.get("application/json", {})
                schema = json_content.get("schema", {})

                if not schema:
                    findings.append(Finding(
                        type="POTENTIAL_MASS_ASSIGNMENT",
                        url=spec_url,
                        description=f"Endpoint {method.upper()} {path} accepts input but has no request body schema",
                        severity=Severity.MEDIUM,
                        metadata={"endpoint": path, "method": method.upper()}
                    ))
                else:
                    additional_props = schema.get("additionalProperties", None)

                    if additional_props is True or (additional_props is None and "properties" in schema):
                        findings.append(Finding(
                            type="POTENTIAL_MASS_ASSIGNMENT",
                            url=spec_url,
                            description=f"Endpoint {method.upper()} {path} allows additional properties in request",
                            severity=Severity.MEDIUM,
                            metadata={"endpoint": path, "method": method.upper()}
                        ))

        return findings

    async def _analyze_bola_risks(self, spec_url: str, spec_data: Dict, paths: Dict) -> List[Finding]:
        """Analyze for potential BOLA risks"""
        findings = []

        id_patterns = [r'\{id\}', r'\{.*?_id\}', r'\{user_?id\}', r'/\d+', r'\{uuid\}', r'\{guid\}']

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            has_id_param = any(re.search(pattern, path, re.IGNORECASE) for pattern in id_patterns)

            if not has_id_param:
                continue

            for method in ["get", "put", "patch", "delete"]:
                if method not in methods:
                    continue

                operation = methods[method]
                if not isinstance(operation, dict):
                    continue

                op_security = operation.get("security")
                global_security = spec_data.get("security", [])

                if op_security == [] or (op_security is None and not global_security):
                    findings.append(Finding(
                        type="POTENTIAL_BOLA",
                        url=spec_url,
                        description=f"Endpoint {method.upper()} {path} has ID parameter but may lack proper authorization checks",
                        severity=Severity.MEDIUM,
                        metadata={"endpoint": path, "method": method.upper()}
                    ))

        return findings


# ============================================================================
# Vulnerability Knowledge Base
# ============================================================================

class VulnerabilityKnowledgeBase:
    """Provides detailed information, remediation, and references for findings"""

    VULNERABILITY_INFO = {
        "JWT_NONE_ALGORITHM": {
            "impact": "Attackers can forge arbitrary JWT tokens without a valid signature, leading to complete authentication bypass",
            "remediation": [
                "Never use 'none' algorithm in production environments",
                "Enforce strong signature algorithms (RS256, ES256)",
                "Validate the algorithm claim in JWT header matches expected value",
                "Reject tokens with 'none' algorithm at the API gateway level"
            ],
            "references": [
                "OWASP API Security Top 10: API2:2023 - Broken Authentication",
                "CWE-347: Improper Verification of Cryptographic Signature",
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
            ]
        },
        "JWT_WEAK_ALGORITHM": {
            "impact": "Symmetric algorithms (HMAC) are vulnerable to key guessing attacks and confusion attacks where public keys are misused as symmetric keys",
            "remediation": [
                "Use asymmetric algorithms (RS256, ES256) for production",
                "If using HMAC, ensure secret keys have high entropy (256+ bits)",
                "Implement algorithm whitelisting in token validation",
                "Consider rotating keys regularly"
            ],
            "references": [
                "OWASP API Security Top 10: API2:2023 - Broken Authentication",
                "CWE-326: Inadequate Encryption Strength",
                "RFC 7518 - JSON Web Algorithms (JWA)"
            ]
        },
        "JWT_NO_EXPIRATION": {
            "impact": "Tokens without expiration never expire, allowing indefinite access if stolen. Compromised tokens remain valid forever",
            "remediation": [
                "Always include 'exp' (expiration) claim in JWT tokens",
                "Set reasonable expiration times (e.g., 15 minutes for access tokens)",
                "Implement token refresh mechanism for longer sessions",
                "Consider implementing token revocation mechanism"
            ],
            "references": [
                "OWASP API Security Top 10: API2:2023 - Broken Authentication",
                "CWE-613: Insufficient Session Expiration",
                "RFC 7519 - JSON Web Token (JWT)"
            ]
        },
        "JWT_EXPIRED": {
            "impact": "Server is accepting expired tokens, allowing unauthorized access with old credentials",
            "remediation": [
                "Implement proper expiration validation in token verification",
                "Reject expired tokens at API gateway and service levels",
                "Ensure server clocks are synchronized (use NTP)",
                "Add clock skew tolerance of only a few seconds"
            ],
            "references": [
                "OWASP API Security Top 10: API2:2023 - Broken Authentication",
                "CWE-613: Insufficient Session Expiration"
            ]
        },
        "JWT_MISSING_AUDIENCE": {
            "impact": "Tokens can be reused across different services/applications (confused deputy attack), allowing privilege escalation",
            "remediation": [
                "Always include 'aud' (audience) claim specifying intended recipient",
                "Validate audience claim matches your service identifier",
                "Use different tokens for different services/APIs",
                "Implement strict audience validation in middleware"
            ],
            "references": [
                "OWASP API Security Top 10: API2:2023 - Broken Authentication",
                "CWE-639: Authorization Bypass Through User-Controlled Key",
                "RFC 7519 Section 4.1.3 - Audience Claim"
            ]
        },
        "JWT_SENSITIVE_DATA": {
            "impact": "JWT payloads are base64-encoded, not encrypted. Sensitive data is exposed to anyone who intercepts the token",
            "remediation": [
                "Never store sensitive data (passwords, keys, PII) in JWT payload",
                "Use opaque tokens (random strings) for sensitive applications",
                "Consider using JWE (JSON Web Encryption) for encrypted payloads",
                "Limit JWT to non-sensitive claims (user_id, roles, permissions)"
            ],
            "references": [
                "OWASP API Security Top 10: API3:2023 - Broken Object Property Level Authorization",
                "CWE-200: Exposure of Sensitive Information",
                "RFC 7516 - JSON Web Encryption (JWE)"
            ]
        },
        "EXPOSED_API_KEY": {
            "impact": "Exposed API keys can be used to impersonate your application, leading to unauthorized access, data breaches, and billing fraud",
            "remediation": [
                "Immediately revoke and rotate the exposed API key",
                "Never include API keys in API responses or client-side code",
                "Use environment variables or secure vaults for key storage",
                "Implement key rotation policies",
                "Use OAuth 2.0 or similar for client authentication",
                "Add IP whitelisting and rate limiting to API keys"
            ],
            "references": [
                "OWASP API Security Top 10: API2:2023 - Broken Authentication",
                "CWE-798: Use of Hard-coded Credentials",
                "CWE-522: Insufficiently Protected Credentials"
            ]
        },
        "SECRETS_LEAK": {
            "impact": "Leaked secrets (passwords, tokens, private keys) allow attackers to compromise systems, databases, and external services",
            "remediation": [
                "Immediately revoke and rotate all exposed secrets",
                "Never return secrets in API responses",
                "Use secret management systems (HashiCorp Vault, AWS Secrets Manager)",
                "Implement secret scanning in CI/CD pipelines",
                "Redact sensitive data from logs and error messages"
            ],
            "references": [
                "OWASP API Security Top 10: API3:2023 - Broken Object Property Level Authorization",
                "CWE-312: Cleartext Storage of Sensitive Information",
                "CWE-209: Generation of Error Message Containing Sensitive Information"
            ]
        },
        "UNRESTRICTED_CORS": {
            "impact": "Allows any website to make authenticated requests to your API from users' browsers, enabling CSRF and data theft",
            "remediation": [
                "Replace wildcard (*) with specific allowed origins",
                "Implement origin whitelist validation",
                "Never use * with credentials (Access-Control-Allow-Credentials: true)",
                "Consider using same-origin policy where possible",
                "Validate Origin header on the server side"
            ],
            "references": [
                "OWASP API Security Top 10: API7:2023 - Server Side Request Forgery",
                "CWE-346: Origin Validation Error",
                "MDN Web Docs: CORS"
            ]
        },
        "PRIVATE_FIELD_ACCESS": {
            "impact": "Exposure of sensitive internal fields can reveal implementation details, credentials, or allow privilege escalation",
            "remediation": [
                "Implement field-level access control and filtering",
                "Use DTO (Data Transfer Object) pattern to explicitly define response schemas",
                "Never serialize entire database models directly",
                "Apply @JsonIgnore or similar annotations to sensitive fields",
                "Implement role-based field filtering"
            ],
            "references": [
                "OWASP API Security Top 10: API3:2023 - Broken Object Property Level Authorization",
                "CWE-213: Exposure of Sensitive Information Due to Incompatible Policies"
            ]
        },
        "DIRECTORY_TRAVERSAL": {
            "impact": "Attackers can access files outside intended directories, potentially reading sensitive configuration files, source code, or credentials",
            "remediation": [
                "Validate and sanitize all file path inputs",
                "Use allowlist of permitted files/directories",
                "Implement path canonicalization and check for '..' sequences",
                "Run application with minimal file system permissions",
                "Never directly use user input in file operations"
            ],
            "references": [
                "OWASP API Security Top 10: API1:2023 - Broken Object Level Authorization",
                "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
                "OWASP Path Traversal"
            ]
        },
        "PRIVATE_IP_DISCLOSURE": {
            "impact": "Reveals internal network topology and IP addressing scheme, aiding reconnaissance for further attacks",
            "remediation": [
                "Remove internal IP addresses from API responses",
                "Use proxy/load balancer IPs instead of internal IPs",
                "Sanitize error messages and debug output",
                "Implement response filtering for IP addresses",
                "Review logging and monitoring outputs"
            ],
            "references": [
                "OWASP API Security Top 10: API8:2023 - Security Misconfiguration",
                "CWE-200: Exposure of Sensitive Information",
                "CWE-209: Generation of Error Message Containing Sensitive Information"
            ]
        },
        "DIRECTORY_LISTING": {
            "impact": "Exposes application structure, files, and potentially sensitive resources to attackers for reconnaissance",
            "remediation": [
                "Disable directory listing in web server configuration",
                "For Apache: Options -Indexes in .htaccess",
                "For Nginx: autoindex off in server block",
                "Add index.html files to all directories",
                "Implement proper access controls on file resources"
            ],
            "references": [
                "OWASP API Security Top 10: API8:2023 - Security Misconfiguration",
                "CWE-548: Exposure of Information Through Directory Listing"
            ]
        },
        "SSL_NOT_ENFORCED": {
            "impact": "Traffic is transmitted in clear text, allowing eavesdropping, man-in-the-middle attacks, and credential theft",
            "remediation": [
                "Enforce HTTPS for all API endpoints",
                "Implement HTTP to HTTPS redirects (301/302)",
                "Enable HSTS (HTTP Strict Transport Security) header",
                "Use strong TLS versions (TLS 1.2+) and cipher suites",
                "Disable SSLv3 and TLS 1.0/1.1"
            ],
            "references": [
                "OWASP API Security Top 10: API8:2023 - Security Misconfiguration",
                "CWE-319: Cleartext Transmission of Sensitive Information",
                "OWASP Transport Layer Protection Cheat Sheet"
            ]
        },
        "SSL_CERT_NOT_TRUSTED": {
            "impact": "Invalid/untrusted SSL certificates enable man-in-the-middle attacks and indicate potential security compromise",
            "remediation": [
                "Obtain valid SSL certificate from trusted CA",
                "Ensure certificate is not expired",
                "Configure proper certificate chain",
                "Implement certificate pinning for mobile apps",
                "Monitor certificate expiration dates"
            ],
            "references": [
                "OWASP API Security Top 10: API8:2023 - Security Misconfiguration",
                "CWE-295: Improper Certificate Validation",
                "SSL Labs Best Practices"
            ]
        },
        "NO_SECURITY_SCHEMES": {
            "impact": "API endpoints may be unprotected, allowing unauthorized access to sensitive data and operations",
            "remediation": [
                "Define security schemes in OpenAPI specification",
                "Implement authentication (OAuth 2.0, API Keys, JWT)",
                "Apply security requirements to all sensitive endpoints",
                "Use different security schemes for different sensitivity levels",
                "Document authentication requirements clearly"
            ],
            "references": [
                "OWASP API Security Top 10: API2:2023 - Broken Authentication",
                "OpenAPI 3.0 Security Specification"
            ]
        },
        "UNAUTHENTICATED_ENDPOINT": {
            "impact": "Endpoint explicitly allows unauthenticated access, potentially exposing sensitive operations or data",
            "remediation": [
                "Review if unauthenticated access is truly necessary",
                "Implement authentication for sensitive endpoints",
                "Use rate limiting for public endpoints",
                "Apply principle of least privilege",
                "Consider IP whitelisting for sensitive operations"
            ],
            "references": [
                "OWASP API Security Top 10: API2:2023 - Broken Authentication",
                "CWE-306: Missing Authentication for Critical Function"
            ]
        },
        "POTENTIAL_MASS_ASSIGNMENT": {
            "impact": "Attackers can modify object properties they shouldn't have access to (e.g., isAdmin, price, role)",
            "remediation": [
                "Use explicit DTOs with only allowed fields",
                "Implement allowlist of modifiable properties",
                "Set additionalProperties: false in request schemas",
                "Never bind request data directly to database models",
                "Use separate models for input and database entities"
            ],
            "references": [
                "OWASP API Security Top 10: API6:2023 - Unrestricted Access to Sensitive Business Flows",
                "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes"
            ]
        },
        "POTENTIAL_BOLA": {
            "impact": "Users may access or modify objects belonging to other users by manipulating ID parameters (IDOR vulnerability)",
            "remediation": [
                "Implement object-level authorization checks",
                "Verify user owns/can access the requested object ID",
                "Use UUIDs instead of sequential IDs",
                "Implement indirect object references",
                "Log and monitor access to sensitive resources"
            ],
            "references": [
                "OWASP API Security Top 10: API1:2023 - Broken Object Level Authorization",
                "CWE-639: Authorization Bypass Through User-Controlled Key",
                "OWASP IDOR Testing Guide"
            ]
        },
        "API_SPEC_DISCOVERED": {
            "impact": "API specification exposes all endpoints, parameters, and structures, aiding attacker reconnaissance",
            "remediation": [
                "Consider restricting API documentation to authenticated users",
                "Remove or protect Swagger UI in production",
                "Use API gateway to expose only necessary endpoints",
                "Implement rate limiting on documentation endpoints",
                "Review what information is exposed in specifications"
            ],
            "references": [
                "OWASP API Security Top 10: API9:2023 - Improper Inventory Management",
                "CWE-538: Insertion of Sensitive Information into Externally-Accessible File"
            ]
        }
    }

    @classmethod
    def get_info(cls, finding_type: str) -> Dict[str, Any]:
        """Get detailed information for a finding type"""
        return cls.VULNERABILITY_INFO.get(finding_type, {
            "impact": "No detailed impact information available",
            "remediation": ["Review security best practices for this finding type"],
            "references": ["OWASP API Security Top 10: https://owasp.org/API-Security/"]
        })


# ============================================================================
# Main Scanner Class
# ============================================================================

class APISecurityScanner:
    """Enhanced API security scanner"""

    def __init__(
            self,
            target_url: str,
            logger: logging.Logger,
            rate_limit: int = 10,
            max_concurrent: int = 5,
            timeout: int = 30,
            max_retries: int = 3,
            verify_ssl: bool = True,
            allow_private_ips: bool = False,
            test_endpoints: bool = False,
            save_specs: bool = True,
            output_folder: str = './api-security-output',
            custom_headers: Optional[Dict[str, str]] = None
    ):
        # Validate target URL
        self.target_url = URLValidator.validate_url(target_url, allow_private=allow_private_ips)
        self.logger = logger
        self.test_endpoints = test_endpoints
        self.save_specs = save_specs
        self.output_folder = Path(output_folder)
        self.custom_headers = custom_headers or {}
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries

        # State
        self.processed_urls: Set[str] = set()
        self.analyzed_tokens: Set[str] = set()
        self.findings: List[Finding] = []
        self.discovered_endpoints: List[str] = []

        # Async utilities
        self.rate_limiter = RateLimiter(rate=rate_limit, per=1.0)
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.response_cache = ResponseCache(max_size=1000)

        # HTTP session
        self.session: Optional[ClientSession] = None
        self.timeout = ClientTimeout(total=timeout, connect=10)

        # Security checks
        self.security_checks: List[SecurityCheck] = [
            JWTSecurityCheck(logger),
            APIKeyDetectionCheck(logger),
            SecretDetectionCheck(logger),
            SecurityHeaderCheck(logger),
            PrivateFieldAccessCheck(logger),
            DirectoryTraversalCheck(logger),
            PrivateIPDisclosureCheck(logger),
            DirectoryListingCheck(logger),
        ]

        # OpenAPI analyzer
        self.openapi_analyzer = OpenAPIAnalyzer(logger)

    async def init_session(self):
        """Initialize aiohttp session with security settings"""
        import ssl

        if self.verify_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
        else:
            ssl_context = False

        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=100,
            limit_per_host=10
        )

        self.session = ClientSession(
            timeout=self.timeout,
            connector=connector,
            trust_env=True
        )

    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()

    async def request(self, url: str, method: str = "GET") -> Optional[aiohttp.ClientResponse]:
        """Make rate-limited HTTP request with retry logic"""

        # Check cache
        cached = await self.response_cache.get(url, method)
        if cached:
            self.logger.debug(f"Using cached response for {url}")
            # Create mock response object
            mock_response = type('obj', (object,), {
                'status': cached[0],
                '_body': cached[1],
                'headers': cached[2],
                'url': url
            })()
            return mock_response

        # Rate limiting
        await self.rate_limiter.acquire()

        # Concurrency control
        async with self.semaphore:
            for attempt in range(self.max_retries):
                try:
                    headers = self.custom_headers.copy()

                    async with self.session.request(
                            method,
                            url,
                            headers=headers,
                            allow_redirects=True
                    ) as response:
                        body = await response.read()
                        response._body = body

                        # Cache successful responses
                        if response.status == 200:
                            await self.response_cache.set(
                                url,
                                method,
                                response.status,
                                body,
                                dict(response.headers)
                            )

                        self.logger.debug(f"{method} {url} - Status: {response.status}")
                        return response

                except ClientSSLError as e:
                    self.logger.error(f"SSL certificate error at {url}: {e}")
                    self.findings.append(Finding(
                        type="SSL_CERT_NOT_TRUSTED",
                        url=url,
                        description=f"SSL certificate is not trusted or invalid: {str(e)}",
                        severity=Severity.HIGH
                    ))
                    return None

                except asyncio.TimeoutError:
                    if attempt < self.max_retries - 1:
                        wait_time = 2 ** attempt
                        self.logger.warning(
                            f"Timeout for {url}, retrying in {wait_time}s... (attempt {attempt + 1}/{self.max_retries})")
                        await asyncio.sleep(wait_time)
                        continue
                    self.logger.error(f"Timeout after {self.max_retries} attempts: {url}")
                    return None

                except ClientError as e:
                    self.logger.error(f"Client error for {url}: {e}")
                    return None

                except Exception as e:
                    self.logger.error(f"Unexpected error for {url}: {e}")
                    import traceback
                    self.logger.debug(traceback.format_exc())
                    return None

        return None

    async def discover_api_spec(self, spec_url: str):
        """Try to discover and parse OpenAPI/Swagger specifications"""
        self.logger.debug(f"Checking for API spec at {spec_url}")

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

        self.logger.info(f"✓ Discovered API specification at {spec_url}")

        # Save the spec
        if self.save_specs:
            await self.save_api_spec(spec_url, spec_data)

        # Add finding
        self.findings.append(Finding(
            type="API_SPEC_DISCOVERED",
            url=spec_url,
            description="OpenAPI/Swagger specification discovered",
            severity=Severity.INFO
        ))

        # Analyze the spec
        endpoints, spec_findings = await self.openapi_analyzer.analyze_spec(spec_url, spec_data)
        self.discovered_endpoints.extend(endpoints)
        self.findings.extend(spec_findings)

    async def save_api_spec(self, spec_url: str, spec_data: Dict):
        """Save API specification to file"""
        output_dir = self.output_folder / "api-specs"
        output_dir.mkdir(parents=True, exist_ok=True)

        parsed = urlparse(spec_url)
        filename = f"spec-{parsed.netloc}{parsed.path.replace('/', '_')}.json"
        filepath = output_dir / filename

        with open(filepath, "w") as f:
            json.dump(spec_data, f, indent=2)

        self.logger.info(f"Saved API spec to {filepath}")

    async def test_endpoint(self, url: str):
        """Test a single endpoint for security issues"""
        if url in self.processed_urls:
            return

        self.processed_urls.add(url)
        self.logger.debug(f"Testing endpoint: {url}")

        # Check SSL enforcement
        parsed = urlparse(url)
        if parsed.scheme == "http":
            self.findings.append(Finding(
                type="SSL_NOT_ENFORCED",
                url=url,
                description="SSL/TLS not enforced - connection uses insecure HTTP protocol",
                severity=Severity.MEDIUM
            ))

        # Make request
        response = await self.request(url)
        if not response:
            return

        # Run all security checks
        for check in self.security_checks:
            try:
                check_findings = await check.check(url, response)
                self.findings.extend(check_findings)
            except Exception as e:
                self.logger.error(f"Error in {check.name} for {url}: {e}")

    async def scan(self):
        """Main scanning function"""
        self.logger.info("=" * 70)
        self.logger.info("API Security Scanner - Enhanced Edition")
        self.logger.info("=" * 70)
        self.logger.info(f"Target: {self.target_url}")
        self.logger.info("")

        await self.init_session()

        try:
            # Step 1: Discover API specifications
            self.logger.info("[1] Discovering API Specifications")
            self.logger.info("-" * 70)

            tasks = []
            for endpoint in Config.DEFAULT_OPENAPI_ENDPOINTS:
                spec_url = URLValidator.safe_url_join(self.target_url, endpoint)
                if spec_url not in self.processed_urls:
                    self.processed_urls.add(spec_url)
                    tasks.append(self.discover_api_spec(spec_url))

            await asyncio.gather(*tasks, return_exceptions=True)

            # Step 2: Test discovered endpoints from specifications
            if self.discovered_endpoints and self.test_endpoints:
                self.logger.info("")
                self.logger.info("[2] Testing Discovered Endpoints from Specifications")
                self.logger.info("-" * 70)

                tasks = []
                for endpoint in self.discovered_endpoints[:20]:  # Limit to first 20
                    tasks.append(self.test_endpoint(endpoint))

                await asyncio.gather(*tasks, return_exceptions=True)

            # Step 3: Test the main target URL
            self.logger.info("")
            self.logger.info("[3] Testing Target URL")
            self.logger.info("-" * 70)
            await self.test_endpoint(self.target_url)

        finally:
            await self.close_session()

        # Generate report
        self.generate_report()

    def _format_finding(self, finding: Finding, index: int) -> str:
        """Format a single finding with detailed information"""
        output = []

        # Header with severity indicator
        severity_symbols = {
            Severity.CRITICAL: "[!!!]",
            Severity.HIGH: "[!!]",
            Severity.MEDIUM: "[!]",
            Severity.LOW: "[*]",
            Severity.INFO: "[i]"
        }

        symbol = severity_symbols.get(finding.severity, "[?]")
        output.append("")
        output.append("┌" + "─" * 68 + "┐")
        output.append(f"│ {symbol} Finding #{index}: {finding.type:<54}│")
        output.append("└" + "─" * 68 + "┘")
        output.append("")

        # Basic Information
        output.append("📋 BASIC INFORMATION:")
        output.append(f"   Severity:    {finding.severity.value}")
        output.append(f"   Detected At: {finding.timestamp}")
        output.append(f"   Finding Type: {finding.type}")
        output.append("")

        # Discovery Path - Clear path showing where and how the finding was discovered
        output.append("🔍 DISCOVERY PATH:")
        output.append(f"   → Target URL: {self.target_url}")
        output.append(f"   → Affected Endpoint: {finding.url}")

        # Add metadata-based path information
        if finding.metadata:
            if 'method' in finding.metadata:
                output.append(f"   → HTTP Method: {finding.metadata['method']}")
            if 'endpoint' in finding.metadata:
                output.append(f"   → API Endpoint: {finding.metadata['endpoint']}")
            if 'field' in finding.metadata:
                output.append(f"   → Vulnerable Field: {finding.metadata['field']}")
            if 'claim' in finding.metadata:
                output.append(f"   → JWT Claim: {finding.metadata['claim']}")
        output.append("")

        # Description
        output.append("📝 DESCRIPTION:")
        output.append(f"   {finding.description}")
        output.append("")

        # Additional Details from Metadata
        if finding.metadata:
            output.append("🔬 TECHNICAL DETAILS:")
            for key, value in finding.metadata.items():
                if key not in ['method', 'endpoint', 'field', 'claim']:  # Already shown above
                    # Format the key nicely
                    formatted_key = key.replace('_', ' ').title()
                    # Truncate long values
                    value_str = str(value)
                    if len(value_str) > 80:
                        value_str = value_str[:77] + "..."
                    output.append(f"   {formatted_key}: {value_str}")
            output.append("")

        # Get detailed vulnerability information
        vuln_info = VulnerabilityKnowledgeBase.get_info(finding.type)

        # Impact
        if vuln_info.get('impact'):
            output.append("⚠️  IMPACT:")
            # Wrap long impact text
            impact_lines = self._wrap_text(vuln_info['impact'], 65)
            for line in impact_lines:
                output.append(f"   {line}")
            output.append("")

        # Remediation Steps
        if vuln_info.get('remediation'):
            output.append("🔧 REMEDIATION STEPS:")
            for i, step in enumerate(vuln_info['remediation'], 1):
                # Wrap long remediation steps
                step_lines = self._wrap_text(f"{i}. {step}", 65)
                for j, line in enumerate(step_lines):
                    if j == 0:
                        output.append(f"   {line}")
                    else:
                        output.append(f"      {line}")
            output.append("")

        # References
        if vuln_info.get('references'):
            output.append("📚 REFERENCES:")
            for ref in vuln_info['references']:
                output.append(f"   • {ref}")
            output.append("")

        output.append("─" * 70)

        return "\n".join(output)

    def _wrap_text(self, text: str, width: int) -> List[str]:
        """Wrap text to specified width"""
        words = text.split()
        lines = []
        current_line = []
        current_length = 0

        for word in words:
            if current_length + len(word) + len(current_line) <= width:
                current_line.append(word)
                current_length += len(word)
            else:
                if current_line:
                    lines.append(" ".join(current_line))
                current_line = [word]
                current_length = len(word)

        if current_line:
            lines.append(" ".join(current_line))

        return lines if lines else [""]

    def generate_report(self):
        """Generate final security report"""
        self.logger.info("")
        self.logger.info("╔" + "=" * 68 + "╗")
        self.logger.info("║" + " " * 18 + "SECURITY SCAN REPORT" + " " * 30 + "║")
        self.logger.info("╚" + "=" * 68 + "╝")
        self.logger.info("")

        # Scan Information
        self.logger.info("📊 SCAN INFORMATION:")
        self.logger.info(f"   Target:           {self.target_url}")
        self.logger.info(f"   Scan Completed:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info(f"   Endpoints Tested: {len(self.processed_urls)}")
        self.logger.info(f"   Endpoints Discovered: {len(self.discovered_endpoints)}")
        self.logger.info("")

        # Group findings by severity
        by_severity = {severity: [] for severity in Severity}
        for finding in self.findings:
            by_severity[finding.severity].append(finding)

        # Summary with visual indicators
        self.logger.info("📈 FINDINGS SUMMARY:")
        self.logger.info("   ┌────────────┬───────┐")
        self.logger.info("   │ Severity   │ Count │")
        self.logger.info("   ├────────────┼───────┤")

        critical_count = len(by_severity[Severity.CRITICAL])
        high_count = len(by_severity[Severity.HIGH])
        medium_count = len(by_severity[Severity.MEDIUM])
        low_count = len(by_severity[Severity.LOW])
        info_count = len(by_severity[Severity.INFO])

        self.logger.info(f"   │ CRITICAL   │ {critical_count:>5} │ {'🔴' * min(critical_count, 5)}")
        self.logger.info(f"   │ HIGH       │ {high_count:>5} │ {'🟠' * min(high_count, 5)}")
        self.logger.info(f"   │ MEDIUM     │ {medium_count:>5} │ {'🟡' * min(medium_count, 5)}")
        self.logger.info(f"   │ LOW        │ {low_count:>5} │ {'🔵' * min(low_count, 5)}")
        self.logger.info(f"   │ INFO       │ {info_count:>5} │ {'⚪' * min(info_count, 5)}")
        self.logger.info("   └────────────┴───────┘")
        self.logger.info("")

        # Detailed findings by severity
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        severity_titles = {
            Severity.CRITICAL: "🔴 CRITICAL VULNERABILITIES (Immediate Action Required)",
            Severity.HIGH: "🟠 HIGH SEVERITY FINDINGS (Urgent Remediation Needed)",
            Severity.MEDIUM: "🟡 MEDIUM SEVERITY FINDINGS (Should Be Addressed)",
            Severity.LOW: "🔵 LOW SEVERITY FINDINGS (Consider Fixing)",
            Severity.INFO: "⚪ INFORMATIONAL FINDINGS"
        }

        for severity in severity_order:
            findings = by_severity[severity]
            if not findings:
                continue

            self.logger.info("")
            self.logger.info("=" * 70)
            self.logger.info(severity_titles[severity])
            self.logger.info("=" * 70)

            for i, finding in enumerate(findings, 1):
                formatted_finding = self._format_finding(finding, i)
                self.logger.info(formatted_finding)

        # Save JSON report
        self.save_json_report()

        # Final summary
        self.logger.info("")
        self.logger.info("=" * 70)
        total_findings = sum(len(findings) for findings in by_severity.values())
        total_issues = critical_count + high_count + medium_count

        if total_issues == 0:
            self.logger.info("✅ No critical, high, or medium severity issues found!")
        else:
            self.logger.info(f"⚠️  TOTAL FINDINGS: {total_findings}")
            self.logger.info(f"   Issues Requiring Attention: {total_issues}")
            if critical_count > 0:
                self.logger.info(f"   ⚠️  {critical_count} CRITICAL issues require immediate action!")
            if high_count > 0:
                self.logger.info(f"   ⚠️  {high_count} HIGH severity issues need urgent remediation!")

        self.logger.info("=" * 70)
        self.logger.info("")

    def save_json_report(self):
        """Save report as JSON file"""
        self.output_folder.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = self.output_folder / f"report_{timestamp}.json"

        # Group by severity
        by_severity = {severity.value: [] for severity in Severity}
        for finding in self.findings:
            by_severity[finding.severity.value].append(finding.to_dict())

        report = {
            "target": self.target_url,
            "scan_time": datetime.now().isoformat(),
            "summary": {
                "critical": len(by_severity[Severity.CRITICAL.value]),
                "high": len(by_severity[Severity.HIGH.value]),
                "medium": len(by_severity[Severity.MEDIUM.value]),
                "low": len(by_severity[Severity.LOW.value]),
                "info": len(by_severity[Severity.INFO.value]),
                "discovered_endpoints": len(self.discovered_endpoints)
            },
            "findings_by_severity": by_severity,
            "discovered_endpoints": self.discovered_endpoints
        }

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"✓ JSON report saved to {report_file}")


# ============================================================================
# CLI and Main Entry Point
# ============================================================================

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging"""
    logger = logging.getLogger("api_scanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Format
    formatter = logging.Formatter(
        '%(message)s'
    )

    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def load_targets_from_file(filepath: str) -> List[str]:
    """Load target URLs from a file"""
    targets = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    except FileNotFoundError:
        print(f"Error: Target file '{filepath}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading target file: {e}")
        sys.exit(1)

    return targets


async def scan_target(target: str, args: argparse.Namespace, logger: logging.Logger):
    """Scan a single target"""
    try:
        # Parse custom headers
        headers = {}
        if args.headers:
            for header in args.headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()

        # Create scanner
        scanner = APISecurityScanner(
            target_url=target,
            logger=logger,
            rate_limit=args.rate_limit,
            max_concurrent=args.max_concurrent,
            timeout=args.timeout,
            max_retries=args.max_retries,
            verify_ssl=not args.no_verify_ssl,
            allow_private_ips=args.allow_private_ips,
            test_endpoints=args.test_endpoints,
            save_specs=args.save_specs,
            output_folder=args.output_folder,
            custom_headers=headers
        )

        await scanner.scan()

    except ValueError as e:
        logger.error(f"Validation error for {target}: {e}")
    except Exception as e:
        logger.error(f"Error scanning {target}: {e}")
        import traceback
        logger.debug(traceback.format_exc())


async def run_parallel_scans(targets: List[str], args: argparse.Namespace, logger: logging.Logger):
    """Run scans in parallel"""
    tasks = [scan_target(target, args, logger) for target in targets]
    await asyncio.gather(*tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced API Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single target
  %(prog)s https://api.example.com

  # Scan multiple targets
  %(prog)s https://api1.example.com https://api2.example.com

  # Scan targets from a file
  %(prog)s -f targets.txt

  # Scan with additional options
  %(prog)s https://example.com --test-endpoints --parallel
  %(prog)s https://example.com --rate-limit 20 --max-concurrent 10
  %(prog)s https://example.com -H "Authorization: Bearer token" --verbose
        """
    )

    # Target specification
    parser.add_argument('targets', nargs='*', help='Target URL(s) to scan')
    parser.add_argument('-f', '--file', dest='target_file', help='File containing target URLs (one per line)')

    # Scan options
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--test-endpoints', action='store_true', help='Test discovered API endpoints')
    parser.add_argument('--no-save-specs', action='store_false', dest='save_specs',
                        help='Do not save discovered API specs')
    parser.add_argument('-o', '--output-folder', default='./api-security-output',
                        help='Output folder for reports and specs')
    parser.add_argument('-H', '--header', action='append', dest='headers', help='Custom HTTP headers')

    # Performance options
    parser.add_argument('--rate-limit', type=int, default=10, help='Requests per second (default: 10)')
    parser.add_argument('--max-concurrent', type=int, default=5, help='Maximum concurrent requests (default: 5)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('--max-retries', type=int, default=3, help='Maximum retry attempts (default: 3)')
    parser.add_argument('--parallel', action='store_true', help='Scan multiple targets in parallel')

    # Security options
    parser.add_argument('--no-verify-ssl', action='store_true',
                        help='Disable SSL certificate verification (not recommended)')
    parser.add_argument('--allow-private-ips', action='store_true',
                        help='Allow scanning private IP addresses (use with caution)')

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(verbose=args.verbose)

    # Collect targets
    target_urls = []

    if args.target_file:
        target_urls = load_targets_from_file(args.target_file)
    elif args.targets:
        target_urls = args.targets
    else:
        logger.error("Error: No targets specified. Use either positional arguments or -f/--file option")
        parser.print_help()
        sys.exit(1)

    # Validate URLs
    valid_targets = []
    for url in target_urls:
        if not url.startswith(('http://', 'https://')):
            logger.warning(f"Skipping invalid URL (must start with http:// or https://): {url}")
            continue
        valid_targets.append(url)

    if not valid_targets:
        logger.error("Error: No valid target URLs found")
        sys.exit(1)

    # Print scan summary
    logger.info("")
    logger.info("=" * 70)
    logger.info("API Security Scanner - Enhanced Edition")
    logger.info("=" * 70)
    logger.info(f"Total targets: {len(valid_targets)}")
    logger.info(f"Scan mode: {'Parallel' if args.parallel else 'Sequential'}")
    logger.info(f"Rate limit: {args.rate_limit} req/s")
    logger.info(f"Max concurrent: {args.max_concurrent}")
    logger.info("=" * 70)
    logger.info("")

    try:
        if args.parallel and len(valid_targets) > 1:
            # Run scans in parallel
            asyncio.run(run_parallel_scans(valid_targets, args, logger))
        else:
            # Run scans sequentially
            for i, target in enumerate(valid_targets, 1):
                if len(valid_targets) > 1:
                    logger.info(f"\n[{i}/{len(valid_targets)}] Scanning: {target}")
                    logger.info("=" * 70)

                asyncio.run(scan_target(target, args, logger))

                if i < len(valid_targets):
                    logger.info("\n" + "=" * 70 + "\n")

    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

    logger.info("")
    logger.info("=" * 70)
    logger.info("All scans completed!")
    logger.info("=" * 70)
    logger.info("")


if __name__ == "__main__":
    main()