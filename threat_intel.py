"""
Threat Intelligence Module - Fixed
Properly handles network errors so legitimate sites
like google.com are never wrongly flagged as suspicious.
"""

import re
import socket
import ssl
import hashlib
from urllib.parse import urlparse
from typing import Dict, List, Optional
from datetime import datetime


# Known safe domains - never flag these as suspicious regardless of network errors
KNOWN_SAFE_DOMAINS = {
    "google.com", "www.google.com",
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "amazon.com", "www.amazon.com",
    "github.com", "www.github.com",
    "youtube.com", "www.youtube.com",
    "facebook.com", "www.facebook.com",
    "twitter.com", "www.twitter.com",
    "linkedin.com", "www.linkedin.com",
    "wikipedia.org", "www.wikipedia.org",
    "stackoverflow.com",
    "cloudflare.com",
    "paypal.com", "www.paypal.com",
    "netflix.com", "www.netflix.com",
    "adobe.com", "www.adobe.com",
    "dropbox.com", "www.dropbox.com",
    "zoom.us",
}

# Free TLDs massively abused for phishing
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".loan"}

# URL shorteners that hide real destinations
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "rebrand.ly", "cutt.ly", "short.io", "is.gd", "buff.ly"
}

# Deceptive path keywords
DECEPTIVE_PATHS = [
    "login", "signin", "sign-in", "log-in",
    "verify", "verification", "validate",
    "account", "secure", "security",
    "update", "confirm", "password",
    "credential", "banking", "wallet"
]


class ThreatIntelligence:
    """
    Threat intelligence and IOC analysis.
    
    The URL check works in two stages:
    1. Pattern analysis  - always works, no network needed
    2. Live checks (SSL) - only adds penalties for DEFINITE failures,
                          never penalises network timeouts on known-safe domains
    """

    def __init__(self):
        self.timeout = 5
        self.ioc_patterns = {
            "md5":         r"\b[a-fA-F0-9]{32}\b",
            "sha1":        r"\b[a-fA-F0-9]{40}\b",
            "sha256":      r"\b[a-fA-F0-9]{64}\b",
            "ipv4":        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "email":       r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            "btc_address": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        }

    # ── IOC Extraction ─────────────────────────────────────────────────

    def extract_iocs(self, text: str) -> Dict:
        """Extract all Indicators of Compromise from text"""
        return {
            "hashes": {
                "md5":    list(set(re.findall(self.ioc_patterns["md5"],    text))),
                "sha1":   list(set(re.findall(self.ioc_patterns["sha1"],   text))),
                "sha256": list(set(re.findall(self.ioc_patterns["sha256"], text))),
            },
            "network": {
                "ips":     list(set(re.findall(self.ioc_patterns["ipv4"],  text))),
                "domains": [],
                "emails":  list(set(re.findall(self.ioc_patterns["email"], text))),
            },
            "crypto": {
                "btc_addresses": list(set(re.findall(self.ioc_patterns["btc_address"], text))),
            },
        }

    # ── URL Reputation ──────────────────────────────────────────────────

    def check_url_reputation(self, url: str) -> Dict:
        """
        Analyze a URL for phishing/malicious indicators.
        Handles malformed URLs, bad schemes, dangerous extensions, and pattern checks.
        """
        result = {
            "url": url,
            "safe": True,
            "checks": [],
            "risk_score": 0,
            "pattern_checks": [],
            "live_checks": [],
            "network_available": None,
        }

        url = url.strip()

        # ── Pre-check 1: Validate scheme ──────────────────────────────
        # Must start with http:// or https:// exactly
        import re as _re
        scheme_match = _re.match(r"^(https?)://", url, _re.IGNORECASE)
        if not scheme_match:
            # Check what scheme they actually used
            bad_scheme = url.split("://")[0].lower() if "://" in url else url[:10]
            if bad_scheme and bad_scheme not in ("http", "https"):
                result["checks"].append(
                    "Invalid URL scheme '" + bad_scheme + "' — valid schemes are http:// and https:// only"
                )
                result["pattern_checks"].append("invalid_scheme")
                result["risk_score"] -= 40
                result["safe"] = False
            else:
                result["checks"].append("URL is missing http:// or https:// — not a valid web address")
                result["pattern_checks"].append("missing_scheme")
                result["risk_score"] -= 20
                result["safe"] = False
            return result

        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower().strip()
            domain_no_port = domain.split(":")[0]
            path = parsed.path.lower()
            scheme = parsed.scheme.lower()
            full_lower = url.lower()

            # If domain is empty after parsing, URL is malformed
            if not domain_no_port:
                result["checks"].append("Malformed URL — could not extract domain")
                result["pattern_checks"].append("malformed_url")
                result["risk_score"] -= 30
                result["safe"] = False
                return result

            # ── Pre-check 2: Dangerous file extensions in domain or path ──
            # Extensions that are NEVER valid as a domain TLD
            # Note: .com is excluded here because it is a valid TLD
            # We only flag extensions that make zero sense as a domain ending
            DANGEROUS_DOMAIN_EXTENSIONS = {
                ".bat", ".exe", ".cmd", ".scr", ".vbs",
                ".ps1", ".msi", ".pif", ".hta", ".jar",
                ".wsf", ".wsh", ".reg", ".dll", ".sys",
                ".inf", ".sh", ".py", ".rb", ".php",
            }
            # Extensions dangerous when served as files in the path
            DANGEROUS_FILE_EXTENSIONS = {
                ".bat", ".exe", ".cmd", ".scr", ".vbs", ".js",
                ".ps1", ".msi", ".com", ".pif", ".hta", ".jar",
                ".wsf", ".wsh", ".reg", ".dll", ".sys", ".inf",
            }
            # Check domain itself for dangerous extension
            for ext in DANGEROUS_DOMAIN_EXTENSIONS:
                if domain_no_port.endswith(ext):
                    result["checks"].append(
                        "Domain ends with dangerous executable extension '"
                        + ext + "' — this is not a real website URL"
                    )
                    result["pattern_checks"].append("dangerous_extension_in_domain")
                    result["risk_score"] -= 50
                    result["safe"] = False
                    break
            # Also catch double extension tricks like fitgirl.com.bat
            import re as _re2
            double_ext = _re2.search(
                r"\.(com|net|org|io|co)\.(bat|exe|cmd|scr|vbs|ps1|msi|pif|hta)$",
                domain_no_port
            )
            if double_ext and "dangerous_extension_in_domain" not in result["pattern_checks"]:
                result["checks"].append(
                    "Double extension trick detected: " + double_ext.group(0)
                    + " — legitimate domain disguised as executable"
                )
                result["pattern_checks"].append("double_extension_trick")
                result["risk_score"] -= 50
                result["safe"] = False

            # Check path for dangerous file being served
            for ext in DANGEROUS_FILE_EXTENSIONS:
                if path.endswith(ext):
                    result["checks"].append(
                        "URL points to a dangerous file type '" + ext + "'"
                    )
                    result["pattern_checks"].append("dangerous_file_in_path")
                    result["risk_score"] -= 30
                    result["safe"] = False
                    break

            # ── Stage 1: Pattern Analysis ──────────────────────────────

            # HTTP vs HTTPS
            if scheme == "http":
                result["checks"].append("Not using HTTPS (insecure connection)")
                result["pattern_checks"].append("no_https")
                result["risk_score"] -= 10
                result["safe"] = False

            # IP address as domain
            if _re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_no_port):
                result["checks"].append("IP address used as domain (never legitimate for login pages)")
                result["pattern_checks"].append("ip_as_domain")
                result["risk_score"] -= 30
                result["safe"] = False

            # URL shorteners
            if domain_no_port in URL_SHORTENERS:
                result["checks"].append("URL shortener detected — hides the real destination")
                result["pattern_checks"].append("url_shortener")
                result["risk_score"] -= 20
                result["safe"] = False

            # Suspicious free TLDs
            for tld in SUSPICIOUS_TLDS:
                if domain_no_port.endswith(tld):
                    result["checks"].append("Free TLD " + tld + " — heavily abused for phishing")
                    result["pattern_checks"].append("suspicious_tld")
                    result["risk_score"] -= 20
                    result["safe"] = False
                    break

            # @ symbol in URL
            if "@" in url:
                result["checks"].append("@ symbol in URL — browser ignores everything before it (redirect trick)")
                result["pattern_checks"].append("at_symbol")
                result["risk_score"] -= 30
                result["safe"] = False

            # Excessive subdomains
            parts = domain_no_port.split(".")
            if len(parts) > 4:
                result["checks"].append(
                    "Excessive subdomains (" + str(len(parts)) + " levels) — common domain spoofing trick"
                )
                result["pattern_checks"].append("excessive_subdomains")
                result["risk_score"] -= 15
                result["safe"] = False

            # Brand in subdomain
            known_brands = [
                "paypal", "google", "microsoft", "apple", "amazon",
                "facebook", "netflix", "chase", "wellsfargo", "citibank",
                "instagram", "whatsapp", "linkedin", "twitter", "dropbox",
            ]
            actual_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain_no_port
            for brand in known_brands:
                if brand in domain_no_port and brand not in actual_domain:
                    result["checks"].append(
                        "Brand name '" + brand + "' appears in subdomain but actual domain is " + actual_domain
                    )
                    result["pattern_checks"].append("brand_in_subdomain")
                    result["risk_score"] -= 25
                    result["safe"] = False
                    break

            # Deceptive path keywords
            for kw in DECEPTIVE_PATHS:
                if kw in path:
                    result["checks"].append("Deceptive keyword in URL path: /" + kw + "/")
                    result["pattern_checks"].append("deceptive_path")
                    result["risk_score"] -= 10
                    result["safe"] = False
                    break

            # Extremely long URL
            if len(url) > 200:
                result["checks"].append(
                    "Extremely long URL (" + str(len(url)) + " chars) — often used to confuse users"
                )
                result["pattern_checks"].append("long_url")
                result["risk_score"] -= 10
                result["safe"] = False

            # ── Stage 2: Live Network Checks ───────────────────────────
            is_known_safe = domain_no_port in KNOWN_SAFE_DOMAINS

            if is_known_safe:
                result["live_checks"].append("known_safe_domain_skipped")
                result["network_available"] = "skipped"
            elif scheme == "https":
                ssl_result = self._check_ssl_safe(domain_no_port)
                result["network_available"] = ssl_result["network_available"]
                if ssl_result["checked"]:
                    if ssl_result["self_signed"]:
                        result["checks"].append("Self-signed SSL certificate (not trusted by browsers)")
                        result["live_checks"].append("self_signed_ssl")
                        result["risk_score"] -= 20
                        result["safe"] = False
                    elif ssl_result["expired"]:
                        result["checks"].append("SSL certificate has expired")
                        result["live_checks"].append("expired_ssl")
                        result["risk_score"] -= 20
                        result["safe"] = False
                    elif ssl_result["ssl_error"]:
                        result["checks"].append("SSL error: " + ssl_result["ssl_error"])
                        result["live_checks"].append("ssl_error")
                        result["risk_score"] -= 20
                        result["safe"] = False
                elif ssl_result["no_resolve"] and result["risk_score"] < -10:
                    result["checks"].append("Domain does not resolve in DNS")
                    result["live_checks"].append("domain_no_resolve")
                    result["risk_score"] -= 15
                    result["safe"] = False

        except Exception as e:
            result["checks"].append("Analysis error: " + str(e))

        if result["risk_score"] >= 0 and not result["checks"]:
            result["safe"] = True

        return result

    def _check_ssl_safe(self, domain: str) -> Dict:
        """
        Try to check SSL certificate.
        Returns structured result distinguishing between:
        - Actually checked (connected successfully)
        - No network (timeout, getaddrinfo, connection refused)
        - No resolve (DNS lookup failed)
        - SSL error (connected but cert is bad)
        """
        out = {
            "checked": False,
            "valid": False,
            "self_signed": False,
            "expired": False,
            "ssl_error": None,
            "no_network": False,
            "no_resolve": False,
            "network_available": False,
            "issuer": None,
            "expiry": None,
            "days_until_expiry": None,
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    out["checked"] = True
                    out["network_available"] = True

                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    out["issuer"] = issuer.get("organizationName", "Unknown")
                    out["self_signed"] = (
                        issuer.get("commonName") == subject.get("commonName")
                        and issuer.get("organizationName") == subject.get("organizationName")
                    )
                    try:
                        expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        out["expiry"] = expiry_date.strftime("%Y-%m-%d")
                        days_left = (expiry_date - datetime.now()).days
                        out["days_until_expiry"] = days_left
                        out["expired"] = days_left < 0
                    except Exception:
                        pass
                    out["valid"] = not out["self_signed"] and not out["expired"]

        except ssl.SSLError as e:
            out["checked"] = True  # We connected, but SSL is bad
            out["network_available"] = True
            # Translate raw SSL errors into plain English
            raw = str(e).lower()
            # Handles: TLSV1_ALERT_INTERNAL_ERROR and similar SSL errors
            if "tlsv1_alert_internal_error" in raw or "internal error" in raw:
                out["ssl_error"] = "Server rejected the SSL handshake (broken SSL configuration)"
            elif "certificate_expired" in raw or "cert has expired" in raw:
                out["ssl_error"] = "SSL certificate has expired"
                out["expired"] = True
            elif "certificate_verify_failed" in raw:
                out["ssl_error"] = "SSL certificate could not be verified (untrusted or self-signed)"
            elif "wrong_version_number" in raw or "wrong version" in raw:
                out["ssl_error"] = "SSL version mismatch — server using outdated security protocol"
            elif "self signed" in raw or "self_signed" in raw:
                out["ssl_error"] = "Self-signed certificate — not issued by a trusted authority"
                out["self_signed"] = True
            elif "hostname mismatch" in raw or "doesn't match" in raw:
                out["ssl_error"] = "SSL certificate domain mismatch — cert belongs to a different site"
            elif "no cipher" in raw:
                out["ssl_error"] = "No shared SSL cipher — server using insecure or outdated encryption"
            elif "handshake" in raw:
                out["ssl_error"] = "SSL handshake failed — server has an SSL configuration problem"
            else:
                out["ssl_error"] = "SSL error — site has an invalid or misconfigured certificate"

        except socket.gaierror:
            # getaddrinfo failed = DNS resolution failure
            out["no_resolve"] = True
            out["network_available"] = False

        except (socket.timeout, ConnectionRefusedError, OSError):
            # Timeout or connection refused = network issue, not site issue
            out["no_network"] = True
            out["network_available"] = False

        except Exception as e:
            err = str(e).lower()
            if "getaddrinfo" in err or "name or service" in err:
                out["no_resolve"] = True
            else:
                out["no_network"] = True
            out["network_available"] = False

        return out

    # ── SSL Certificate (public) ────────────────────────────────────────

    def check_ssl_certificate(self, domain: str) -> Dict:
        """Public SSL check method"""
        r = self._check_ssl_safe(domain)
        return {
            "valid": r["valid"],
            "issuer": r["issuer"],
            "expiry": r["expiry"],
            "days_until_expiry": r["days_until_expiry"],
            "self_signed": r["self_signed"],
            "error": r["ssl_error"] if not r["checked"] else None,
        }

    # ── IP Reputation ───────────────────────────────────────────────────

    def check_ip_reputation(self, ip: str) -> Dict:
        result = {
            "ip": ip,
            "is_private": self._is_private_ip(ip),
            "is_suspicious": False,
            "details": [],
        }

        if result["is_private"]:
            result["details"].append("Private/internal IP address (RFC 1918)")
            return result

        known_ranges = {
            "Google DNS":    ["8.8.8.", "8.8.4."],
            "Cloudflare":    ["1.1.1.", "1.0.0."],
            "AWS":           ["54.", "52.", "18.", "3."],
            "Azure":         ["20.", "40.", "13."],
            "Google Cloud":  ["34.", "35."],
        }
        for provider, prefixes in known_ranges.items():
            if any(ip.startswith(p) for p in prefixes):
                result["details"].append("Known " + provider + " IP range")
                return result

        # Suspicious ranges
        suspicious_ranges = {
            "Tor exit node": ["185.220.", "199.249.", "23.129."],
            "Known abuse hosting": ["104.244."],
        }
        for label, prefixes in suspicious_ranges.items():
            if any(ip.startswith(p) for p in prefixes):
                result["is_suspicious"] = True
                result["details"].append(label + " — high-risk IP range")
                return result

        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result["hostname"] = hostname
            result["details"].append("Resolves to: " + hostname)
        except Exception:
            result["details"].append("No reverse DNS entry")

        return result

    # ── File Hash ───────────────────────────────────────────────────────

    def generate_file_hash(self, filepath: str, algorithm: str = "sha256") -> str:
        hash_func = getattr(hashlib, algorithm)()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            return "Error: " + str(e)

    # ── Campaign Detection ──────────────────────────────────────────────

    def analyze_email_campaign(self, emails: List[Dict]) -> Dict:
        result = {
            "total_emails": len(emails),
            "common_senders": {},
            "common_subjects": {},
            "common_urls": {},
            "is_campaign": False,
            "campaign_indicators": [],
        }
        for ed in emails:
            sender = ed.get("from", "")
            subject = ed.get("subject", "")
            result["common_senders"][sender] = result["common_senders"].get(sender, 0) + 1
            result["common_subjects"][subject] = result["common_subjects"].get(subject, 0) + 1
            for url in ed.get("urls", []):
                result["common_urls"][url] = result["common_urls"].get(url, 0) + 1
        if len(emails) >= 3:
            if result["common_subjects"] and max(result["common_subjects"].values()) >= 3:
                result["is_campaign"] = True
                result["campaign_indicators"].append("Repeated subject line detected")
            if result["common_urls"] and max(result["common_urls"].values()) >= 3:
                result["is_campaign"] = True
                result["campaign_indicators"].append("Same URL appearing in multiple emails")
        return result

    # ── Helpers ─────────────────────────────────────────────────────────

    def _is_private_ip(self, ip: str) -> bool:
        try:
            parts = list(map(int, ip.split(".")))
            if len(parts) != 4:
                return False
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
            return False
        except Exception:
            return False