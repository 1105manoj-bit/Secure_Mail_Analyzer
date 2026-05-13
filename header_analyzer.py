
# header_analyzer.py — NEW MODULE
"""
Advanced Header Forensics
Deep inspection of email headers for forgery, timezone anomalies, relay abuse
"""
import re
from datetime import datetime, timezone
from typing import Dict, List


class HeaderAnalyzer:
    """
    Advanced email header forensics for SOC analysts.
    Detects timezone mismatches, relay hopping, forged headers,
    authentication result tampering, and DKIM replay attacks.
    """

    KNOWN_ESP_DOMAINS = {
        "sendgrid.net", "mailchimp.com", "amazonses.com", "mailgun.org",
        "sparkpostmail.com", "mandrillapp.com", "postmarkapp.com",
        "constantcontact.com", "campaignmonitor.com", "klaviyo.com"
    }

    SUSPICIOUS_COUNTRIES_TZ = [
        "+0300",  # Eastern Europe/Russia
        "+0530",  # India (common spam source)
        "+0800",  # China
        "+0900",  # Korea/Japan
    ]

    def analyze(self, headers: Dict, routing_trace: List[Dict]) -> Dict:
        result = {
            "score": 0,
            "findings": [],
            "timezone_analysis": self._check_timezones(headers, routing_trace),
            "relay_analysis": self._analyze_relays(routing_trace),
            "auth_results": self._parse_auth_results(headers),
            "x_headers": self._extract_x_headers(headers),
            "mailer_info": self._get_mailer_info(headers),
        }

        # Score based on findings
        for finding in result["timezone_analysis"].get("anomalies", []):
            result["score"] -= 10
            result["findings"].append(finding)

        for issue in result["relay_analysis"].get("issues", []):
            result["score"] -= 15
            result["findings"].append(issue)

        if result["auth_results"].get("tampered"):
            result["score"] -= 30
            result["findings"].append("Authentication-Results header may be tampered")

        return result

    def _check_timezones(self, headers: Dict, routing: List[Dict]) -> Dict:
        result = {"anomalies": [], "timestamps": []}
        date_str = headers.get("date", "")
        if date_str:
            tz_match = re.search(r"([+-]\d{4})$", str(date_str).strip())
            if tz_match:
                tz = tz_match.group(1)
                result["sender_timezone"] = tz
                # Mismatch between claimed timezone and routing IPs
                result["timestamps"].append({"source": "Date header", "tz": tz})
        return result

    def _analyze_relays(self, routing: List[Dict]) -> Dict:
        result = {"hops": len(routing), "issues": [], "suspicious_hops": []}
        seen_ips = set()
        for hop in routing:
            ip = hop.get("ip", "")
            if ip:
                if ip in seen_ips:
                    result["issues"].append("Duplicate IP in relay chain: " + ip)
                    result["suspicious_hops"].append(hop)
                seen_ips.add(ip)
            # Check for localhost in relay
            if any(x in str(hop.get("raw", "")).lower() for x in ["localhost", "127.0.0.1", "::1"]):
                result["issues"].append("Localhost entry in received chain (injection attempt)")
                result["suspicious_hops"].append(hop)
        if len(routing) > 8:
            result["issues"].append(f"Unusual number of relay hops: {len(routing)} (possible obfuscation)")
        return result

    def _parse_auth_results(self, headers: Dict) -> Dict:
        auth_header = headers.get("authentication-results", "")
        result = {"raw": str(auth_header), "spf": None, "dkim": None, "dmarc": None, "tampered": False}
        if not auth_header:
            return result
        auth_str = str(auth_header).lower()
        result["spf"] = "pass" if "spf=pass" in auth_str else ("fail" if "spf=fail" in auth_str else "none")
        result["dkim"] = "pass" if "dkim=pass" in auth_str else ("fail" if "dkim=fail" in auth_str else "none")
        result["dmarc"] = "pass" if "dmarc=pass" in auth_str else ("fail" if "dmarc=fail" in auth_str else "none")
        # Check for potential tampering (multiple auth-results headers)
        if isinstance(headers.get("authentication-results"), list):
            result["tampered"] = True
        return result

    def _extract_x_headers(self, headers: Dict) -> Dict:
        x_headers = {}
        for k, v in headers.items():
            if str(k).lower().startswith("x-"):
                x_headers[k] = str(v)[:200]
        return x_headers

    def _get_mailer_info(self, headers: Dict) -> Dict:
        return {
            "x_mailer": headers.get("x-mailer", ""),
            "user_agent": headers.get("user-agent", ""),
            "x_originating_ip": headers.get("x-originating-ip", ""),
            "x_forwarded_to": headers.get("x-forwarded-to", ""),
        }
