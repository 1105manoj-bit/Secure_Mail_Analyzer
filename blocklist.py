# blocklist.py
"""
Threat Blocklist Manager
Maintains lists of known malicious domains, IPs, and hashes.
Can be updated from community feeds (MISP, AlienVault OTX, etc.)
"""
import json
import os
import re
from typing import Dict, Set


class BlocklistManager:
    """
    Manages blocklists of known malicious indicators.
    In production, sync these from threat intelligence feeds.
    """

    # Sample known-bad domains (real phishing/malware domains from public sources)
    KNOWN_BAD_DOMAINS: Set[str] = {
        # Free TLDs heavily abused for phishing
        # These are pattern-based - any .tk/.ml/.ga/.cf/.gq domain is higher risk
        # Real blocklist would have thousands of specific entries
        "paypal-secure-login.tk",
        "microsoft-verify.ml",
        "amazon-security-alert.ga",
        "apple-id-verify.cf",
        "google-account-update.gq",
        "irs-refund-2024.tk",
        "fedex-delivery-alert.ml",
        "netflix-billing-update.ga",
        "chase-secure-login.tk",
    }

    # Known malicious IP ranges (Tor exit nodes, bulletproof hosting, etc.)
    KNOWN_BAD_IP_PREFIXES: Set[str] = {
        "185.220.",   # Tor exit nodes
        "199.249.",   # Tor exit nodes
        "104.244.",   # Known abuse hosting
        "23.129.",    # Abuse hosting
    }

    # Known phishing file hashes (MD5) - sample
    KNOWN_BAD_HASHES: Set[str] = {
        "44d88612fea8a8f36de82e1278abb02f",  # EICAR test file MD5
        "69630e4574ec6798239b091cda43dca0",  # Known malware sample
    }

    def __init__(self):
        self.custom_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.getcwd(), "custom_blocklist.json"
        )
        self.custom = self._load_custom()

    def _load_custom(self) -> Dict:
        if os.path.exists(self.custom_path):
            try:
                with open(self.custom_path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"domains": [], "ips": [], "hashes": []}

    def _save_custom(self):
        with open(self.custom_path, "w") as f:
            json.dump(self.custom, f, indent=2)

    def check_domain(self, domain: str) -> Dict:
        domain = domain.lower().strip()
        in_builtin = domain in self.KNOWN_BAD_DOMAINS
        in_custom = domain in self.custom.get("domains", [])
        # Pattern check: free TLDs
        free_tld = bool(re.search(r"\.(tk|ml|ga|cf|gq)$", domain))
        return {
            "domain": domain,
            "blocked": in_builtin or in_custom,
            "source": "builtin" if in_builtin else ("custom" if in_custom else None),
            "free_tld_warning": free_tld,
            "risk_note": "Free TLD commonly abused for phishing" if free_tld else None,
        }

    def check_ip(self, ip: str) -> Dict:
        in_custom = ip in self.custom.get("ips", [])
        in_bad_range = any(ip.startswith(p) for p in self.KNOWN_BAD_IP_PREFIXES)
        return {
            "ip": ip,
            "blocked": in_custom or in_bad_range,
            "source": "custom" if in_custom else ("known_bad_range" if in_bad_range else None),
        }

    def check_hash(self, hash_val: str) -> Dict:
        h = hash_val.lower().strip()
        in_builtin = h in self.KNOWN_BAD_HASHES
        in_custom = h in self.custom.get("hashes", [])
        return {
            "hash": h,
            "blocked": in_builtin or in_custom,
            "source": "builtin" if in_builtin else ("custom" if in_custom else None),
        }

    def add_domain(self, domain: str) -> bool:
        if domain not in self.custom["domains"]:
            self.custom["domains"].append(domain.lower().strip())
            self._save_custom()
            return True
        return False

    def add_ip(self, ip: str) -> bool:
        if ip not in self.custom["ips"]:
            self.custom["ips"].append(ip.strip())
            self._save_custom()
            return True
        return False

    def add_hash(self, hash_val: str) -> bool:
        if hash_val not in self.custom["hashes"]:
            self.custom["hashes"].append(hash_val.lower().strip())
            self._save_custom()
            return True
        return False

    def get_all(self) -> Dict:
        return {
            "builtin": {
                "domains": len(self.KNOWN_BAD_DOMAINS),
                "ip_ranges": len(self.KNOWN_BAD_IP_PREFIXES),
                "hashes": len(self.KNOWN_BAD_HASHES),
            },
            "custom": {
                "domains": self.custom.get("domains", []),
                "ips": self.custom.get("ips", []),
                "hashes": self.custom.get("hashes", []),
            }
        }