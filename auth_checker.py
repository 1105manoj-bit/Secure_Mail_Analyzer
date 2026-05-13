"""
Email Authentication Checker - Fixed for Windows
Uses dnspython (primary) with nslookup fallback
Install: pip install dnspython
"""

import re
import subprocess
import sys
from typing import Dict, List, Optional


def _dns_txt_lookup(domain: str) -> List[str]:
    """
    Resolve TXT records.
    Tries dnspython first (works everywhere),
    falls back to nslookup (built into Windows),
    then falls back to dig (Linux/Mac).
    """

    # ── Method 1: dnspython (best, cross-platform) ──
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        records = []
        try:
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                # Handle quoted strings joined together
                txt = txt.replace('" "', "")
                if txt:
                    records.append(txt)
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except Exception:
            pass
        return records
    except ImportError:
        pass  # dnspython not installed, try fallback

    # ── Method 2: nslookup (built into Windows) ──
    records = _nslookup_txt(domain)
    if records is not None:
        return records

    # ── Method 3: dig (Linux/Mac) ──
    records = _dig_txt(domain)
    if records is not None:
        return records

    return []


def _nslookup_txt(domain: str) -> Optional[List[str]]:
    """Use nslookup which is built into every Windows machine"""
    try:
        result = subprocess.run(
            ["nslookup", "-type=TXT", domain],
            capture_output=True, text=True, timeout=8,
            creationflags=0x08000000 if sys.platform == "win32" else 0
        )
        records = []
        output = result.stdout + result.stderr
        # nslookup formats TXT records as: text = "v=spf1 ..."
        for line in output.splitlines():
            line = line.strip()
            # Match lines like: text = "v=spf1 include:..."
            if "=" in line and ('"' in line or "v=spf" in line.lower() or "v=dkim" in line.lower() or "v=dmarc" in line.lower()):
                # Extract the quoted content
                matches = re.findall(r'"([^"]+)"', line)
                for m in matches:
                    records.append(m)
                # Also try unquoted content after =
                if not matches and "=" in line:
                    val = line.split("=", 1)[1].strip().strip('"')
                    if val:
                        records.append(val)
        return records if records else None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _dig_txt(domain: str) -> Optional[List[str]]:
    """Use dig (Linux/Mac)"""
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", domain],
            capture_output=True, text=True, timeout=8
        )
        if result.returncode != 0:
            return None
        records = []
        for line in result.stdout.splitlines():
            line = line.strip().strip('"')
            if line:
                records.append(line)
        return records if records else None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _check_dns_available() -> str:
    """Check which DNS method is available"""
    try:
        import dns.resolver
        return "dnspython"
    except ImportError:
        pass
    try:
        result = subprocess.run(
            ["nslookup", "-type=TXT", "google.com"],
            capture_output=True, text=True, timeout=5,
            creationflags=0x08000000 if sys.platform == "win32" else 0
        )
        if "spf" in result.stdout.lower() or "text" in result.stdout.lower():
            return "nslookup"
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", "google.com"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return "dig"
    except Exception:
        pass
    return "none"


class EmailAuthChecker:
    """
    Real SPF, DKIM, DMARC verification.
    Works on Windows, Linux, and Mac.

    Priority:
      1. dnspython (pip install dnspython)  <- best
      2. nslookup  (built into Windows)     <- fallback
      3. dig       (Linux/Mac)              <- fallback
    """

    def __init__(self):
        self.dns_method = _check_dns_available()

    def check_all(self, domain: str) -> Dict:
        spf = self.check_spf(domain)
        dkim = self.check_dkim(domain)
        dmarc = self.check_dmarc(domain)
        total_score = spf["score"] + dkim["score"] + dmarc["score"]
        return {
            "domain": domain,
            "dns_method": self.dns_method,
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "total_score": total_score,
            "max_score": 90,
            "grade": self._grade(total_score),
            "summary": self._summary(spf, dkim, dmarc),
        }

    def check_spf(self, domain: str) -> Dict:
        result = {
            "status": "none",
            "details": "No SPF record found",
            "record": None,
            "includes": [],
            "all_mechanism": None,
            "score": 0,
            "recommendations": []
        }

        if self.dns_method == "none":
            result["status"] = "error"
            result["details"] = "DNS unavailable. Run: pip install dnspython"
            return result

        try:
            records = _dns_txt_lookup(domain)
            spf_record = next((r for r in records if "v=spf1" in r.lower()), None)

            if not spf_record:
                result["recommendations"].append(
                    "Add SPF TXT record: v=spf1 include:_spf." + domain + " ~all"
                )
                return result

            result["record"] = spf_record
            result["status"] = "pass"
            result["score"] = 30

            for part in spf_record.split():
                if part.startswith("include:"):
                    result["includes"].append(part[8:])
                elif part in ["-all", "~all", "+all", "?all"]:
                    result["all_mechanism"] = part

            mech = result["all_mechanism"]
            if mech == "-all":
                result["details"] = "SPF configured with strict policy (-all)"
            elif mech == "~all":
                result["details"] = "SPF configured with soft-fail (~all)"
                result["score"] = 20
                result["recommendations"].append(
                    "Consider using -all instead of ~all for stricter enforcement"
                )
            elif mech == "+all":
                result["status"] = "fail"
                result["details"] = "SPF allows ALL senders (+all) — DANGEROUS"
                result["score"] = -10
                result["recommendations"].append(
                    "Change +all to -all immediately — anyone can spoof your domain!"
                )
            else:
                result["details"] = "SPF record found: " + spf_record[:80]
                result["score"] = 15

        except Exception as e:
            result["status"] = "error"
            result["details"] = "SPF check error: " + str(e)

        return result

    def check_dkim(self, domain: str, selector: str = None) -> Dict:
        result = {
            "status": "none",
            "details": "No DKIM record found",
            "record": None,
            "selector": None,
            "key_type": None,
            "score": 0,
            "recommendations": []
        }

        if self.dns_method == "none":
            result["status"] = "error"
            result["details"] = "DNS unavailable. Run: pip install dnspython"
            return result

        # Common selectors to try — covers most email providers
        selectors = [
            selector,
            "google", "default", "mail", "email", "dkim",
            "k1", "s1", "s2", "selector1", "selector2",
            "smtp", "outbound", "mandrill", "sendgrid",
            "mailchimp", "ses", "proofpoint", "mimecast",
            "20230601", "20221208", "20210112",  # Google date-based selectors
        ]

        for sel in selectors:
            if not sel:
                continue
            try:
                dkim_domain = sel + "._domainkey." + domain
                records = _dns_txt_lookup(dkim_domain)
                for txt in records:
                    if "v=dkim1" in txt.lower() or "p=" in txt.lower():
                        result["record"] = txt[:200]
                        result["selector"] = sel
                        result["status"] = "pass"
                        result["score"] = 30
                        result["details"] = "DKIM record found (selector: " + sel + ")"
                        m = re.search(r"k=(\w+)", txt, re.IGNORECASE)
                        if m:
                            result["key_type"] = m.group(1)
                        # Check if key revoked (empty p=)
                        p_match = re.search(r"p=([^;\s]*)", txt, re.IGNORECASE)
                        if p_match and not p_match.group(1).strip():
                            result["status"] = "fail"
                            result["details"] = "DKIM key has been revoked (selector: " + sel + ")"
                            result["score"] = 0
                        return result
            except Exception:
                continue

        result["recommendations"].append(
            "Configure DKIM signing for " + domain + " with your email provider"
        )
        return result

    def check_dmarc(self, domain: str) -> Dict:
        result = {
            "status": "none",
            "details": "No DMARC record found",
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "pct": 100,
            "rua": None,
            "ruf": None,
            "score": 0,
            "recommendations": []
        }

        if self.dns_method == "none":
            result["status"] = "error"
            result["details"] = "DNS unavailable. Run: pip install dnspython"
            return result

        try:
            records = _dns_txt_lookup("_dmarc." + domain)
            dmarc_record = next(
                (r for r in records if "v=dmarc1" in r.lower()), None
            )

            if not dmarc_record:
                result["recommendations"].append(
                    "Add DMARC TXT record at _dmarc." + domain
                )
                return result

            result["record"] = dmarc_record
            result["status"] = "pass"

            p_match = re.search(r"p=(\w+)", dmarc_record, re.IGNORECASE)
            if p_match:
                result["policy"] = p_match.group(1).lower()

            sp_match = re.search(r"sp=(\w+)", dmarc_record, re.IGNORECASE)
            if sp_match:
                result["subdomain_policy"] = sp_match.group(1).lower()

            pct_match = re.search(r"pct=(\d+)", dmarc_record, re.IGNORECASE)
            if pct_match:
                result["pct"] = int(pct_match.group(1))

            rua_match = re.search(r"rua=([^;\s]+)", dmarc_record, re.IGNORECASE)
            if rua_match:
                result["rua"] = rua_match.group(1).strip()

            ruf_match = re.search(r"ruf=([^;\s]+)", dmarc_record, re.IGNORECASE)
            if ruf_match:
                result["ruf"] = ruf_match.group(1).strip()

            policy = result["policy"]
            if policy == "reject":
                result["score"] = 30
                result["details"] = "DMARC with reject policy (strongest protection)"
            elif policy == "quarantine":
                result["score"] = 20
                result["details"] = "DMARC with quarantine policy (good)"
                result["recommendations"].append(
                    "Consider upgrading DMARC from quarantine to reject"
                )
            elif policy == "none":
                result["score"] = 10
                result["details"] = "DMARC monitoring only (p=none) — not enforced"
                result["recommendations"].append(
                    "Upgrade DMARC from p=none to p=quarantine or p=reject"
                )
            else:
                result["score"] = 5
                result["details"] = "DMARC record found (policy: " + str(policy) + ")"

            if result["pct"] < 100:
                result["score"] = max(0, result["score"] - 5)
                result["recommendations"].append(
                    "DMARC only applies to " + str(result["pct"]) + "% of emails — increase pct to 100"
                )

            if not result["rua"]:
                result["recommendations"].append(
                    "Add rua= tag to receive aggregate DMARC reports"
                )

        except Exception as e:
            result["status"] = "error"
            result["details"] = "DMARC check error: " + str(e)

        return result

    def _grade(self, score: int) -> str:
        if score >= 85:
            return "A+"
        elif score >= 70:
            return "A"
        elif score >= 55:
            return "B"
        elif score >= 40:
            return "C"
        elif score >= 25:
            return "D"
        else:
            return "F"

    def _summary(self, spf, dkim, dmarc) -> str:
        passing = [
            k for k, v in {"SPF": spf, "DKIM": dkim, "DMARC": dmarc}.items()
            if v["status"] == "pass"
        ]
        failing = [
            k for k, v in {"SPF": spf, "DKIM": dkim, "DMARC": dmarc}.items()
            if v["status"] != "pass"
        ]
        if not failing:
            return "All authentication checks passed (" + ", ".join(passing) + ")"
        elif not passing:
            return "No email authentication configured — domain is vulnerable to spoofing"
        else:
            return (
                ", ".join(passing) + " configured. "
                "Missing: " + ", ".join(failing)
            )