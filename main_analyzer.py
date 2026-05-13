"""
Main Email Security Analyzer v2.0
Orchestrates all analysis modules into one comprehensive report
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Optional


class EmailSecurityAnalyzer:

    def __init__(self):
        from email_parser import EmailParser
        from auth_checker import EmailAuthChecker
        from phishing_detector import PhishingDetector
        from threat_intel import ThreatIntelligence

        self.parser = EmailParser()
        self.auth_checker = EmailAuthChecker()
        self.phishing_detector = PhishingDetector()
        self.threat_intel = ThreatIntelligence()

    # ── Public API ──────────────────────────────────────────────────────

    def analyze_eml_file(self, filepath: str) -> Dict:
        email_data = self.parser.parse_file(filepath)
        return self.analyze_email_data(email_data)

    def analyze_email_data(self, email_data: Dict) -> Dict:
        sender_email = email_data.get("from", "")
        sender_domain = self._extract_domain(sender_email)

        # 1. Authentication
        auth_results = None
        if sender_domain:
            try:
                auth_results = self.auth_checker.check_all(sender_domain)
            except Exception as e:
                auth_results = {"error": str(e), "domain": sender_domain, "total_score": 0,
                                "grade": "F", "summary": "Auth check failed",
                                "spf": {"status": "error", "details": str(e), "score": 0, "recommendations": []},
                                "dkim": {"status": "error", "details": str(e), "score": 0, "recommendations": []},
                                "dmarc": {"status": "error", "details": str(e), "score": 0, "recommendations": []}}

        # 2. Phishing detection
        phishing_results = self.phishing_detector.analyze_email({
            "headers": email_data.get("headers", {}),
            "subject": email_data.get("subject", ""),
            "body": email_data.get("body", ""),
            "from": email_data.get("from", ""),
            "reply_to": email_data.get("reply_to", ""),
            "urls": email_data.get("urls", []),
        })

        # 3. IOC extraction
        combined_text = email_data.get("body", "") + " " + str(email_data.get("headers", {}))
        iocs = self.threat_intel.extract_iocs(combined_text)

        # 4. URL reputation
        url_reputation = []
        for url in email_data.get("urls", [])[:15]:
            try:
                rep = self.threat_intel.check_url_reputation(url)
                url_reputation.append(rep)
            except Exception as e:
                url_reputation.append({"url": url, "safe": None, "checks": ["Analysis failed: " + str(e)], "risk_score": 0})

        # 5. IP reputation
        ip_reputation = []
        for ip in email_data.get("ip_addresses", [])[:10]:
            try:
                rep = self.threat_intel.check_ip_reputation(ip)
                ip_reputation.append(rep)
            except Exception:
                pass

        # 6. Attachment analysis
        attachment_risk = self._analyze_attachments(email_data.get("attachments", []))

        # 7. Header anomaly summary
        header_anomalies = self._check_header_anomalies(email_data)

        # 8. Overall score
        overall_score, risk_level = self._calculate_overall_score(
            auth_results, phishing_results, attachment_risk, url_reputation, header_anomalies
        )

        # 9. Recommendations
        recommendations = self._generate_recommendations(
            auth_results, phishing_results, attachment_risk, url_reputation, header_anomalies, email_data
        )

        return {
            "metadata": {
                "analyzed_at": datetime.now().isoformat(),
                "subject": email_data.get("subject", ""),
                "from": email_data.get("from", ""),
                "to": email_data.get("to", ""),
                "reply_to": email_data.get("reply_to", ""),
                "date": email_data.get("date", ""),
                "message_id": email_data.get("message_id", ""),
                "sender_domain": sender_domain or "",
            },
            "overall_assessment": {
                "risk_level": risk_level,
                "security_score": overall_score,
                "verdict": self._get_verdict(risk_level, phishing_results),
                "confidence": self._calculate_confidence(email_data),
            },
            "authentication": auth_results,
            "phishing_indicators": phishing_results,
            "threat_intelligence": {
                "iocs": iocs,
                "url_reputation": url_reputation,
                "ip_reputation": ip_reputation,
            },
            "attachments": {
                "count": len(email_data.get("attachments", [])),
                "details": email_data.get("attachments", []),
                "risk_assessment": attachment_risk,
                "has_dangerous": email_data.get("has_dangerous_attachments", False),
            },
            "routing_analysis": {
                "hops": len(email_data.get("routing_trace", [])),
                "trace": email_data.get("routing_trace", []),
            },
            "header_anomalies": header_anomalies,
            "recommendations": recommendations,
            "raw_data": {
                "urls_found": email_data.get("urls", []),
                "ips_found": email_data.get("ip_addresses", []),
                "emails_found": email_data.get("email_addresses", []),
            },
        }

    # ── Internal helpers ─────────────────────────────────────────────────

    def _extract_domain(self, email_str: str) -> Optional[str]:
        if not email_str:
            return None
        m = re.search(r"@([\w\.\-]+)", email_str)
        return m.group(1).lower() if m else None

    def _analyze_attachments(self, attachments: List[Dict]) -> Dict:
        result = {"risk_level": "SAFE", "issues": [], "score": 0}
        if not attachments:
            return result
        dangerous = [a for a in attachments if a.get("is_dangerous")]
        if dangerous:
            result["risk_level"] = "HIGH"
            result["issues"].append(str(len(dangerous)) + " dangerous file type(s): " + ", ".join(a["filename"] for a in dangerous[:3]))
            result["score"] -= 50 * len(dangerous)
        for att in attachments:
            fname = att.get("filename", "").lower()
            if fname.count(".") > 1:
                parts = fname.rsplit(".", 2)
                if len(parts) == 3:
                    result["issues"].append("Double extension trick: " + att["filename"])
                    result["score"] -= 25
            if len(fname) > 100:
                result["issues"].append("Suspiciously long filename (obfuscation)")
                result["score"] -= 10
            if re.search(r"\.(pdf|doc|docx|jpg|png)\.(exe|scr|bat|cmd|vbs|js)$", fname):
                result["issues"].append("Misleading extension: " + att["filename"])
                result["score"] -= 50
                result["risk_level"] = "CRITICAL"
        if result["score"] < -100:
            result["risk_level"] = "CRITICAL"
        elif result["score"] < -50:
            result["risk_level"] = "HIGH"
        return result

    def _check_header_anomalies(self, email_data: Dict) -> Dict:
        anomalies = []
        headers = email_data.get("headers", {})
        from_addr = email_data.get("from", "")
        reply_to = email_data.get("reply_to", "")
        score = 0

        # Missing standard headers
        if not headers.get("message-id"):
            anomalies.append("Missing Message-ID header")
            score -= 10
        if not headers.get("date"):
            anomalies.append("Missing Date header")
            score -= 5
        if not from_addr:
            anomalies.append("Missing From header")
            score -= 20

        # Check for suspicious mailer
        mailer = str(headers.get("x-mailer", "")).lower()
        if mailer and any(s in mailer for s in ["phpmailer", "massmailer", "bulk"]):
            anomalies.append("Bulk/mass-mail software detected: " + mailer[:40])
            score -= 15

        # Check return-path vs from mismatch
        return_path = str(headers.get("return-path", "")).lower()
        if return_path and from_addr:
            rp_domain = self._extract_domain(return_path)
            from_domain = self._extract_domain(from_addr)
            if rp_domain and from_domain and rp_domain != from_domain:
                anomalies.append("Return-Path domain differs from From domain (possible spoofing)")
                score -= 20

        # Reply-To mismatch already handled by phishing_detector, flag here too
        if reply_to and from_addr:
            rd = self._extract_domain(reply_to)
            fd = self._extract_domain(from_addr)
            if rd and fd and rd != fd:
                anomalies.append("Reply-To redirects to different domain: " + rd)

        return {"anomalies": anomalies, "score": score, "count": len(anomalies)}

    def _calculate_overall_score(self, auth, phishing, attachments, urls, headers) -> tuple:
        score = 100

        # Auth penalty (up to -30)
        if auth:
            auth_total = auth.get("total_score", 0)
            max_auth = auth.get("max_score", 90)
            pct = auth_total / max(max_auth, 1)

            # Check if all auth checks errored (DNS unavailable)
            # In that case apply a smaller penalty — we cannot confirm
            # authentication but also cannot confirm it is missing
            spf_status = auth.get("spf", {}).get("status", "none")
            dkim_status = auth.get("dkim", {}).get("status", "none")
            dmarc_status = auth.get("dmarc", {}).get("status", "none")
            all_errors = all(s == "error" for s in [spf_status, dkim_status, dmarc_status])

            if all_errors:
                # DNS not available - apply small neutral penalty only
                score -= 10
            elif pct < 0.33:
                score -= 30
            elif pct < 0.55:
                score -= 18
            elif pct < 0.77:
                score -= 8

        # Phishing penalty (up to -55)
        ph_score = phishing.get("total_score", 0)
        if ph_score <= -150:
            score -= 55   # Extreme — multiple critical indicators (BEC, PIN theft etc)
        elif ph_score <= -100:
            score -= 45   # Very high — many strong phishing signals
        elif ph_score <= -70:
            score -= 35   # High — several phishing signals
        elif ph_score <= -40:
            score -= 22   # Medium — a few signals
        elif ph_score <= -20:
            score -= 12   # Low — minor signals
        elif ph_score < -5:
            score -= 5    # Minimal

        # Attachment penalty (up to -20)
        att_score = attachments.get("score", 0)
        if att_score < -80:
            score -= 20
        elif att_score < -30:
            score -= 12
        elif att_score < 0:
            score -= 6

        # URL penalty (up to -10)
        unsafe = sum(1 for u in urls if u.get("safe") is False)
        score -= min(unsafe * 4, 10)

        # Header anomaly penalty (up to -10)
        score += max(headers.get("score", 0), -10)

        score = max(0, min(100, score))

        if score >= 72:
            risk = "LOW"
        elif score >= 52:
            risk = "MEDIUM"
        elif score >= 38:
            risk = "HIGH"
        else:
            risk = "CRITICAL"

        # Override: if BEC or banking scam detected with strong signals,
        # always CRITICAL regardless of auth DNS issues
        ph_indicators = phishing.get("indicators", [])
        bec_suspicious = phishing.get("bec_analysis", {}).get("suspicious", False)
        banking_suspicious = phishing.get("banking_scam", {}).get("suspicious", False)
        if (bec_suspicious or banking_suspicious) and ph_score <= -80:
            risk = "CRITICAL"
            score = min(score, 30)

        return score, risk

    def _get_verdict(self, risk_level: str, phishing) -> str:
        brand = phishing.get("brand_impersonation", {}).get("impersonated_brand")
        bec = phishing.get("bec_analysis", {}).get("suspicious", False)

        if risk_level == "CRITICAL":
            if bec:
                return "CRITICAL: Business Email Compromise (BEC) attack detected. Do NOT transfer funds or change payment details."
            if brand:
                return "CRITICAL: " + brand.title() + " impersonation phishing attack. Delete immediately and report."
            return "CRITICAL: Almost certainly malicious. Delete immediately and do not interact."
        elif risk_level == "HIGH":
            return "HIGH RISK: Email shows strong phishing signals. Do not click links or open attachments."
        elif risk_level == "MEDIUM":
            return "MEDIUM RISK: Email has suspicious characteristics. Verify sender identity before taking action."
        else:
            return "LOW RISK: Email appears legitimate. Standard caution still advised."

    def _calculate_confidence(self, email_data: Dict) -> str:
        score = 0
        if email_data.get("routing_trace"):
            score += 2
        if email_data.get("headers", {}).get("authentication-results"):
            score += 2
        if email_data.get("urls"):
            score += 1
        if email_data.get("body") and len(email_data["body"]) > 50:
            score += 1
        if email_data.get("message_id"):
            score += 1
        if score >= 5:
            return "HIGH"
        elif score >= 3:
            return "MEDIUM"
        return "LOW"

    def _generate_recommendations(self, auth, phishing, attachments, urls, headers, email_data) -> List[str]:
        recs = []

        # Auth
        if auth:
            spf_status = auth.get("spf", {}).get("status", "none")
            dkim_status = auth.get("dkim", {}).get("status", "none")
            dmarc_status = auth.get("dmarc", {}).get("status", "none")
            if spf_status != "pass":
                recs.append("SPF check failed or missing — sender may be spoofing " + auth.get("domain", ""))
            if dkim_status != "pass":
                recs.append("No valid DKIM signature — email authenticity cannot be verified")
            if dmarc_status == "none":
                recs.append("No DMARC policy — sender domain does not prevent spoofing")
            elif dmarc_status == "pass" and auth.get("dmarc", {}).get("policy") == "none":
                recs.append("DMARC policy is p=none (monitoring only) — not enforced")

        # BEC
        if phishing.get("bec_analysis", {}).get("suspicious"):
            recs.append("BEC ALERT: Wire transfer or payment change request detected — verify via phone call to known number")

        # Brand impersonation
        brand = phishing.get("brand_impersonation", {}).get("impersonated_brand")
        if brand:
            recs.append("Brand impersonation detected (" + brand.title() + ") — do not enter credentials or click links")

        # Risk-based
        risk = phishing.get("risk_level", "LOW")
        if risk in ("HIGH", "CRITICAL"):
            recs.append("Do NOT click any links in this email")
            recs.append("Do NOT open attachments or download files")
            recs.append("Do NOT reply or provide personal information")
            recs.append("Report to your IT/security team immediately")

        # URLs
        unsafe_urls = [u for u in urls if u.get("safe") is False]
        if unsafe_urls:
            recs.append(str(len(unsafe_urls)) + " suspicious URL(s) found — avoid clicking all links")

        # Attachments
        att_risk = attachments.get("risk_level", "SAFE")
        if att_risk in ("HIGH", "CRITICAL"):
            recs.append("DANGEROUS attachment detected — do not open under any circumstances")
            recs.append("Submit attachment to your antivirus/sandbox for analysis")

        # Header anomalies
        if headers.get("count", 0) > 0:
            recs.append("Header anomalies detected: " + "; ".join(headers.get("anomalies", [])[:2]))

        # Clean email
        if not recs:
            recs.append("No major threats detected — email appears legitimate")
            recs.append("Always verify sender identity before acting on requests")
            recs.append("When in doubt, contact the sender through a known channel")

        return recs

    # ── Export ───────────────────────────────────────────────────────────

    def export_report(self, report: Dict, format_type: str = "json") -> str:
        if format_type == "json":
            return json.dumps(report, indent=2, default=str)
        elif format_type == "text":
            return self._text_report(report)
        elif format_type == "html":
            return self._html_report(report)
        raise ValueError("Unsupported format: " + format_type)

    def _text_report(self, report: Dict) -> str:
        sep = "=" * 68
        lines = [sep, "  PHISHGUARD — EMAIL SECURITY ANALYSIS REPORT v2.0", sep]
        meta = report.get("metadata", {})
        a = report.get("overall_assessment", {})
        lines += [
            "",
            "METADATA",
            "  Subject  : " + str(meta.get("subject", ""))[:80],
            "  From     : " + str(meta.get("from", "")),
            "  Date     : " + str(meta.get("date", "")),
            "  Analyzed : " + str(meta.get("analyzed_at", "")),
            "",
            sep,
            "  VERDICT: " + a.get("risk_level", "UNKNOWN") + "  |  Score: " + str(a.get("security_score", 0)) + "/100",
            sep,
            "",
            a.get("verdict", ""),
            "",
        ]
        recs = report.get("recommendations", [])
        if recs:
            lines.append("RECOMMENDATIONS")
            for r in recs:
                lines.append("  * " + r)
            lines.append("")
        auth = report.get("authentication", {})
        if auth and not auth.get("error"):
            lines += [sep, "  AUTHENTICATION — " + auth.get("domain", "") + "  [Grade: " + auth.get("grade", "?") + "]", sep]
            for k in ["spf", "dkim", "dmarc"]:
                v = auth.get(k, {})
                lines.append("  " + k.upper() + " [" + v.get("status", "none").upper() + "] " + v.get("details", ""))
            lines.append("")
        ph = report.get("phishing_indicators", {})
        lines += [sep, "  PHISHING ANALYSIS — " + ph.get("risk_level", ""), sep]
        for ind in ph.get("indicators", []):
            lines.append("  [!] " + ind)
        lines.append("")
        atts = report.get("attachments", {})
        if atts.get("count", 0):
            lines += [sep, "  ATTACHMENTS (" + str(atts["count"]) + ")", sep]
            for att in atts.get("details", []):
                mark = "[DANGEROUS]" if att.get("is_dangerous") else "[safe]     "
                lines.append("  " + mark + " " + att.get("filename", "") + " (" + att.get("content_type", "") + ")")
            lines.append("")
        lines += [sep, "  Generated by PhishGuard v2.0  |  https://github.com/your-org/phishguard", sep]
        return "\n".join(lines)

    def _html_report(self, report: Dict) -> str:
        a = report.get("overall_assessment", {})
        meta = report.get("metadata", {})
        risk = a.get("risk_level", "LOW")
        score = a.get("security_score", 0)
        color_map = {"LOW": "#00ff9d", "MEDIUM": "#ffd600", "HIGH": "#ff8c00", "CRITICAL": "#ff3355"}
        color = color_map.get(risk, "#00d4ff")
        recs_html = "".join("<li>" + r + "</li>" for r in report.get("recommendations", []))
        ind_html = "".join("<li>" + i + "</li>" for i in report.get("phishing_indicators", {}).get("indicators", []))
        auth = report.get("authentication", {}) or {}
        auth_rows = ""
        for k in ["spf", "dkim", "dmarc"]:
            v = auth.get(k, {})
            st = v.get("status", "none")
            bg = "#004422" if st == "pass" else "#440011"
            auth_rows += "<tr><td style=\"font-weight:700;\">" + k.upper() + "</td><td style=\"background:" + bg + ";border-radius:4px;padding:2px 8px;\">" + st.upper() + "</td><td>" + v.get("details", "") + "</td></tr>"
        return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>PhishGuard Report</title>
<style>body{background:#080c12;color:#e8f0fe;font-family:system-ui,sans-serif;padding:32px;max-width:900px;margin:0 auto;}
h1{color:#00d4ff;} h2{color:#8fabc7;font-size:.9rem;letter-spacing:.1em;text-transform:uppercase;}
.score{font-size:3rem;font-weight:900;color:""" + color + """;} .risk{display:inline-block;padding:6px 20px;border-radius:6px;font-weight:700;background:""" + color + """22;color:""" + color + """;border:1px solid """ + color + """55;}
table{width:100%;border-collapse:collapse;margin:12px 0;} td,th{padding:10px;text-align:left;border-bottom:1px solid #1e2d45;}
li{margin:6px 0;} .card{background:#0d1320;border:1px solid #1e2d45;border-radius:10px;padding:20px;margin:16px 0;}
</style></head><body>
<h1>&#x1F6E1; PhishGuard Security Report</h1>
<div class="card">
<h2>Overall Assessment</h2>
<div class="score">""" + str(score) + """/100</div>
<br><span class="risk">""" + risk + """ RISK</span>
<p>""" + a.get("verdict", "") + """</p>
<p><small>From: """ + str(meta.get("from","")) + """ &nbsp;|&nbsp; Subject: """ + str(meta.get("subject",""))[:80] + """ &nbsp;|&nbsp; Analyzed: """ + str(meta.get("analyzed_at","")) + """</small></p>
</div>
<div class="card"><h2>Recommendations</h2><ul>""" + recs_html + """</ul></div>
<div class="card"><h2>Authentication</h2><table><tr><th>Check</th><th>Status</th><th>Details</th></tr>""" + auth_rows + """</table></div>
<div class="card"><h2>Phishing Indicators</h2><ul>""" + ind_html + """</ul></div>
<p style="color:#4a6a8a;font-size:.75rem;margin-top:32px;">Generated by PhishGuard v2.0</p>
</body></html>"""


if __name__ == "__main__":
    analyzer = EmailSecurityAnalyzer()
    print("EmailSecurityAnalyzer v2.0 initialized successfully")
    print("Modules: EmailParser, EmailAuthChecker, PhishingDetector, ThreatIntelligence")
