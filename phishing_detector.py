import re
from typing import Dict, List, Optional
from urllib.parse import urlparse


class PhishingDetector:
    def __init__(self):
        self.urgency_keywords = [
            "urgent", "immediate", "action required", "act now",
            "limited time", "expires", "final notice", "last chance",
            "within 24 hours", "deadline", "time sensitive", "asap",
            "critical", "alert", "warning", "attention"
        ]
        self.threat_keywords = [
            "account suspended", "account blocked", "account will be closed",
            "legal action", "lawsuit", "unauthorized access",
            "security breach", "compromised", "criminal charges",
            # ATM / card blocking threats
            "atm will be blocked", "card will be blocked", "account will be blocked",
            "atm blocked", "card blocked", "will be deactivated",
            "will be suspended", "will be terminated", "will be closed",
            "blocked within", "suspended within", "terminated within",
            "deactivated within", "access will be revoked",
        ]
        self.reward_keywords = [
            "you have won", "winner", "prize", "lottery", "selected",
            "congratulations", "free gift", "reward", "unclaimed",
            "inheritance", "million dollars", "bank transfer",
            "amazon gift card", "itunes gift card"
        ]
        self.credential_keywords = [
            "verify your account", "confirm your identity", "update your password",
            "reset your password", "validate your email", "update billing",
            "login to verify", "click here to verify", "update payment",
            # ATM / banking / PIN theft
            "send your pin", "send pin", "your pin", "atm pin", "pin number",
            "verify your pin", "confirm your pin", "enter your pin",
            "send your otp", "your otp", "send otp", "otp verification",
            "send your cvv", "card number", "card details", "card verification",
            "account number", "routing number", "bank details",
            "send your password", "share your password", "your password",
            "social security", "ssn", "date of birth", "mother maiden",
            "security question", "secret answer",
            # POP / credential jargon used in scams
            "send your pop", "send pop", "send the pop",
            "send your details", "send details", "provide your details",
            "send your information", "provide your information",
        ]
        self.impersonated_brands = {
            "microsoft": ["microsoft", "outlook", "office365", "o365", "azure"],
            "google": ["google", "gmail", "youtube"],
            "apple": ["apple", "icloud", "itunes"],
            "amazon": ["amazon", "aws", "prime"],
            "paypal": ["paypal"],
            "facebook": ["facebook", "meta", "instagram", "whatsapp"],
            "netflix": ["netflix"],
            "bank": ["bank", "chase", "wells fargo", "citibank", "hsbc"],
            "irs": ["irs", "internal revenue", "tax refund"],
            "fedex": ["fedex", "ups", "dhl", "usps"],
        }
        self.bec_patterns = [
            r"wire transfer", r"bank transfer",
            r"change.{0,20}(bank|account|routing)",
            r"update.{0,20}(payment|direct deposit)",
            r"urgent.{0,20}(payment|wire|transfer)",
        ]

    def analyze_email(self, email_data):
        subject = email_data.get("subject", "")
        body = email_data.get("body", "")
        headers = email_data.get("headers", {})
        from_addr = email_data.get("from", headers.get("from", ""))
        reply_to = email_data.get("reply_to", headers.get("reply-to", ""))
        full_text = (subject + " " + body).lower()
        content = self._analyze_content(subject, body, full_text)
        header = self._analyze_headers(headers, from_addr, reply_to)
        url = self._analyze_urls(email_data.get("urls", []))
        brand = self._detect_brand_impersonation(full_text, from_addr)
        bec = self._detect_bec(full_text)
        banking = self._detect_banking_scam(full_text)
        total_score = content["score"] + header["score"] + url["score"] + brand["score"] + bec["score"] + banking["score"]
        risk_level = self._score_to_risk(total_score)
        all_indicators = content["indicators"] + header["indicators"] + url["indicators"] + brand["indicators"] + bec["indicators"] + banking["indicators"]
        return {
            "risk_level": risk_level,
            "total_score": total_score,
            "summary": self._generate_summary(risk_level, all_indicators),
            "content_analysis": content,
            "header_analysis": header,
            "url_analysis": url,
            "brand_impersonation": brand,
            "bec_analysis": bec,
            "banking_scam": banking,
            "indicators": all_indicators,
            "suspicious": total_score < -20,
        }

    def _analyze_content(self, subject, body, full_text):
        result = {"score": 0, "indicators": [], "suspicious": False}
        urgency_found = [kw for kw in self.urgency_keywords if kw in full_text]
        if urgency_found:
            result["score"] -= min(len(urgency_found) * 5, 25)
            result["indicators"].append("Urgency language: " + ", ".join(urgency_found[:3]))
        threats_found = [kw for kw in self.threat_keywords if kw in full_text]
        if threats_found:
            result["score"] -= min(len(threats_found) * 8, 30)
            result["indicators"].append("Threatening language detected: " + str(len(threats_found)) + " pattern(s)")
        rewards_found = [kw for kw in self.reward_keywords if kw in full_text]
        if rewards_found:
            result["score"] -= min(len(rewards_found) * 7, 25)
            result["indicators"].append("Reward or lure language detected")
        creds_found = [kw for kw in self.credential_keywords if kw in full_text]
        if creds_found:
            result["score"] -= min(len(creds_found) * 10, 30)
            result["indicators"].append("Credential harvesting phrases detected")
        if subject:
            up_ratio = sum(1 for c in subject if c.isupper()) / max(len(subject), 1)
            if up_ratio > 0.5 and len(subject) > 5:
                result["score"] -= 10
                result["indicators"].append("Subject uses excessive CAPS")
            if re.search(r"[!?]{2,}", subject):
                result["score"] -= 5
                result["indicators"].append("Excessive punctuation in subject")
        body_words = len(body.split()) if body else 0
        if 0 < body_words < 10:
            result["score"] -= 10
            result["indicators"].append("Very short email body (possible lure)")
        result["suspicious"] = result["score"] < -15
        return result

    def _analyze_headers(self, headers, from_addr, reply_to):
        result = {"score": 0, "indicators": [], "suspicious": False}
        if reply_to and from_addr:
            fd = self._extract_domain(from_addr)
            rd = self._extract_domain(reply_to)
            if fd and rd and fd != rd:
                result["score"] -= 30
                result["indicators"].append("Reply-To domain (" + rd + ") differs from From domain (" + fd + ")")
        if from_addr:
            m = re.match(r'"?([^"<]+)"?\s*<([^>]+)>', from_addr)
            if m:
                display_name = m.group(1).lower().strip()
                email_domain = self._extract_domain(m.group(2)) or ""
                for brand, keywords in self.impersonated_brands.items():
                    if any(kw in display_name for kw in keywords):
                        if brand not in email_domain:
                            result["score"] -= 35
                            result["indicators"].append("Display name claims to be " + brand.title() + " but email from " + email_domain)
                            break
        msg_id = headers.get("message-id", "")
        if not msg_id:
            result["score"] -= 10
            result["indicators"].append("Missing Message-ID header")
        result["suspicious"] = result["score"] < -20
        return result

    def _analyze_urls(self, urls):
        result = {"score": 0, "indicators": [], "suspicious_urls": [], "url_count": len(urls), "suspicious": False}
        for url in urls[:20]:
            url_issues = []
            url_score = 0
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                path = parsed.path.lower()
                if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
                    url_issues.append("IP address used as domain")
                    url_score -= 20
                if re.search(r"bit\.ly|tinyurl|ow\.ly|t\.co|goo\.gl", domain):
                    url_issues.append("URL shortener detected")
                    url_score -= 15
                if "@" in url:
                    url_issues.append("@ symbol in URL (redirect trick)")
                    url_score -= 25
                if len(domain.split(".")) > 4:
                    url_issues.append("Excessive subdomain depth")
                    url_score -= 10
                if re.search(r"\.(tk|ml|ga|cf|gq)$", domain):
                    url_issues.append("Free TLD commonly used for phishing")
                    url_score -= 15
                for dp in ["login", "signin", "account", "verify", "secure", "update", "confirm"]:
                    if dp in path:
                        url_issues.append("Deceptive path keyword: /" + dp + "/")
                        url_score -= 8
                        break
                if len(url) > 200:
                    url_issues.append("Extremely long URL (" + str(len(url)) + " chars)")
                    url_score -= 10
                if url_issues:
                    result["suspicious_urls"].append({"url": url[:100], "issues": url_issues, "score": url_score})
                    result["score"] += url_score
            except Exception:
                continue
        if result["suspicious_urls"]:
            result["indicators"].append(str(len(result["suspicious_urls"])) + " suspicious URL(s) detected")
        result["suspicious"] = result["score"] < -15
        return result

    def _detect_brand_impersonation(self, full_text, from_addr):
        result = {"score": 0, "indicators": [], "impersonated_brand": None, "suspicious": False}
        from_domain = self._extract_domain(from_addr) or ""
        brand_mentions = {}
        for brand, keywords in self.impersonated_brands.items():
            count = sum(1 for kw in keywords if kw in full_text)
            if count > 0:
                brand_mentions[brand] = count
        if not brand_mentions:
            return result
        top_brand = max(brand_mentions, key=brand_mentions.get)
        mention_count = brand_mentions[top_brand]
        legit_domains = {
            "microsoft": ["microsoft.com", "outlook.com", "live.com"],
            "google": ["google.com", "gmail.com"],
            "apple": ["apple.com", "icloud.com"],
            "amazon": ["amazon.com"],
            "paypal": ["paypal.com"],
            "facebook": ["facebook.com", "meta.com"],
            "netflix": ["netflix.com"],
        }
        is_legit = any(from_domain.endswith(d) for d in legit_domains.get(top_brand, [])) if from_domain else False
        if mention_count >= 1 and not is_legit and from_domain:
            penalty = 30 if mention_count >= 3 else 15
            result["score"] -= penalty
            result["impersonated_brand"] = top_brand
            result["indicators"].append("Possible " + top_brand.title() + " impersonation from: " + from_domain)
            result["suspicious"] = True
        return result

    def _detect_bec(self, full_text):
        result = {"score": 0, "indicators": [], "patterns_found": [], "suspicious": False}
        for pattern in self.bec_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                result["patterns_found"].append(pattern)
                result["score"] -= 15
        if result["patterns_found"]:
            result["suspicious"] = True
            result["indicators"].append("BEC indicators: " + str(len(result["patterns_found"])) + " wire transfer/payment fraud pattern(s)")
        return result

    def extract_urls(self, text):
        if not text:
            return []
        urls = re.findall(r"https?://[^\s<>\"{}|\\^`\[\]]{3,}", text, re.IGNORECASE)
        clean = []
        for url in urls:
            url = re.sub(r"[.,;:!?)\]>]+$", "", url)
            if url and url not in clean:
                clean.append(url)
        return clean[:50]

    def _extract_domain(self, email_addr):
        if not email_addr:
            return None
        m = re.search(r"@([\w\.\-]+)", email_addr)
        return m.group(1).lower() if m else None

    def _detect_banking_scam(self, full_text: str) -> dict:
        """
        Specifically detects banking, ATM, PIN, and financial credential scams.
        These are extremely high confidence attacks and deserve heavy penalties.
        """
        result = {"score": 0, "indicators": [], "suspicious": False}

        # Direct PIN / OTP / CVV / password requests — NEVER legitimate over email
        direct_requests = [
            "send your pin", "send pin", "your pin",
            "send your otp", "your otp", "send otp",
            "send your cvv", "send cvv",
            "send your password", "share your password",
            "send your card", "send card details",
            "send your account", "send account number",
            "send your bank", "send bank details",
            "send your ssn", "send ssn",
            "send your social", "send social security",
            "send the pop", "send your pop",
            "send your details", "send your information",
            "send your credentials",
        ]
        hits = [kw for kw in direct_requests if kw in full_text]
        if hits:
            result["score"] -= 60
            result["suspicious"] = True
            result["indicators"].append(
                "Direct credential request detected: \"" + hits[0] + "\" — "
                "NO legitimate organisation ever asks for PIN, OTP, CVV or passwords over email"
            )

        # ATM / bank / card blocking threats
        blocking_threats = [
            "atm will be blocked", "card will be blocked",
            "atm will be deactivated", "card will be deactivated",
            "atm blocked", "will be blocked", "get blocked",
            "block your atm", "block your card", "block your account",
        ]
        block_hits = [kw for kw in blocking_threats if kw in full_text]
        if block_hits:
            result["score"] -= 40
            result["suspicious"] = True
            result["indicators"].append(
                "Banking threat detected: \"" + block_hits[0] + "\" — "
                "pressure tactic to force victim to hand over credentials"
            )

        # Grammar/spelling patterns common in scam emails
        # These are specific misspellings frequently seen in financial scams
        scam_spelling = [
            "verrify", "verfy", "verifi",
            "recieve", "priviledge", "beneficiary",
            "kindly revert", "kindly send", "kindly provide",
            "do the needful", "revert back",
            "i am mr", "i am mrs", "my name is mr", "my name is mrs",
            "i am contacting you", "i am writing to inform",
            "dear beneficiary", "dear friend", "dear customer",
        ]
        spelling_hits = [kw for kw in scam_spelling if kw in full_text]
        if spelling_hits:
            result["score"] -= 20
            result["suspicious"] = True
            result["indicators"].append(
                "Scam email language pattern detected: \"" + spelling_hits[0] + "\""
            )

        # Advance fee / Nigerian prince style patterns
        advance_fee = [
            "transfer the sum", "transfer of funds", "sum of money",
            "million dollars", "million usd", "million pounds",
            "next of kin", "inheritance", "deceased",
            "secret business", "confidential proposal",
            "god bless you", "may god", "in god",
            "i need your assistance", "i need your help",
            "percentage of the funds", "percentage of the money",
        ]
        fee_hits = [kw for kw in advance_fee if kw in full_text]
        if fee_hits:
            result["score"] -= 35
            result["suspicious"] = True
            result["indicators"].append(
                "Advance fee fraud pattern: \"" + fee_hits[0] + "\""
            )

        return result

    def _score_to_risk(self, score):
        if score >= -10:
            return "LOW"
        elif score >= -30:
            return "MEDIUM"
        elif score >= -60:
            return "HIGH"
        else:
            return "CRITICAL"

    def _generate_summary(self, risk_level, indicators):
        if risk_level == "LOW":
            return "Email appears legitimate with few suspicious indicators."
        elif risk_level == "MEDIUM":
            return "Email shows " + str(len(indicators)) + " suspicious indicator(s). Exercise caution."
        elif risk_level == "HIGH":
            return "Email is likely phishing with " + str(len(indicators)) + " red flag(s). Do not interact."
        else:
            return "Email is almost certainly malicious with " + str(len(indicators)) + " critical indicator(s). Delete immediately."