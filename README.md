# PhishGuard — Email Security Analyzer

I built this because I wanted to understand how phishing emails actually work under the hood — not just "this looks sketchy" but the actual technical reasons why an email is dangerous. So I made a tool that breaks down every part of a suspicious email and tells you exactly what's wrong with it.

It's a local web app. You run it on your machine, open the browser, paste or upload an email, and it tells you whether it's safe or not and why.

## What it checks

When you give it an email it does all of this automatically:

**Authentication** — it does a real live DNS lookup to check whether the sender's domain has SPF, DKIM, and DMARC set up properly. If someone is pretending to be PayPal but sending from a random `.tk` domain, the authentication check catches it instantly. It gives the domain a grade from A+ to F.
**Phishing content** — scans the email body for pressure tactics like "your account will be suspended in 24 hours", threats, reward lures, credential harvesting phrases, and brand impersonation. If the display name says "PayPal Security" but the actual email address is from some sketchy domain, that gets flagged.
**BEC fraud** — specifically looks for business email compromise patterns. Wire transfer requests, payment redirection, "urgent CEO request" type emails, and the classic "don't tell anyone, I'm in a meeting" line.
**Banking and ATM scams** — detects when someone is asking you to send your PIN, OTP, CVV, or card details over email. No legitimate bank or company ever does this. Ever. So when it shows up in an email it's always flagged as critical.
**Dangerous attachments** — checks file extensions on attachments. `.exe`, `.bat`, `.vbs`, `.ps1` and around 30 other types are immediately flagged. Also catches the double extension trick like `invoice.pdf.exe` where it looks like a PDF but is actually an executable.
**URL analysis** — checks every link in the email for things like IP addresses being used as domains, URL shorteners hiding the real destination, free TLDs (.tk .ml .ga) that scammers love, brand names appearing in subdomains of fake sites, and deceptive path keywords like `/login/verify`.
**Header forensics** — reads the routing headers to see what servers the email actually passed through, checks for Reply-To addresses that are different from the From address, detects missing headers that legitimate emails always have, and identifies bulk mailer software being used.
**IOC extraction** — pulls out all indicators of compromise from the email. File hashes (MD5, SHA1, SHA256), IP addresses, email addresses, and even Bitcoin wallet addresses if there are any.

Everything gets scored from 0 to 100 and categorized as LOW, MEDIUM, HIGH, or CRITICAL risk.

## Getting started

You need Python 3.8 or newer. That's it.

```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
pip install -r requirements.txt
python app.py
```

Open your browser and go to **http://localhost:5000**

If domain checks are showing wrong results on Windows, make sure dnspython installed correctly:

```bash
python -c "import dns; print('DNS working')"
```

If that fails, run `pip install dnspython` again.

## The pages

**Analyze Email** — the main page. Upload a `.eml` file or paste the email content manually. If you paste, fill in the From, Reply-To, Subject, and Body fields. The more info you give it the more accurate the analysis.
**Domain Check** — type any domain and it checks SPF, DKIM, and DMARC via live DNS. Useful for checking where an email came from or checking your own domain's setup. Try `google.com` vs `paypal-secure-login.tk` and see the difference.
**URL Check** — paste any suspicious link and it analyzes it without you actually visiting it. Checks for phishing patterns, SSL issues, suspicious TLDs, and more.
**IOC Extractor** — paste any block of text (email headers, log files, malware reports, anything) and it pulls out all the threat indicators automatically. Hashes, IPs, emails, Bitcoin addresses.
**Dashboard** — shows stats across all emails you've analyzed. How many were CRITICAL, average score, which domains keep showing up as threats, dangerous attachment count.
**History** — every email you analyze is saved automatically. You can search through old analyses, click any row to reload the full report, and delete individual records.
**Blocklist** — add your own malicious domains, IP addresses, or file hashes. Once added they get checked automatically in every future analysis.

## Test emails

There are 5 test `.eml` files in the `test_emails` folder you can use right away:

| File | What it tests |
|---|---|
| `dangerous_attachment_test.eml` | Three dangerous attachments — .bat, .exe, .vbs |
| `paypal_phishing_test.eml` | PayPal impersonation with suspicious URLs and IOCs |
| `bec_wire_transfer_test.eml` | Business email compromise, wire transfer fraud |
| `atm_pin_scam_test.eml` | ATM PIN theft, OTP request, blocking threats |
| `legitimate_github_test.eml` | Clean email — should score 90/100 LOW risk |

Upload any of these through the Analyze Email page to see the tool in action.

---

## API

If you want to use it without the browser:

```bash
# Analyze an email file
curl -X POST -F "email=@suspicious.eml" http://localhost:5000/api/analyze

# Check a domain
curl -X POST -H "Content-Type: application/json" \
  -d '{"domain": "paypal-secure.tk"}' \
  http://localhost:5000/api/check-domain

# Check a URL
curl -X POST -H "Content-Type: application/json" \
  -d '{"url": "http://bit.ly/suspicious"}' \
  http://localhost:5000/api/check-url

# Extract IOCs from text
curl -X POST -H "Content-Type: application/json" \
  -d '{"text": "paste your headers or logs here"}' \
  http://localhost:5000/api/extract-iocs
```
Full endpoint list:

| Endpoint | What it does |
|---|---|
| POST `/api/analyze` | Upload .eml file for full analysis |
| POST `/api/analyze-text` | Analyze pasted email content |
| POST `/api/check-domain` | SPF, DKIM, DMARC check via live DNS |
| POST `/api/check-url` | URL reputation and phishing pattern check |
| POST `/api/check-ip` | IP address reputation check |
| POST `/api/extract-iocs` | Pull indicators of compromise from any text |
| POST `/api/export-report` | Download report as JSON, plain text, or HTML |
| GET `/api/history` | List all past analyses |
| GET `/api/history/<id>` | Get a specific analysis by ID |
| GET `/api/stats` | Dashboard statistics |
| GET `/api/blocklist` | View your custom blocklist |
| POST `/api/blocklist/add` | Add domain, IP, or hash to blocklist |
| GET `/health` | Check if the service is running |

## Project structure

```
phishguard/
├── app.py                # Flask server, all API routes, rate limiting
├── main_analyzer.py      # Orchestrates all modules, calculates scores
├── email_parser.py       # Reads .eml files, extracts all data
├── auth_checker.py       # SPF, DKIM, DMARC via live DNS
├── phishing_detector.py  # Heuristic phishing and scam detection
├── threat_intel.py       # URL reputation, IOC extraction, IP checks
├── header_analyzer.py    # Deep header forensics
├── history_manager.py    # SQLite database for analysis history
├── blocklist.py          # Custom threat blocklist management
├── rate_limiter.py       # API rate limiting (10 analyses/min per IP)
├── requirements.txt
├── test_emails/          # 5 ready-to-use test .eml files
└── static/
    └── index.html        # Full web UI, 8 pages, no frontend framework
```

## Honest limitations

This tool is genuinely useful for learning and for checking suspicious emails, but it has real limitations you should know about:

The phishing detection uses keyword matching that we wrote ourselves. A careful attacker who knows the rules could rephrase things to bypass it. Real enterprise tools use ML models trained on billions of emails.

The blocklist starts with only about 9 known-bad domains. It doesn't sync with any live threat feed. A phishing domain registered yesterday won't be in it unless you add it yourself.

The URL checker looks at patterns in the URL text. It doesn't actually visit the page, take a screenshot, or detonate anything in a sandbox like professional tools do.

The SSL check actually connects to sites when it can, but if your network blocks outbound connections from Python the live checks won't work. The pattern checks always work regardless.

If you want to make it more powerful, integrating the free tier of VirusTotal API (500 lookups/day free) would be the single biggest upgrade you could make.

## Things I might add later

- VirusTotal API integration for file hash and URL lookups
- AlienVault OTX threat feed sync for the blocklist
- Bulk analysis — drop a whole folder of .eml files
- Email notification when CRITICAL emails are found
- Login system if you want to run it for a whole team

Built with Python and Flask. The UI is plain HTML, CSS, and JavaScript — no frameworks, no build tools, just one file. SQLite for the history database, no setup needed.
