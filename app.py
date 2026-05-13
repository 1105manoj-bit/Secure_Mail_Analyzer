"""
PhishGuard v2.0 — Complete Flask Application
Includes: Rate limiting, History, Blocklist, Header forensics
"""

import sys
import os

# Ensure Python finds all sibling modules regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import json
import re
import hashlib
from datetime import datetime

from main_analyzer import EmailSecurityAnalyzer
from history_manager import HistoryManager
from blocklist import BlocklistManager
from rate_limiter import RateLimiter

# Cross-platform paths
_HERE = os.path.dirname(os.path.abspath(__file__))
_STATIC = os.path.join(_HERE, "static")
_UPLOAD = os.path.join(_HERE, "uploads")

app = Flask(__name__, static_folder=_STATIC, static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = _UPLOAD
os.makedirs(_UPLOAD, exist_ok=True)

# Initialize all services
analyzer = EmailSecurityAnalyzer()
history = HistoryManager()
blocklist = BlocklistManager()
limiter = RateLimiter()

ALLOWED_EXTENSIONS = {"eml", "msg", "txt"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()


def rate_check(endpoint):
    ip = get_client_ip()
    limit, window = limiter.get_limits(endpoint)
    allowed, info = limiter.is_allowed(ip, endpoint, limit, window)
    if not allowed:
        return jsonify({"error": info["error"], "retry_after": info["retry_after_seconds"]}), 429
    return None


# ── SERVE UI ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return app.send_static_file("index.html")


# ── ANALYSIS ENDPOINTS ──────────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
def analyze_email():
    err = rate_check("analyze")
    if err: return err
    if "email" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["email"]
    if not file.filename or not allowed_file(file.filename):
        return jsonify({"error": "Invalid file. Upload .eml, .msg, or .txt"}), 400
    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = ts + "_" + secure_filename(file.filename)
        filepath = os.path.join(_UPLOAD, filename)
        file.save(filepath)
        report = analyzer.analyze_eml_file(filepath)
        os.remove(filepath)
        analysis_id = history.save(report)
        report["_id"] = analysis_id
        return jsonify({"success": True, "report": report})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/analyze-text", methods=["POST"])
def analyze_text():
    err = rate_check("analyze")
    if err: return err
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        body = data.get("body", "")
        subject = data.get("subject", "")

        # Detect dangerous file extensions mentioned in pasted email body
        dangerous_exts = [
            ".exe", ".bat", ".cmd", ".scr", ".vbs", ".ps1",
            ".msi", ".dll", ".reg", ".hta", ".jar", ".pif", ".lnk",
        ]
        combined_text = (body + " " + subject).lower()
        detected_attachments = []
        has_dangerous = False
        import re as _re2
        for ext in dangerous_exts:
            pattern = r"[\w\-]+" + ext.replace(".", "\\.")
            matches = _re2.findall(pattern, combined_text)
            for match in matches:
                has_dangerous = True
                detected_attachments.append({
                    "filename": match,
                    "content_type": "application/octet-stream",
                    "size": 0,
                    "is_dangerous": True,
                    "extension": ext,
                    "encoding": "none",
                })

        email_data = {
            "headers": data.get("headers", {}),
            "subject": subject,
            "from": data.get("from", ""),
            "to": data.get("to", ""),
            "reply_to": data.get("reply_to", ""),
            "date": data.get("date", ""),
            "body": body,
            "html_body": "",
            "attachments": detected_attachments,
            "routing_trace": [],
            "urls": analyzer.phishing_detector.extract_urls(body),
            "ip_addresses": [],
            "email_addresses": [],
            "has_dangerous_attachments": has_dangerous,
            "message_id": "",
        }
        report = analyzer.analyze_email_data(email_data)
        analysis_id = history.save(report)
        report["_id"] = analysis_id
        return jsonify({"success": True, "report": report})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/check-domain", methods=["POST"])
def check_domain():
    err = rate_check("check-domain")
    if err: return err
    try:
        data = request.get_json()
        domain = re.sub(r"^https?://", "", data.get("domain", "").strip().lower()).split("/")[0]
        if not domain:
            return jsonify({"error": "No domain provided"}), 400
        results = analyzer.auth_checker.check_all(domain)
        # Also check blocklist
        bl_result = blocklist.check_domain(domain)
        results["blocklist"] = bl_result
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/check-url", methods=["POST"])
def check_url():
    err = rate_check("check-url")
    if err: return err
    try:
        data = request.get_json()
        url = data.get("url", "").strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        results = analyzer.threat_intel.check_url_reputation(url)
        # Parse domain and check blocklist
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        if domain:
            results["blocklist"] = blocklist.check_domain(domain)
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/check-ip", methods=["POST"])
def check_ip():
    err = rate_check("check-url")
    if err: return err
    try:
        data = request.get_json()
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "No IP provided"}), 400
        result = analyzer.threat_intel.check_ip_reputation(ip)
        result["blocklist"] = blocklist.check_ip(ip)
        return jsonify({"success": True, "results": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/extract-iocs", methods=["POST"])
def extract_iocs():
    err = rate_check("extract-iocs")
    if err: return err
    try:
        data = request.get_json()
        text = data.get("text", "")
        if not text:
            return jsonify({"error": "No text provided"}), 400
        iocs = analyzer.threat_intel.extract_iocs(text)
        # Check each hash against blocklist
        flagged = []
        for h in iocs.get("hashes", {}).get("md5", []):
            r = blocklist.check_hash(h)
            if r["blocked"]:
                flagged.append({"type": "MD5", "value": h, "source": r["source"]})
        iocs["blocklist_hits"] = flagged
        return jsonify({"success": True, "iocs": iocs})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/hash-text", methods=["POST"])
def hash_text():
    try:
        data = request.get_json()
        text = data.get("text", "")
        if not text:
            return jsonify({"error": "No text provided"}), 400
        encoded = text.encode("utf-8")
        hashes = {
            "md5": hashlib.md5(encoded).hexdigest(),
            "sha1": hashlib.sha1(encoded).hexdigest(),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
        return jsonify({"success": True, "hashes": hashes, "blocklist": {
            h: blocklist.check_hash(v) for h, v in hashes.items()
        }})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── HISTORY ENDPOINTS ──────────────────────────────────────────────────

@app.route("/api/history", methods=["GET"])
def get_history():
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = int(request.args.get("offset", 0))
        records = history.get_all(limit, offset)
        return jsonify({"success": True, "records": records, "count": len(records)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/history/<int:analysis_id>", methods=["GET"])
def get_history_item(analysis_id):
    try:
        report = history.get_by_id(analysis_id)
        if not report:
            return jsonify({"error": "Not found"}), 404
        return jsonify({"success": True, "report": report})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/history/<int:analysis_id>", methods=["DELETE"])
def delete_history_item(analysis_id):
    try:
        history.delete(analysis_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/history/search", methods=["GET"])
def search_history():
    try:
        q = request.args.get("q", "").strip()
        if not q:
            return jsonify({"error": "No query"}), 400
        results = history.search(q)
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── STATS & DASHBOARD ──────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
def get_stats():
    try:
        stats = history.get_stats()
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── BLOCKLIST ENDPOINTS ─────────────────────────────────────────────────

@app.route("/api/blocklist", methods=["GET"])
def get_blocklist():
    return jsonify({"success": True, "blocklist": blocklist.get_all()})


@app.route("/api/blocklist/add", methods=["POST"])
def add_to_blocklist():
    try:
        data = request.get_json()
        ioc_type = data.get("type", "")
        value = data.get("value", "").strip()
        if not value:
            return jsonify({"error": "No value provided"}), 400
        if ioc_type == "domain":
            added = blocklist.add_domain(value)
        elif ioc_type == "ip":
            added = blocklist.add_ip(value)
        elif ioc_type == "hash":
            added = blocklist.add_hash(value)
        else:
            return jsonify({"error": "Type must be domain, ip, or hash"}), 400
        return jsonify({"success": True, "added": added, "value": value})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── EXPORT ─────────────────────────────────────────────────────────────

@app.route("/api/export-report", methods=["POST"])
def export_report():
    try:
        data = request.get_json()
        report = data.get("report")
        fmt = data.get("format", "json")
        if not report:
            return jsonify({"error": "No report data"}), 400
        exported = analyzer.export_report(report, fmt)
        ext_map = {"json": "json", "text": "txt", "html": "html"}
        ext = ext_map.get(fmt, "txt")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        tmp_path = os.path.join(_UPLOAD, f"phishguard_report_{ts}.{ext}")
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(exported)
        return send_file(tmp_path, as_attachment=True,
                         download_name=os.path.basename(tmp_path))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── HEALTH ────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    stats = history.get_stats()
    return jsonify({
        "status": "healthy",
        "service": "PhishGuard",
        "version": "2.0.0",
        "total_analyses": stats["total"],
        "db_path": history.db_path,
    })


if __name__ == "__main__":
    print("=" * 60)
    print("  PHISHGUARD v2.0 — Email Security Analyzer")
    print("=" * 60)
    print(f"  UI  → http://localhost:5000")
    print(f"  API → http://localhost:5000/api/")
    print(f"  DB  → {history.db_path}")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)