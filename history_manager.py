# history_manager.py — NEW MODULE
"""
Analysis History Manager
SQLite-based persistent storage for all analyzed emails.
Enables trend detection, campaign correlation, and SOC dashboards.
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.getcwd(), "phishguard_history.db")


class HistoryManager:
    """
    Persists every analysis result to SQLite.
    Provides statistics, search, trend analysis, and campaign detection.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analyzed_at TEXT NOT NULL,
                    subject TEXT,
                    sender TEXT,
                    sender_domain TEXT,
                    risk_level TEXT,
                    security_score INTEGER,
                    verdict TEXT,
                    spf_status TEXT,
                    dkim_status TEXT,
                    dmarc_status TEXT,
                    phishing_score INTEGER,
                    has_dangerous_attachments INTEGER,
                    url_count INTEGER,
                    ioc_count INTEGER,
                    indicators TEXT,
                    full_report TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_risk ON analyses(risk_level)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_date ON analyses(analyzed_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON analyses(sender_domain)")

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def save(self, report: Dict) -> int:
        meta = report.get("metadata", {})
        oa = report.get("overall_assessment", {})
        auth = report.get("authentication") or {}
        ph = report.get("phishing_indicators", {})
        ti = report.get("threat_intelligence", {})
        iocs = ti.get("iocs", {})
        ioc_count = (
            len(iocs.get("hashes", {}).get("md5", [])) +
            len(iocs.get("hashes", {}).get("sha256", [])) +
            len(iocs.get("network", {}).get("ips", [])) +
            len(iocs.get("crypto", {}).get("btc_addresses", []))
        )
        indicators_json = json.dumps(ph.get("indicators", []))
        with self._conn() as conn:
            cursor = conn.execute("""
                INSERT INTO analyses
                (analyzed_at, subject, sender, sender_domain, risk_level, security_score,
                 verdict, spf_status, dkim_status, dmarc_status, phishing_score,
                 has_dangerous_attachments, url_count, ioc_count, indicators, full_report)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                meta.get("analyzed_at", datetime.now().isoformat()),
                meta.get("subject", "")[:255],
                meta.get("from", "")[:255],
                meta.get("sender_domain", "")[:100],
                oa.get("risk_level", "UNKNOWN"),
                oa.get("security_score", 0),
                oa.get("verdict", "")[:500],
                auth.get("spf", {}).get("status", "none"),
                auth.get("dkim", {}).get("status", "none"),
                auth.get("dmarc", {}).get("status", "none"),
                ph.get("total_score", 0),
                1 if report.get("attachments", {}).get("has_dangerous") else 0,
                len(report.get("raw_data", {}).get("urls_found", [])),
                ioc_count,
                indicators_json,
                json.dumps(report, default=str)[:50000]
            ))
            return cursor.lastrowid

    def get_all(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT id, analyzed_at, subject, sender, sender_domain,
                       risk_level, security_score, spf_status, dkim_status,
                       dmarc_status, ioc_count, url_count, has_dangerous_attachments
                FROM analyses ORDER BY analyzed_at DESC LIMIT ? OFFSET ?
            """, (limit, offset)).fetchall()
            return [dict(r) for r in rows]

    def get_by_id(self, analysis_id: int) -> Optional[Dict]:
        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT full_report FROM analyses WHERE id=?", (analysis_id,)
            ).fetchone()
            if row:
                return json.loads(row["full_report"])
            return None

    def get_stats(self) -> Dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            by_risk = dict(conn.execute(
                "SELECT risk_level, COUNT(*) FROM analyses GROUP BY risk_level"
            ).fetchall())
            last_7d = conn.execute(
                "SELECT COUNT(*) FROM analyses WHERE analyzed_at >= ?",
                ((datetime.now() - timedelta(days=7)).isoformat(),)
            ).fetchone()[0]
            avg_score = conn.execute(
                "SELECT AVG(security_score) FROM analyses"
            ).fetchone()[0]
            dangerous_att = conn.execute(
                "SELECT COUNT(*) FROM analyses WHERE has_dangerous_attachments=1"
            ).fetchone()[0]
            top_senders = conn.execute("""
                SELECT sender_domain, COUNT(*) as cnt
                FROM analyses WHERE risk_level IN ('HIGH','CRITICAL')
                GROUP BY sender_domain ORDER BY cnt DESC LIMIT 5
            """).fetchall()
            return {
                "total": total,
                "last_7_days": last_7d,
                "avg_score": round(avg_score or 0, 1),
                "by_risk": by_risk,
                "dangerous_attachments": dangerous_att,
                "top_threat_domains": [{"domain": r[0], "count": r[1]} for r in top_senders],
            }

    def search(self, query: str) -> List[Dict]:
        q = "%" + query + "%"
        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT id, analyzed_at, subject, sender, risk_level, security_score
                FROM analyses
                WHERE subject LIKE ? OR sender LIKE ? OR sender_domain LIKE ?
                ORDER BY analyzed_at DESC LIMIT 50
            """, (q, q, q)).fetchall()
            return [dict(r) for r in rows]

    def delete(self, analysis_id: int) -> bool:
        with self._conn() as conn:
            conn.execute("DELETE FROM analyses WHERE id=?", (analysis_id,))
            return True

    def clear_all(self) -> int:
        with self._conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            conn.execute("DELETE FROM analyses")
            return count