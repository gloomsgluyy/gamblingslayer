import sqlite3
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from config import DB_PATH

def get_connection():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'queued',
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            total_urls INTEGER DEFAULT 0,
            scanned_urls INTEGER DEFAULT 0,
            keywords TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            url TEXT NOT NULL,
            domain TEXT,
            category TEXT,
            score INTEGER DEFAULT 0,
            ai_score INTEGER DEFAULT 0,
            final_score INTEGER DEFAULT 0,
            title TEXT,
            content_preview TEXT,
            detected_keywords TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE NOT NULL,
            url TEXT NOT NULL,
            reporter_type TEXT DEFAULT 'anonymous',
            description TEXT,
            status TEXT DEFAULT 'pending',
            priority INTEGER DEFAULT 0,
            scan_result_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP,
            FOREIGN KEY (scan_result_id) REFERENCES scan_results(id)
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            ip_addresses TEXT,
            nameservers TEXT,
            registrar TEXT,
            creation_date TEXT,
            expiration_date TEXT,
            ssl_issuer TEXT,
            ssl_expiry TEXT,
            asn TEXT,
            hosting_provider TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            record_type TEXT NOT NULL,
            record_value TEXT,
            resolver TEXT,
            ttl INTEGER,
            captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS domain_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_domain TEXT NOT NULL,
            target_domain TEXT NOT NULL,
            relation_type TEXT,
            confidence INTEGER DEFAULT 0,
            evidence TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS infrastructure_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            change_type TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS behavior_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            behavior_type TEXT NOT NULL,
            description TEXT,
            metadata TEXT,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS weak_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            weakness_type TEXT NOT NULL,
            severity TEXT,
            description TEXT,
            remediation TEXT,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_id TEXT UNIQUE NOT NULL,
            domains TEXT,
            events TEXT,
            timeline TEXT,
            analysis TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE NOT NULL,
            title TEXT,
            summary TEXT,
            domains TEXT,
            findings TEXT,
            recommendations TEXT,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    """)
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_category ON scan_results(category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_history_domain ON dns_history(domain)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)")
    
    conn.commit()
    conn.close()

class DatabaseManager:
    def __init__(self):
        init_database()
    
    def create_scan(self, scan_id: str, keywords: List[str]) -> bool:
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO scans (scan_id, keywords, started_at) VALUES (?, ?, ?)",
                (scan_id, json.dumps(keywords), datetime.now())
            )
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()
    
    def update_scan_status(self, scan_id: str, status: str, scanned: int = None, total: int = None):
        conn = get_connection()
        updates = ["status = ?"]
        params = [status]
        
        if scanned is not None:
            updates.append("scanned_urls = ?")
            params.append(scanned)
        if total is not None:
            updates.append("total_urls = ?")
            params.append(total)
        if status == "completed":
            updates.append("completed_at = ?")
            params.append(datetime.now())
        
        params.append(scan_id)
        conn.execute(f"UPDATE scans SET {', '.join(updates)} WHERE scan_id = ?", params)
        conn.commit()
        conn.close()
    
    def add_scan_result(self, scan_id: str, result: Dict[str, Any]) -> int:
        conn = get_connection()
        cursor = conn.execute(
            """INSERT INTO scan_results 
               (scan_id, url, domain, category, score, ai_score, final_score, 
                title, content_preview, detected_keywords, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                result.get("url"),
                result.get("domain"),
                result.get("category"),
                result.get("score", 0),
                result.get("ai_score", 0),
                result.get("final_score", 0),
                result.get("title"),
                result.get("content_preview"),
                json.dumps(result.get("detected_keywords", [])),
                json.dumps(result.get("metadata", {}))
            )
        )
        result_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return result_id
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        conn = get_connection()
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        conn.close()
        return dict(row) if row else None
    
    def get_scan_results(self, scan_id: str, category: str = None) -> List[Dict]:
        conn = get_connection()
        query = "SELECT * FROM scan_results WHERE scan_id = ?"
        params = [scan_id]
        if category:
            query += " AND category = ?"
            params.append(category)
        query += " ORDER BY final_score DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def create_report(self, report_id: str, url: str, description: str = None, reporter_type: str = "anonymous") -> bool:
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO reports (report_id, url, description, reporter_type) VALUES (?, ?, ?, ?)",
                (report_id, url, description, reporter_type)
            )
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()
    
    def get_reports(self, status: str = None, limit: int = 100) -> List[Dict]:
        conn = get_connection()
        query = "SELECT * FROM reports"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def update_report_status(self, report_id: str, status: str):
        conn = get_connection()
        conn.execute(
            "UPDATE reports SET status = ?, updated_at = ? WHERE report_id = ?",
            (status, datetime.now(), report_id)
        )
        conn.commit()
        conn.close()
    
    def save_domain_info(self, domain: str, info: Dict[str, Any]):
        conn = get_connection()
        existing = conn.execute("SELECT id FROM domains WHERE domain = ?", (domain,)).fetchone()
        
        if existing:
            conn.execute(
                """UPDATE domains SET 
                   ip_addresses = ?, nameservers = ?, registrar = ?,
                   creation_date = ?, expiration_date = ?, ssl_issuer = ?,
                   ssl_expiry = ?, asn = ?, hosting_provider = ?,
                   last_seen = ?, metadata = ?
                   WHERE domain = ?""",
                (
                    json.dumps(info.get("ip_addresses", [])),
                    json.dumps(info.get("nameservers", [])),
                    info.get("registrar"),
                    info.get("creation_date"),
                    info.get("expiration_date"),
                    info.get("ssl_issuer"),
                    info.get("ssl_expiry"),
                    info.get("asn"),
                    info.get("hosting_provider"),
                    datetime.now(),
                    json.dumps(info.get("metadata", {})),
                    domain
                )
            )
        else:
            conn.execute(
                """INSERT INTO domains 
                   (domain, ip_addresses, nameservers, registrar, creation_date,
                    expiration_date, ssl_issuer, ssl_expiry, asn, hosting_provider, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    domain,
                    json.dumps(info.get("ip_addresses", [])),
                    json.dumps(info.get("nameservers", [])),
                    info.get("registrar"),
                    info.get("creation_date"),
                    info.get("expiration_date"),
                    info.get("ssl_issuer"),
                    info.get("ssl_expiry"),
                    info.get("asn"),
                    info.get("hosting_provider"),
                    json.dumps(info.get("metadata", {}))
                )
            )
        conn.commit()
        conn.close()
    
    def save_dns_record(self, domain: str, record_type: str, value: str, resolver: str, ttl: int = None):
        conn = get_connection()
        conn.execute(
            "INSERT INTO dns_history (domain, record_type, record_value, resolver, ttl) VALUES (?, ?, ?, ?, ?)",
            (domain, record_type, value, resolver, ttl)
        )
        conn.commit()
        conn.close()
    
    def save_domain_relation(self, source: str, target: str, relation_type: str, confidence: int, evidence: str = None):
        conn = get_connection()
        conn.execute(
            "INSERT INTO domain_relations (source_domain, target_domain, relation_type, confidence, evidence) VALUES (?, ?, ?, ?, ?)",
            (source, target, relation_type, confidence, evidence)
        )
        conn.commit()
        conn.close()
    
    def save_infrastructure_change(self, domain: str, change_type: str, old_value: str, new_value: str):
        conn = get_connection()
        conn.execute(
            "INSERT INTO infrastructure_changes (domain, change_type, old_value, new_value) VALUES (?, ?, ?, ?)",
            (domain, change_type, old_value, new_value)
        )
        conn.commit()
        conn.close()
    
    def save_behavior_log(self, domain: str, behavior_type: str, description: str, metadata: Dict = None):
        conn = get_connection()
        conn.execute(
            "INSERT INTO behavior_logs (domain, behavior_type, description, metadata) VALUES (?, ?, ?, ?)",
            (domain, behavior_type, description, json.dumps(metadata or {}))
        )
        conn.commit()
        conn.close()
    
    def save_weak_link(self, domain: str, weakness_type: str, severity: str, description: str, remediation: str = None):
        conn = get_connection()
        conn.execute(
            "INSERT INTO weak_links (domain, weakness_type, severity, description, remediation) VALUES (?, ?, ?, ?, ?)",
            (domain, weakness_type, severity, description, remediation)
        )
        conn.commit()
        conn.close()
    
    def save_attack_chain(self, chain_id: str, chain_data: Dict[str, Any]):
        conn = get_connection()
        conn.execute(
            "INSERT INTO attack_chains (chain_id, domains, events, timeline, analysis) VALUES (?, ?, ?, ?, ?)",
            (
                chain_id,
                json.dumps(chain_data.get("domains", [])),
                json.dumps(chain_data.get("events", [])),
                json.dumps(chain_data.get("timeline", [])),
                json.dumps(chain_data.get("analysis", {}))
            )
        )
        conn.commit()
        conn.close()
    
    def save_evidence_report(self, report_id: str, report_data: Dict[str, Any]):
        conn = get_connection()
        conn.execute(
            "INSERT INTO evidence_reports (report_id, title, summary, domains, findings, recommendations) VALUES (?, ?, ?, ?, ?, ?)",
            (
                report_id,
                report_data.get("title"),
                report_data.get("summary"),
                json.dumps(report_data.get("domains", [])),
                json.dumps(report_data.get("findings", [])),
                json.dumps(report_data.get("recommendations", []))
            )
        )
        conn.commit()
        conn.close()
    
    def get_domain_info(self, domain: str) -> Optional[Dict]:
        conn = get_connection()
        row = conn.execute("SELECT * FROM domains WHERE domain = ?", (domain,)).fetchone()
        conn.close()
        if row:
            result = dict(row)
            result["ip_addresses"] = json.loads(result.get("ip_addresses") or "[]")
            result["nameservers"] = json.loads(result.get("nameservers") or "[]")
            result["metadata"] = json.loads(result.get("metadata") or "{}")
            return result
        return None
    
    def get_dns_history(self, domain: str) -> List[Dict]:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM dns_history WHERE domain = ? ORDER BY captured_at DESC",
            (domain,)
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_domain_relations(self, domain: str) -> List[Dict]:
        conn = get_connection()
        rows = conn.execute(
            """SELECT * FROM domain_relations 
               WHERE source_domain = ? OR target_domain = ? 
               ORDER BY confidence DESC""",
            (domain, domain)
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_infrastructure_changes(self, domain: str) -> List[Dict]:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM infrastructure_changes WHERE domain = ? ORDER BY detected_at DESC",
            (domain,)
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_behavior_logs(self, domain: str) -> List[Dict]:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM behavior_logs WHERE domain = ? ORDER BY detected_at DESC",
            (domain,)
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_weak_links(self, domain: str = None) -> List[Dict]:
        conn = get_connection()
        if domain:
            rows = conn.execute(
                "SELECT * FROM weak_links WHERE domain = ? ORDER BY detected_at DESC",
                (domain,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM weak_links ORDER BY detected_at DESC").fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_statistics(self) -> Dict[str, Any]:
        conn = get_connection()
        stats = {}
        
        stats["total_scans"] = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        stats["completed_scans"] = conn.execute("SELECT COUNT(*) FROM scans WHERE status = 'completed'").fetchone()[0]
        stats["total_results"] = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
        stats["direct_judol"] = conn.execute("SELECT COUNT(*) FROM scan_results WHERE category = 'direct_judol'").fetchone()[0]
        stats["deface_forward"] = conn.execute("SELECT COUNT(*) FROM scan_results WHERE category = 'deface_forward'").fetchone()[0]
        stats["suspected"] = conn.execute("SELECT COUNT(*) FROM scan_results WHERE category = 'suspected'").fetchone()[0]
        stats["total_reports"] = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        stats["pending_reports"] = conn.execute("SELECT COUNT(*) FROM reports WHERE status = 'pending'").fetchone()[0]
        stats["total_domains"] = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
        
        conn.close()
        return stats

db = DatabaseManager()
