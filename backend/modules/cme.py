import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

import tldextract

import sys
sys.path.append("..")

class CMEEngine:
    def __init__(self, db_manager=None):
        self.db = db_manager
    
    def extract_domain(self, url_or_domain: str) -> str:
        extracted = tldextract.extract(url_or_domain)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def get_current_infrastructure(self, domain: str) -> Dict[str, Any]:
        if not self.db:
            return {"domain": domain, "error": "No database available"}
        
        domain_info = self.db.get_domain_info(domain)
        dns_history = self.db.get_dns_history(domain)
        relations = self.db.get_domain_relations(domain)
        
        latest_dns = defaultdict(list)
        for record in dns_history[:50]:
            latest_dns[record["record_type"]].append(record["record_value"])
        
        return {
            "domain": domain,
            "captured_at": datetime.now().isoformat(),
            "ip_addresses": domain_info.get("ip_addresses", []) if domain_info else [],
            "nameservers": domain_info.get("nameservers", []) if domain_info else [],
            "hosting_provider": domain_info.get("hosting_provider") if domain_info else None,
            "asn": domain_info.get("asn") if domain_info else None,
            "registrar": domain_info.get("registrar") if domain_info else None,
            "ssl_issuer": domain_info.get("ssl_issuer") if domain_info else None,
            "dns_records": dict(latest_dns),
            "related_domains": [r["target_domain"] for r in relations if r["source_domain"] == domain]
        }
    
    def detect_mobility(self, domain: str, current: Dict[str, Any] = None, previous: Dict[str, Any] = None) -> Dict[str, Any]:
        domain = self.extract_domain(domain)
        
        if not current:
            current = self.get_current_infrastructure(domain)
        
        if not previous and self.db:
            previous = self.db.get_domain_info(domain)
        
        if not previous:
            return {
                "domain": domain,
                "analyzed_at": datetime.now().isoformat(),
                "is_new": True,
                "changes": [],
                "mobility_score": 0,
                "mobility_level": "unknown"
            }
        
        changes = []
        
        current_ips = set(current.get("ip_addresses", []))
        previous_ips = set(previous.get("ip_addresses", []))
        
        if current_ips != previous_ips:
            added_ips = current_ips - previous_ips
            removed_ips = previous_ips - current_ips
            
            changes.append({
                "type": "ip_change",
                "severity": "high",
                "added": list(added_ips),
                "removed": list(removed_ips),
                "description": f"IP addresses changed: {len(removed_ips)} removed, {len(added_ips)} added"
            })
            
            if self.db:
                self.db.save_infrastructure_change(
                    domain, "ip_change",
                    json.dumps(list(previous_ips)),
                    json.dumps(list(current_ips))
                )
        
        current_ns = set(current.get("nameservers", []))
        previous_ns = set(previous.get("nameservers", []))
        
        if current_ns != previous_ns:
            changes.append({
                "type": "nameserver_change",
                "severity": "high",
                "old": list(previous_ns),
                "new": list(current_ns),
                "description": "Nameservers have changed"
            })
            
            if self.db:
                self.db.save_infrastructure_change(
                    domain, "nameserver_change",
                    json.dumps(list(previous_ns)),
                    json.dumps(list(current_ns))
                )
        
        current_hosting = current.get("hosting_provider")
        previous_hosting = previous.get("hosting_provider")
        
        if current_hosting and previous_hosting and current_hosting != previous_hosting:
            changes.append({
                "type": "hosting_change",
                "severity": "high",
                "old": previous_hosting,
                "new": current_hosting,
                "description": f"Hosting provider changed from {previous_hosting} to {current_hosting}"
            })
            
            if self.db:
                self.db.save_infrastructure_change(
                    domain, "hosting_change",
                    previous_hosting, current_hosting
                )
        
        current_asn = current.get("asn")
        previous_asn = previous.get("asn")
        
        if current_asn and previous_asn and current_asn != previous_asn:
            changes.append({
                "type": "asn_change",
                "severity": "medium",
                "old": previous_asn,
                "new": current_asn,
                "description": f"ASN changed from {previous_asn} to {current_asn}"
            })
        
        current_ssl = current.get("ssl_issuer")
        previous_ssl = previous.get("ssl_issuer")
        
        if current_ssl and previous_ssl and current_ssl != previous_ssl:
            changes.append({
                "type": "ssl_change",
                "severity": "low",
                "old": previous_ssl,
                "new": current_ssl,
                "description": "SSL certificate issuer changed"
            })
        
        mobility_score = self._calculate_mobility_score(changes)
        
        result = {
            "domain": domain,
            "analyzed_at": datetime.now().isoformat(),
            "is_new": False,
            "changes": changes,
            "change_count": len(changes),
            "mobility_score": mobility_score,
            "mobility_level": self._classify_mobility(mobility_score),
            "current_state": current,
            "previous_state": previous
        }
        
        if changes and self.db:
            self.db.save_behavior_log(
                domain, "infrastructure_mobility",
                f"Detected {len(changes)} infrastructure changes",
                {
                    "changes": changes,
                    "mobility_score": mobility_score
                }
            )
        
        return result
    
    def _calculate_mobility_score(self, changes: List[Dict]) -> int:
        score = 0
        
        severity_weights = {
            "high": 30,
            "medium": 20,
            "low": 10
        }
        
        for change in changes:
            severity = change.get("severity", "medium")
            score += severity_weights.get(severity, 15)
        
        return min(score, 100)
    
    def _classify_mobility(self, score: int) -> str:
        if score >= 70:
            return "high"
        elif score >= 40:
            return "medium"
        elif score > 0:
            return "low"
        return "stable"
    
    def analyze_movement_direction(self, domain: str) -> Dict[str, Any]:
        if not self.db:
            return {"domain": domain, "error": "No database available"}
        
        domain = self.extract_domain(domain)
        changes = self.db.get_infrastructure_changes(domain)
        
        if not changes:
            return {
                "domain": domain,
                "analyzed_at": datetime.now().isoformat(),
                "has_history": False,
                "movement_patterns": []
            }
        
        patterns = {
            "ip_changes": [],
            "hosting_changes": [],
            "ns_changes": [],
            "geographic_movement": []
        }
        
        for change in changes:
            change_type = change.get("change_type")
            
            if change_type == "ip_change":
                patterns["ip_changes"].append({
                    "old": json.loads(change.get("old_value") or "[]"),
                    "new": json.loads(change.get("new_value") or "[]"),
                    "detected_at": change.get("detected_at")
                })
            
            elif change_type == "hosting_change":
                patterns["hosting_changes"].append({
                    "old": change.get("old_value"),
                    "new": change.get("new_value"),
                    "detected_at": change.get("detected_at")
                })
            
            elif change_type == "nameserver_change":
                patterns["ns_changes"].append({
                    "old": json.loads(change.get("old_value") or "[]"),
                    "new": json.loads(change.get("new_value") or "[]"),
                    "detected_at": change.get("detected_at")
                })
        
        movement_analysis = {
            "domain": domain,
            "analyzed_at": datetime.now().isoformat(),
            "has_history": True,
            "total_changes": len(changes),
            "change_frequency": self._calculate_frequency(changes),
            "movement_patterns": patterns,
            "trend": self._analyze_trend(patterns)
        }
        
        return movement_analysis
    
    def _calculate_frequency(self, changes: List[Dict]) -> str:
        if len(changes) == 0:
            return "none"
        elif len(changes) <= 2:
            return "low"
        elif len(changes) <= 5:
            return "medium"
        else:
            return "high"
    
    def _analyze_trend(self, patterns: Dict) -> Dict[str, Any]:
        trend = {
            "is_active": False,
            "primary_change_type": None,
            "indicators": []
        }
        
        total_changes = (
            len(patterns["ip_changes"]) + 
            len(patterns["hosting_changes"]) + 
            len(patterns["ns_changes"])
        )
        
        if total_changes > 0:
            trend["is_active"] = True
            
            if len(patterns["ip_changes"]) >= len(patterns["hosting_changes"]):
                trend["primary_change_type"] = "ip_rotation"
            else:
                trend["primary_change_type"] = "hosting_migration"
            
            if len(patterns["ip_changes"]) > 3:
                trend["indicators"].append("frequent_ip_rotation")
            
            if len(patterns["hosting_changes"]) > 1:
                trend["indicators"].append("hosting_hopping")
            
            if len(patterns["ns_changes"]) > 1:
                trend["indicators"].append("nameserver_changes")
        
        return trend
    
    def track_multiple_domains(self, domains: List[str]) -> Dict[str, Any]:
        result = {
            "analyzed_at": datetime.now().isoformat(),
            "domains_analyzed": len(domains),
            "mobility_results": [],
            "high_mobility_domains": [],
            "statistics": {}
        }
        
        mobility_counts = defaultdict(int)
        
        for domain in domains:
            try:
                mobility = self.detect_mobility(domain)
                result["mobility_results"].append(mobility)
                
                level = mobility.get("mobility_level", "unknown")
                mobility_counts[level] += 1
                
                if level == "high":
                    result["high_mobility_domains"].append(domain)
            except Exception:
                continue
        
        result["statistics"] = {
            "high_mobility": mobility_counts["high"],
            "medium_mobility": mobility_counts["medium"],
            "low_mobility": mobility_counts["low"],
            "stable": mobility_counts["stable"],
            "unknown": mobility_counts["unknown"]
        }
        
        return result
