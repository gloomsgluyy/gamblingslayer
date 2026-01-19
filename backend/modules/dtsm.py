import json
from typing import Dict, List, Any
from datetime import datetime
from collections import Counter

import dns.resolver
import tldextract

import sys
sys.path.append("..")
from config import DNS_RESOLVERS

class DTSMEngine:
    def __init__(self, db_manager=None):
        self.db = db_manager
        self.resolvers = DNS_RESOLVERS
    
    def extract_domain(self, url_or_domain: str) -> str:
        extracted = tldextract.extract(url_or_domain)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def query_dns_multi_resolver(self, domain: str, record_type: str = "A") -> Dict[str, List[Dict]]:
        results = {}
        
        for resolver_ip in self.resolvers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = 5
                resolver.lifetime = 10
                
                answers = resolver.resolve(domain, record_type)
                
                records = []
                for rdata in answers:
                    records.append({
                        "value": str(rdata),
                        "ttl": answers.rrset.ttl if answers.rrset else None
                    })
                
                results[resolver_ip] = {
                    "records": records,
                    "success": True,
                    "error": None
                }
                
                if self.db:
                    for record in records:
                        self.db.save_dns_record(
                            domain, record_type, record["value"],
                            resolver_ip, record["ttl"]
                        )
                        
            except dns.resolver.NXDOMAIN:
                results[resolver_ip] = {"records": [], "success": False, "error": "NXDOMAIN"}
            except dns.resolver.NoAnswer:
                results[resolver_ip] = {"records": [], "success": False, "error": "NoAnswer"}
            except dns.resolver.Timeout:
                results[resolver_ip] = {"records": [], "success": False, "error": "Timeout"}
            except Exception as e:
                results[resolver_ip] = {"records": [], "success": False, "error": str(e)}
        
        return results
    
    def detect_dns_tampering(self, domain: str) -> Dict[str, Any]:
        domain = self.extract_domain(domain)
        
        result = {
            "domain": domain,
            "analyzed_at": datetime.now().isoformat(),
            "record_types_checked": [],
            "inconsistencies": [],
            "tampering_detected": False,
            "risk_score": 0,
            "details": {}
        }
        
        for record_type in ["A", "AAAA", "NS", "CNAME"]:
            resolver_results = self.query_dns_multi_resolver(domain, record_type)
            
            if any(r["success"] for r in resolver_results.values()):
                result["record_types_checked"].append(record_type)
                result["details"][record_type] = resolver_results
                
                inconsistency = self._check_inconsistency(resolver_results, record_type)
                if inconsistency:
                    result["inconsistencies"].append(inconsistency)
        
        result["tampering_detected"] = len(result["inconsistencies"]) > 0
        result["risk_score"] = self._calculate_risk_score(result)
        
        if result["tampering_detected"] and self.db:
            self.db.save_behavior_log(
                domain, "dns_tampering",
                f"DNS tampering detected with {len(result['inconsistencies'])} inconsistencies",
                {"inconsistencies": result["inconsistencies"]}
            )
        
        return result
    
    def _check_inconsistency(self, resolver_results: Dict, record_type: str) -> Dict[str, Any]:
        all_values = {}
        
        for resolver, data in resolver_results.items():
            if data["success"]:
                values = frozenset(r["value"] for r in data["records"])
                if values:
                    all_values[resolver] = values
        
        if len(all_values) < 2:
            return None
        
        unique_responses = set(all_values.values())
        
        if len(unique_responses) > 1:
            value_counts = Counter()
            for values in all_values.values():
                value_counts[values] += 1
            
            most_common = value_counts.most_common(1)[0]
            anomalous_resolvers = []
            
            for resolver, values in all_values.items():
                if values != most_common[0]:
                    anomalous_resolvers.append({
                        "resolver": resolver,
                        "returned": list(values),
                        "expected": list(most_common[0])
                    })
            
            return {
                "record_type": record_type,
                "type": "response_mismatch",
                "severity": "high" if record_type == "A" else "medium",
                "consensus_count": most_common[1],
                "total_resolvers": len(all_values),
                "anomalous_resolvers": anomalous_resolvers,
                "description": f"Different {record_type} records returned by different resolvers"
            }
        
        return None
    
    def _calculate_risk_score(self, result: Dict[str, Any]) -> int:
        score = 0
        
        for inconsistency in result["inconsistencies"]:
            if inconsistency["severity"] == "high":
                score += 30
            elif inconsistency["severity"] == "medium":
                score += 20
            else:
                score += 10
            
            anomaly_ratio = len(inconsistency.get("anomalous_resolvers", [])) / max(inconsistency.get("total_resolvers", 1), 1)
            score += int(anomaly_ratio * 20)
        
        return min(score, 100)
    
    def check_ttl_anomalies(self, domain: str) -> Dict[str, Any]:
        domain = self.extract_domain(domain)
        
        result = {
            "domain": domain,
            "analyzed_at": datetime.now().isoformat(),
            "ttl_analysis": {},
            "anomalies": []
        }
        
        normal_ttl_ranges = {
            "A": (60, 86400),
            "NS": (3600, 172800),
            "MX": (3600, 86400),
            "TXT": (300, 86400)
        }
        
        for record_type in ["A", "NS", "MX", "TXT"]:
            resolver_results = self.query_dns_multi_resolver(domain, record_type)
            
            ttls = []
            for resolver, data in resolver_results.items():
                if data["success"]:
                    for record in data["records"]:
                        if record.get("ttl") is not None:
                            ttls.append(record["ttl"])
            
            if ttls:
                min_ttl = min(ttls)
                max_ttl = max(ttls)
                avg_ttl = sum(ttls) / len(ttls)
                
                result["ttl_analysis"][record_type] = {
                    "min": min_ttl,
                    "max": max_ttl,
                    "average": avg_ttl,
                    "variance": max_ttl - min_ttl
                }
                
                expected_min, expected_max = normal_ttl_ranges.get(record_type, (60, 86400))
                
                if min_ttl < expected_min:
                    result["anomalies"].append({
                        "record_type": record_type,
                        "type": "low_ttl",
                        "severity": "high" if min_ttl < 60 else "medium",
                        "value": min_ttl,
                        "expected_min": expected_min,
                        "description": f"Unusually low TTL for {record_type} records (may indicate fast-flux)"
                    })
                
                if max_ttl - min_ttl > 3600:
                    result["anomalies"].append({
                        "record_type": record_type,
                        "type": "ttl_variance",
                        "severity": "medium",
                        "variance": max_ttl - min_ttl,
                        "description": "High TTL variance across resolvers"
                    })
        
        return result
    
    def check_shadow_records(self, domain: str) -> Dict[str, Any]:
        domain = self.extract_domain(domain)
        
        result = {
            "domain": domain,
            "analyzed_at": datetime.now().isoformat(),
            "subdomains_checked": [],
            "shadow_records": [],
            "suspicious_patterns": []
        }
        
        suspicious_subdomains = [
            "admin", "api", "backend", "cdn", "dev", "staging",
            "test", "app", "m", "mobile", "wap", "old", "new",
            "backup", "mirror", "alt", "redirect", "go", "link",
            "slot", "game", "play", "bet", "casino", "poker"
        ]
        
        for subdomain in suspicious_subdomains:
            full_domain = f"{subdomain}.{domain}"
            
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 5
                
                answers = resolver.resolve(full_domain, "A")
                
                records = [str(rdata) for rdata in answers]
                
                result["subdomains_checked"].append(full_domain)
                result["shadow_records"].append({
                    "subdomain": subdomain,
                    "full_domain": full_domain,
                    "records": records,
                    "exists": True
                })
                
                gambling_keywords = ["slot", "game", "play", "bet", "casino", "poker"]
                if subdomain in gambling_keywords:
                    result["suspicious_patterns"].append({
                        "subdomain": subdomain,
                        "type": "gambling_related_subdomain",
                        "severity": "high",
                        "description": f"Gambling-related subdomain detected: {full_domain}"
                    })
                    
            except dns.resolver.NXDOMAIN:
                result["subdomains_checked"].append(full_domain)
            except Exception:
                continue
        
        if self.db and result["suspicious_patterns"]:
            self.db.save_behavior_log(
                domain, "shadow_manipulation",
                f"Found {len(result['shadow_records'])} shadow subdomains",
                {"patterns": result["suspicious_patterns"]}
            )
        
        return result
    
    def analyze_nameserver_hierarchy(self, domain: str) -> Dict[str, Any]:
        domain = self.extract_domain(domain)
        
        result = {
            "domain": domain,
            "analyzed_at": datetime.now().isoformat(),
            "nameservers": [],
            "ns_analysis": [],
            "anomalies": []
        }
        
        ns_results = self.query_dns_multi_resolver(domain, "NS")
        
        nameservers = set()
        for resolver, data in ns_results.items():
            if data["success"]:
                for record in data["records"]:
                    nameservers.add(record["value"].rstrip("."))
        
        result["nameservers"] = list(nameservers)
        
        ns_providers = {}
        for ns in nameservers:
            ns_domain = tldextract.extract(ns).registered_domain
            if ns_domain not in ns_providers:
                ns_providers[ns_domain] = []
            ns_providers[ns_domain].append(ns)
        
        for provider, servers in ns_providers.items():
            ns_ips = []
            for ns in servers:
                try:
                    resolver = dns.resolver.Resolver()
                    answers = resolver.resolve(ns, "A")
                    ns_ips.extend([str(rdata) for rdata in answers])
                except Exception:
                    pass
            
            result["ns_analysis"].append({
                "provider": provider,
                "servers": servers,
                "ip_addresses": ns_ips
            })
        
        if len(ns_providers) > 2:
            result["anomalies"].append({
                "type": "multiple_ns_providers",
                "severity": "medium",
                "count": len(ns_providers),
                "providers": list(ns_providers.keys()),
                "description": "Domain uses nameservers from multiple providers (unusual)"
            })
        
        return result
    
    def full_dns_analysis(self, url_or_domain: str) -> Dict[str, Any]:
        domain = self.extract_domain(url_or_domain)
        
        result = {
            "domain": domain,
            "analyzed_at": datetime.now().isoformat(),
            "tampering_check": self.detect_dns_tampering(domain),
            "ttl_analysis": self.check_ttl_anomalies(domain),
            "shadow_check": self.check_shadow_records(domain),
            "ns_analysis": self.analyze_nameserver_hierarchy(domain),
            "overall_risk_score": 0,
            "findings_summary": []
        }
        
        total_score = result["tampering_check"]["risk_score"]
        
        for anomaly in result["ttl_analysis"].get("anomalies", []):
            if anomaly["severity"] == "high":
                total_score += 15
            elif anomaly["severity"] == "medium":
                total_score += 10
        
        for pattern in result["shadow_check"].get("suspicious_patterns", []):
            if pattern["severity"] == "high":
                total_score += 20
            elif pattern["severity"] == "medium":
                total_score += 10
        
        for anomaly in result["ns_analysis"].get("anomalies", []):
            if anomaly["severity"] == "high":
                total_score += 15
            elif anomaly["severity"] == "medium":
                total_score += 10
        
        result["overall_risk_score"] = min(total_score, 100)
        
        if result["tampering_check"]["tampering_detected"]:
            result["findings_summary"].append("DNS tampering detected across resolvers")
        
        if result["ttl_analysis"].get("anomalies"):
            result["findings_summary"].append(f"TTL anomalies found: {len(result['ttl_analysis']['anomalies'])}")
        
        if result["shadow_check"].get("suspicious_patterns"):
            result["findings_summary"].append(f"Suspicious subdomains: {len(result['shadow_check']['suspicious_patterns'])}")
        
        if result["ns_analysis"].get("anomalies"):
            result["findings_summary"].append(f"Nameserver anomalies: {len(result['ns_analysis']['anomalies'])}")
        
        return result
