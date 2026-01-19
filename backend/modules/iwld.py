import json
from typing import Dict, List, Any
from datetime import datetime

import tldextract

import sys
sys.path.append("..")

class IWLDEngine:
    def __init__(self, db_manager=None):
        self.db = db_manager
        
        self.weakness_definitions = {
            "dns_instability": {
                "severity": "high",
                "description": "DNS records show instability or inconsistency",
                "remediation": "Monitor for DNS hijacking or fast-flux behavior"
            },
            "low_ttl": {
                "severity": "medium",
                "description": "Unusually low TTL values detected",
                "remediation": "May indicate preparation for domain rotation"
            },
            "missing_dnssec": {
                "severity": "low",
                "description": "DNSSEC not configured",
                "remediation": "Domain is vulnerable to DNS spoofing"
            },
            "weak_ssl": {
                "severity": "high",
                "description": "SSL certificate issues detected",
                "remediation": "Check for certificate validity and issuer"
            },
            "free_ssl": {
                "severity": "low",
                "description": "Using free SSL certificate",
                "remediation": "Common for gambling sites, not inherently weak"
            },
            "single_ip": {
                "severity": "medium",
                "description": "Domain resolves to single IP",
                "remediation": "Single point of failure, easy to block"
            },
            "shared_hosting": {
                "severity": "medium",
                "description": "Hosted on shared infrastructure",
                "remediation": "May share IP with other domains"
            },
            "no_redundancy": {
                "severity": "medium",
                "description": "No nameserver redundancy detected",
                "remediation": "Single nameserver provider is a weak point"
            },
            "recent_registration": {
                "severity": "medium",
                "description": "Domain was recently registered",
                "remediation": "New domains are more suspicious"
            },
            "privacy_whois": {
                "severity": "low",
                "description": "WHOIS information is privacy protected",
                "remediation": "Common for malicious domains to hide ownership"
            },
            "exposed_admin": {
                "severity": "high",
                "description": "Admin or backend endpoints exposed",
                "remediation": "Security misconfiguration detected"
            },
            "open_ports": {
                "severity": "medium",
                "description": "Non-standard ports are open",
                "remediation": "May indicate additional services"
            }
        }
    
    def extract_domain(self, url_or_domain: str) -> str:
        extracted = tldextract.extract(url_or_domain)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def analyze_weak_links(self, domain: str) -> Dict[str, Any]:
        domain = self.extract_domain(domain)
        
        result = {
            "domain": domain,
            "analyzed_at": datetime.now().isoformat(),
            "weak_links": [],
            "vulnerability_score": 0,
            "priority_targets": [],
            "summary": {}
        }
        
        if not self.db:
            result["weak_links"].append({
                "type": "analysis_limited",
                "severity": "info",
                "description": "Limited analysis without database",
                "remediation": "Run infrastructure scan first"
            })
            return result
        
        domain_info = self.db.get_domain_info(domain)
        dns_history = self.db.get_dns_history(domain)
        behavior_logs = self.db.get_behavior_logs(domain)
        infrastructure_changes = self.db.get_infrastructure_changes(domain)
        
        if domain_info:
            result["weak_links"].extend(self._analyze_domain_info(domain_info))
        
        if dns_history:
            result["weak_links"].extend(self._analyze_dns_history(dns_history))
        
        if behavior_logs:
            result["weak_links"].extend(self._analyze_behavior_logs(behavior_logs))
        
        if infrastructure_changes:
            result["weak_links"].extend(self._analyze_changes(infrastructure_changes))
        
        result["vulnerability_score"] = self._calculate_vulnerability_score(result["weak_links"])
        result["priority_targets"] = self._identify_priority_targets(result["weak_links"])
        result["summary"] = self._generate_summary(result)
        
        for weak_link in result["weak_links"]:
            if weak_link["severity"] in ["high", "medium"]:
                self.db.save_weak_link(
                    domain,
                    weak_link["type"],
                    weak_link["severity"],
                    weak_link["description"],
                    weak_link.get("remediation")
                )
        
        return result
    
    def _analyze_domain_info(self, info: Dict) -> List[Dict[str, Any]]:
        weaknesses = []
        
        ip_addresses = info.get("ip_addresses", [])
        if isinstance(ip_addresses, str):
            ip_addresses = json.loads(ip_addresses)
        
        if len(ip_addresses) == 1:
            weaknesses.append({
                "type": "single_ip",
                "severity": "medium",
                "description": f"Domain uses single IP: {ip_addresses[0]}",
                "remediation": "Easy to block at network level",
                "target": ip_addresses[0]
            })
        
        nameservers = info.get("nameservers", [])
        if isinstance(nameservers, str):
            nameservers = json.loads(nameservers)
        
        if nameservers:
            ns_providers = set()
            for ns in nameservers:
                ns_domain = tldextract.extract(ns).registered_domain
                ns_providers.add(ns_domain)
            
            if len(ns_providers) == 1:
                weaknesses.append({
                    "type": "no_redundancy",
                    "severity": "medium",
                    "description": f"Single NS provider: {list(ns_providers)[0]}",
                    "remediation": "Block or take down nameserver provider",
                    "target": list(ns_providers)[0]
                })
        
        ssl_issuer = info.get("ssl_issuer", "")
        if ssl_issuer and "let's encrypt" in ssl_issuer.lower():
            weaknesses.append({
                "type": "free_ssl",
                "severity": "low",
                "description": "Using free Let's Encrypt certificate",
                "remediation": "Certificate can be quickly revoked",
                "target": ssl_issuer
            })
        
        if info.get("registrar") is None:
            weaknesses.append({
                "type": "privacy_whois",
                "severity": "low",
                "description": "WHOIS information hidden or unavailable",
                "remediation": "Owner information concealed"
            })
        
        hosting = info.get("hosting_provider", "")
        if hosting:
            problematic_hosts = ["cloudflare", "fastly", "akamai"]
            for host in problematic_hosts:
                if host in hosting.lower():
                    weaknesses.append({
                        "type": "cdn_protected",
                        "severity": "low",
                        "description": f"Protected by CDN: {hosting}",
                        "remediation": "Origin server may be hidden behind CDN"
                    })
                    break
        
        return weaknesses
    
    def _analyze_dns_history(self, history: List[Dict]) -> List[Dict[str, Any]]:
        weaknesses = []
        
        if not history:
            return weaknesses
        
        ttls = []
        for record in history:
            if record.get("ttl") is not None:
                ttls.append(record["ttl"])
        
        if ttls:
            min_ttl = min(ttls)
            if min_ttl < 300:
                weaknesses.append({
                    "type": "low_ttl",
                    "severity": "medium",
                    "description": f"Very low TTL detected: {min_ttl} seconds",
                    "remediation": "Indicates fast-flux or quick rotation capability"
                })
            
            ttl_variance = max(ttls) - min(ttls)
            if ttl_variance > 3600:
                weaknesses.append({
                    "type": "dns_instability",
                    "severity": "high",
                    "description": f"High TTL variance: {ttl_variance} seconds",
                    "remediation": "DNS configuration is unstable"
                })
        
        ip_values = set()
        for record in history:
            if record.get("record_type") == "A":
                ip_values.add(record.get("record_value"))
        
        if len(ip_values) > 5:
            weaknesses.append({
                "type": "ip_rotation",
                "severity": "high",
                "description": f"Multiple IPs in history: {len(ip_values)} different IPs",
                "remediation": "Fast-flux or IP rotation detected"
            })
        
        return weaknesses
    
    def _analyze_behavior_logs(self, logs: List[Dict]) -> List[Dict[str, Any]]:
        weaknesses = []
        
        behavior_counts = {}
        for log in logs:
            btype = log.get("behavior_type", "unknown")
            behavior_counts[btype] = behavior_counts.get(btype, 0) + 1
        
        if behavior_counts.get("dns_tampering", 0) > 0:
            weaknesses.append({
                "type": "dns_tampering_detected",
                "severity": "high",
                "description": f"DNS tampering detected {behavior_counts['dns_tampering']} times",
                "remediation": "Infrastructure may be compromised or using evasion tactics"
            })
        
        if behavior_counts.get("shadow_manipulation", 0) > 0:
            weaknesses.append({
                "type": "hidden_infrastructure",
                "severity": "high",
                "description": "Shadow subdomains or hidden infrastructure detected",
                "remediation": "Check for hidden admin panels or backends"
            })
        
        return weaknesses
    
    def _analyze_changes(self, changes: List[Dict]) -> List[Dict[str, Any]]:
        weaknesses = []
        
        change_types = {}
        for change in changes:
            ctype = change.get("change_type", "unknown")
            change_types[ctype] = change_types.get(ctype, 0) + 1
        
        if change_types.get("hosting_change", 0) >= 2:
            weaknesses.append({
                "type": "hosting_instability",
                "severity": "medium",
                "description": f"Hosting changed {change_types['hosting_change']} times",
                "remediation": "Operator may be evading takedowns"
            })
        
        if change_types.get("ip_change", 0) >= 3:
            weaknesses.append({
                "type": "ip_instability",
                "severity": "high",
                "description": f"IP changed {change_types['ip_change']} times",
                "remediation": "Active IP rotation indicates awareness of blocking"
            })
        
        return weaknesses
    
    def _calculate_vulnerability_score(self, weak_links: List[Dict]) -> int:
        score = 0
        
        severity_scores = {
            "high": 25,
            "medium": 15,
            "low": 5,
            "info": 0
        }
        
        for weak_link in weak_links:
            severity = weak_link.get("severity", "low")
            score += severity_scores.get(severity, 5)
        
        return min(score, 100)
    
    def _identify_priority_targets(self, weak_links: List[Dict]) -> List[Dict[str, Any]]:
        priority = []
        
        high_severity = [w for w in weak_links if w.get("severity") == "high"]
        
        for weak_link in high_severity:
            if weak_link.get("target"):
                priority.append({
                    "target": weak_link["target"],
                    "type": weak_link["type"],
                    "action": weak_link.get("remediation", "Monitor")
                })
        
        single_ip = next((w for w in weak_links if w["type"] == "single_ip"), None)
        if single_ip and single_ip.get("target"):
            priority.append({
                "target": single_ip["target"],
                "type": "infrastructure",
                "action": "Block at network level"
            })
        
        single_ns = next((w for w in weak_links if w["type"] == "no_redundancy"), None)
        if single_ns and single_ns.get("target"):
            priority.append({
                "target": single_ns["target"],
                "type": "nameserver",
                "action": "Report to nameserver provider"
            })
        
        return priority
    
    def _generate_summary(self, result: Dict) -> Dict[str, Any]:
        weak_links = result.get("weak_links", [])
        
        by_severity = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for weak_link in weak_links:
            severity = weak_link.get("severity", "info")
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        vuln_score = result.get("vulnerability_score", 0)
        if vuln_score >= 70:
            overall = "critical"
        elif vuln_score >= 50:
            overall = "high"
        elif vuln_score >= 30:
            overall = "medium"
        elif vuln_score > 0:
            overall = "low"
        else:
            overall = "minimal"
        
        return {
            "total_weaknesses": len(weak_links),
            "by_severity": by_severity,
            "vulnerability_score": vuln_score,
            "overall_assessment": overall,
            "priority_count": len(result.get("priority_targets", []))
        }
    
    def compare_weak_links(self, domains: List[str]) -> Dict[str, Any]:
        result = {
            "analyzed_at": datetime.now().isoformat(),
            "domains_analyzed": len(domains),
            "analyses": [],
            "shared_weaknesses": [],
            "most_vulnerable": None,
            "least_vulnerable": None
        }
        
        for domain in domains:
            analysis = self.analyze_weak_links(domain)
            result["analyses"].append({
                "domain": domain,
                "vulnerability_score": analysis["vulnerability_score"],
                "weakness_count": len(analysis["weak_links"]),
                "priority_targets": analysis["priority_targets"]
            })
        
        if result["analyses"]:
            sorted_by_score = sorted(result["analyses"], key=lambda x: x["vulnerability_score"], reverse=True)
            result["most_vulnerable"] = sorted_by_score[0]["domain"]
            result["least_vulnerable"] = sorted_by_score[-1]["domain"]
        
        weakness_types = {}
        for analysis in result["analyses"]:
            domain = analysis["domain"]
            full_analysis = self.analyze_weak_links(domain)
            for weak_link in full_analysis["weak_links"]:
                wtype = weak_link["type"]
                if wtype not in weakness_types:
                    weakness_types[wtype] = []
                weakness_types[wtype].append(domain)
        
        for wtype, domains_with in weakness_types.items():
            if len(domains_with) > 1:
                result["shared_weaknesses"].append({
                    "weakness_type": wtype,
                    "domains": domains_with,
                    "count": len(domains_with)
                })
        
        return result
    
    def get_priority_blocking_list(self, domains: List[str]) -> Dict[str, Any]:
        result = {
            "generated_at": datetime.now().isoformat(),
            "domains_analyzed": len(domains),
            "ip_block_list": [],
            "domain_block_list": [],
            "ns_report_list": [],
            "hosting_report_list": []
        }
        
        ips_to_block = set()
        ns_to_report = set()
        
        for domain in domains:
            analysis = self.analyze_weak_links(domain)
            
            for target in analysis.get("priority_targets", []):
                if target["type"] == "infrastructure":
                    ips_to_block.add(target["target"])
                elif target["type"] == "nameserver":
                    ns_to_report.add(target["target"])
            
            result["domain_block_list"].append({
                "domain": domain,
                "vulnerability_score": analysis["vulnerability_score"],
                "priority": "high" if analysis["vulnerability_score"] >= 50 else "normal"
            })
        
        result["ip_block_list"] = list(ips_to_block)
        result["ns_report_list"] = list(ns_to_report)
        
        result["domain_block_list"].sort(key=lambda x: -x["vulnerability_score"])
        
        return result
