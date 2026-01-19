import json
import uuid
from typing import Dict, List, Any
from datetime import datetime

import tldextract

import sys
sys.path.append("..")

class NEREEngine:
    def __init__(self, db_manager=None):
        self.db = db_manager
    
    def extract_domain(self, url_or_domain: str) -> str:
        extracted = tldextract.extract(url_or_domain)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def generate_evidence_report(self, domain: str, include_related: bool = True) -> Dict[str, Any]:
        domain = self.extract_domain(domain)
        report_id = f"report_{uuid.uuid4().hex[:12]}"
        
        report = {
            "report_id": report_id,
            "domain": domain,
            "generated_at": datetime.now().isoformat(),
            "title": f"Network Evidence Report: {domain}",
            "summary": "",
            "findings": [],
            "evidence": {
                "domain_info": {},
                "dns_records": [],
                "infrastructure_changes": [],
                "behavior_logs": [],
                "domain_relations": [],
                "weak_links": []
            },
            "related_domains": [],
            "risk_assessment": {},
            "recommendations": [],
            "timeline": []
        }
        
        if not self.db:
            report["summary"] = "Limited report - no database available"
            return report
        
        domain_info = self.db.get_domain_info(domain)
        if domain_info:
            report["evidence"]["domain_info"] = {
                "domain": domain,
                "ip_addresses": domain_info.get("ip_addresses", []),
                "nameservers": domain_info.get("nameservers", []),
                "registrar": domain_info.get("registrar"),
                "hosting_provider": domain_info.get("hosting_provider"),
                "ssl_issuer": domain_info.get("ssl_issuer"),
                "first_seen": domain_info.get("first_seen"),
                "last_seen": domain_info.get("last_seen")
            }
        
        dns_history = self.db.get_dns_history(domain)
        report["evidence"]["dns_records"] = [
            {
                "record_type": r.get("record_type"),
                "value": r.get("record_value"),
                "resolver": r.get("resolver"),
                "ttl": r.get("ttl"),
                "captured_at": r.get("captured_at")
            }
            for r in dns_history[:50]
        ]
        
        changes = self.db.get_infrastructure_changes(domain)
        report["evidence"]["infrastructure_changes"] = [
            {
                "change_type": c.get("change_type"),
                "old_value": c.get("old_value"),
                "new_value": c.get("new_value"),
                "detected_at": c.get("detected_at")
            }
            for c in changes
        ]
        
        behavior_logs = self.db.get_behavior_logs(domain)
        report["evidence"]["behavior_logs"] = [
            {
                "behavior_type": b.get("behavior_type"),
                "description": b.get("description"),
                "detected_at": b.get("detected_at")
            }
            for b in behavior_logs
        ]
        
        relations = self.db.get_domain_relations(domain)
        report["evidence"]["domain_relations"] = [
            {
                "source": r.get("source_domain"),
                "target": r.get("target_domain"),
                "relation_type": r.get("relation_type"),
                "confidence": r.get("confidence")
            }
            for r in relations
        ]
        
        weak_links = self.db.get_weak_links(domain)
        report["evidence"]["weak_links"] = [
            {
                "weakness_type": w.get("weakness_type"),
                "severity": w.get("severity"),
                "description": w.get("description"),
                "remediation": w.get("remediation")
            }
            for w in weak_links
        ]
        
        report["findings"] = self._generate_findings(report["evidence"])
        
        if include_related:
            related = set()
            for rel in relations:
                if rel.get("source_domain") == domain:
                    related.add(rel.get("target_domain"))
                else:
                    related.add(rel.get("source_domain"))
            report["related_domains"] = list(related)
        
        report["risk_assessment"] = self._assess_risk(report)
        report["recommendations"] = self._generate_recommendations(report)
        report["timeline"] = self._build_timeline(report)
        report["summary"] = self._generate_summary(report)
        
        if self.db:
            self.db.save_evidence_report(report_id, {
                "title": report["title"],
                "summary": report["summary"],
                "domains": [domain] + report["related_domains"],
                "findings": report["findings"],
                "recommendations": report["recommendations"]
            })
        
        return report
    
    def _generate_findings(self, evidence: Dict) -> List[Dict[str, Any]]:
        findings = []
        
        domain_info = evidence.get("domain_info", {})
        if domain_info:
            ip_count = len(domain_info.get("ip_addresses", []))
            if ip_count > 0:
                findings.append({
                    "category": "infrastructure",
                    "severity": "info",
                    "title": f"Domain resolves to {ip_count} IP address(es)",
                    "details": f"IPs: {', '.join(domain_info.get('ip_addresses', []))}"
                })
            
            if domain_info.get("hosting_provider"):
                findings.append({
                    "category": "infrastructure",
                    "severity": "info",
                    "title": f"Hosted by {domain_info.get('hosting_provider')}",
                    "details": f"ASN: {domain_info.get('asn', 'Unknown')}"
                })
        
        changes = evidence.get("infrastructure_changes", [])
        if len(changes) > 0:
            ip_changes = len([c for c in changes if c.get("change_type") == "ip_change"])
            hosting_changes = len([c for c in changes if c.get("change_type") == "hosting_change"])
            
            if ip_changes > 0:
                findings.append({
                    "category": "mobility",
                    "severity": "high" if ip_changes > 2 else "medium",
                    "title": f"IP address changed {ip_changes} time(s)",
                    "details": "Frequent IP changes may indicate evasion tactics"
                })
            
            if hosting_changes > 0:
                findings.append({
                    "category": "mobility",
                    "severity": "high" if hosting_changes > 1 else "medium",
                    "title": f"Hosting provider changed {hosting_changes} time(s)",
                    "details": "Hosting migration detected"
                })
        
        behavior_logs = evidence.get("behavior_logs", [])
        behavior_types = set(b.get("behavior_type") for b in behavior_logs)
        
        if "dns_tampering" in behavior_types:
            findings.append({
                "category": "evasion",
                "severity": "high",
                "title": "DNS tampering detected",
                "details": "Domain shows signs of DNS manipulation"
            })
        
        if "shadow_manipulation" in behavior_types:
            findings.append({
                "category": "evasion",
                "severity": "high",
                "title": "Shadow infrastructure detected",
                "details": "Hidden subdomains or shadow infrastructure found"
            })
        
        relations = evidence.get("domain_relations", [])
        if len(relations) > 0:
            redirect_count = len([r for r in relations if r.get("relation_type") == "redirect"])
            mirror_count = len([r for r in relations if "mirror" in r.get("relation_type", "")])
            
            if redirect_count > 0:
                findings.append({
                    "category": "network",
                    "severity": "medium",
                    "title": f"{redirect_count} redirect relationship(s) detected",
                    "details": "Domain has redirect chains to other domains"
                })
            
            if mirror_count > 0:
                findings.append({
                    "category": "network",
                    "severity": "high",
                    "title": f"{mirror_count} potential mirror domain(s) detected",
                    "details": "Domain appears to have mirror sites"
                })
        
        weak_links = evidence.get("weak_links", [])
        high_severity = [w for w in weak_links if w.get("severity") == "high"]
        if high_severity:
            findings.append({
                "category": "vulnerability",
                "severity": "high",
                "title": f"{len(high_severity)} high-severity weakness(es) detected",
                "details": "; ".join(w.get("description", "") for w in high_severity[:3])
            })
        
        return findings
    
    def _assess_risk(self, report: Dict) -> Dict[str, Any]:
        score = 0
        factors = []
        
        for finding in report.get("findings", []):
            if finding["severity"] == "high":
                score += 25
                factors.append(finding["title"])
            elif finding["severity"] == "medium":
                score += 15
            elif finding["severity"] == "low":
                score += 5
        
        changes = report["evidence"].get("infrastructure_changes", [])
        if len(changes) > 3:
            score += 15
            factors.append("High infrastructure mobility")
        
        related = report.get("related_domains", [])
        if len(related) > 3:
            score += 10
            factors.append(f"Connected to {len(related)} other domains")
        
        score = min(score, 100)
        
        if score >= 70:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 30:
            level = "medium"
        elif score > 0:
            level = "low"
        else:
            level = "minimal"
        
        return {
            "risk_score": score,
            "risk_level": level,
            "contributing_factors": factors[:5]
        }
    
    def _generate_recommendations(self, report: Dict) -> List[Dict[str, Any]]:
        recommendations = []
        risk = report.get("risk_assessment", {})
        
        if risk.get("risk_level") in ["critical", "high"]:
            recommendations.append({
                "priority": "high",
                "action": "Block domain",
                "details": "Domain poses significant risk and should be blocked at network level"
            })
            
            recommendations.append({
                "priority": "high",
                "action": "Report to authorities",
                "details": "Forward evidence to relevant cybersecurity authorities"
            })
        
        related = report.get("related_domains", [])
        if len(related) > 0:
            recommendations.append({
                "priority": "medium",
                "action": "Investigate related domains",
                "details": f"Analyze {len(related)} connected domain(s) for complete network picture"
            })
        
        weak_links = report["evidence"].get("weak_links", [])
        priority_targets = [w for w in weak_links if w.get("severity") == "high"]
        if priority_targets:
            recommendations.append({
                "priority": "medium",
                "action": "Target weak points",
                "details": "Focus enforcement on identified infrastructure weaknesses"
            })
        
        changes = report["evidence"].get("infrastructure_changes", [])
        if len(changes) > 2:
            recommendations.append({
                "priority": "medium",
                "action": "Continuous monitoring",
                "details": "Domain shows active infrastructure changes, requires ongoing surveillance"
            })
        
        if risk.get("risk_level") in ["medium", "low"]:
            recommendations.append({
                "priority": "low",
                "action": "Add to watchlist",
                "details": "Monitor domain for future suspicious activity"
            })
        
        return recommendations
    
    def _build_timeline(self, report: Dict) -> List[Dict[str, Any]]:
        events = []
        
        domain_info = report["evidence"].get("domain_info", {})
        if domain_info.get("first_seen"):
            events.append({
                "timestamp": domain_info["first_seen"],
                "event_type": "first_seen",
                "description": "Domain first observed"
            })
        
        for change in report["evidence"].get("infrastructure_changes", []):
            events.append({
                "timestamp": change.get("detected_at"),
                "event_type": change.get("change_type"),
                "description": f"Changed from {change.get('old_value')} to {change.get('new_value')}"
            })
        
        for behavior in report["evidence"].get("behavior_logs", []):
            events.append({
                "timestamp": behavior.get("detected_at"),
                "event_type": behavior.get("behavior_type"),
                "description": behavior.get("description")
            })
        
        events.sort(key=lambda x: x.get("timestamp") or "")
        
        return events
    
    def _generate_summary(self, report: Dict) -> str:
        domain = report.get("domain")
        risk = report.get("risk_assessment", {})
        findings_count = len(report.get("findings", []))
        related_count = len(report.get("related_domains", []))
        
        summary_parts = [
            f"Domain {domain} assessed with {risk.get('risk_level', 'unknown')} risk level",
            f"(score: {risk.get('risk_score', 0)}/100)."
        ]
        
        if findings_count > 0:
            summary_parts.append(f"Analysis identified {findings_count} finding(s).")
        
        if related_count > 0:
            summary_parts.append(f"Connected to {related_count} related domain(s).")
        
        high_findings = [f for f in report.get("findings", []) if f["severity"] == "high"]
        if high_findings:
            summary_parts.append(f"Key concerns: {high_findings[0]['title']}.")
        
        return " ".join(summary_parts)
    
    def generate_network_report(self, domains: List[str]) -> Dict[str, Any]:
        report_id = f"network_{uuid.uuid4().hex[:12]}"
        
        report = {
            "report_id": report_id,
            "generated_at": datetime.now().isoformat(),
            "title": f"Network Analysis Report - {len(domains)} Domains",
            "domains_analyzed": len(domains),
            "individual_reports": [],
            "network_topology": {"nodes": [], "edges": []},
            "aggregate_statistics": {},
            "network_risk_assessment": {},
            "recommendations": []
        }
        
        all_domains = set(domains)
        all_relations = []
        
        for domain in domains:
            individual = self.generate_evidence_report(domain, include_related=True)
            report["individual_reports"].append({
                "domain": domain,
                "risk_score": individual["risk_assessment"].get("risk_score", 0),
                "risk_level": individual["risk_assessment"].get("risk_level"),
                "findings_count": len(individual["findings"]),
                "summary": individual["summary"]
            })
            
            all_domains.update(individual.get("related_domains", []))
            all_relations.extend(individual["evidence"].get("domain_relations", []))
        
        node_ids = {}
        nodes = []
        for i, domain in enumerate(all_domains):
            node_ids[domain] = i
            is_primary = domain in domains
            nodes.append({
                "id": i,
                "domain": domain,
                "type": "primary" if is_primary else "related"
            })
        
        edges = []
        seen_edges = set()
        for rel in all_relations:
            source = rel.get("source")
            target = rel.get("target")
            
            if source in node_ids and target in node_ids:
                edge_key = (source, target)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges.append({
                        "source": node_ids[source],
                        "target": node_ids[target],
                        "type": rel.get("relation_type"),
                        "confidence": rel.get("confidence", 50)
                    })
        
        report["network_topology"] = {"nodes": nodes, "edges": edges}
        
        risk_scores = [r["risk_score"] for r in report["individual_reports"]]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        report["aggregate_statistics"] = {
            "total_domains": len(all_domains),
            "primary_domains": len(domains),
            "related_domains": len(all_domains) - len(domains),
            "total_connections": len(edges),
            "average_risk_score": round(avg_risk, 2),
            "high_risk_domains": len([r for r in report["individual_reports"] if r["risk_level"] in ["high", "critical"]])
        }
        
        if avg_risk >= 60:
            network_level = "critical"
        elif avg_risk >= 40:
            network_level = "high"
        elif avg_risk >= 20:
            network_level = "medium"
        else:
            network_level = "low"
        
        report["network_risk_assessment"] = {
            "average_score": round(avg_risk, 2),
            "network_risk_level": network_level,
            "highest_risk_domain": max(report["individual_reports"], key=lambda x: x["risk_score"])["domain"] if report["individual_reports"] else None
        }
        
        if network_level in ["critical", "high"]:
            report["recommendations"].append({
                "priority": "high",
                "action": "Network-wide blocking",
                "details": f"Block all {len(all_domains)} identified domains"
            })
        
        if len(edges) > len(domains):
            report["recommendations"].append({
                "priority": "medium",
                "action": "Disrupt network connections",
                "details": "Target shared infrastructure to disrupt entire network"
            })
        
        if self.db:
            self.db.save_evidence_report(report_id, {
                "title": report["title"],
                "summary": f"Network of {len(all_domains)} domains with {network_level} risk level",
                "domains": list(all_domains),
                "findings": [],
                "recommendations": report["recommendations"]
            })
        
        return report
    
    def export_report_text(self, report: Dict) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append(report.get("title", "Evidence Report"))
        lines.append("=" * 60)
        lines.append(f"Generated: {report.get('generated_at')}")
        lines.append(f"Report ID: {report.get('report_id')}")
        lines.append("")
        
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(report.get("summary", "No summary available"))
        lines.append("")
        
        risk = report.get("risk_assessment", {})
        lines.append("RISK ASSESSMENT")
        lines.append("-" * 40)
        lines.append(f"Risk Score: {risk.get('risk_score', 0)}/100")
        lines.append(f"Risk Level: {risk.get('risk_level', 'Unknown').upper()}")
        lines.append("")
        
        findings = report.get("findings", [])
        if findings:
            lines.append("KEY FINDINGS")
            lines.append("-" * 40)
            for i, finding in enumerate(findings, 1):
                lines.append(f"{i}. [{finding.get('severity', 'info').upper()}] {finding.get('title')}")
                lines.append(f"   {finding.get('details', '')}")
            lines.append("")
        
        recommendations = report.get("recommendations", [])
        if recommendations:
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 40)
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. [{rec.get('priority', 'medium').upper()}] {rec.get('action')}")
                lines.append(f"   {rec.get('details', '')}")
            lines.append("")
        
        lines.append("=" * 60)
        lines.append("END OF REPORT")
        lines.append("=" * 60)
        
        return "\n".join(lines)
