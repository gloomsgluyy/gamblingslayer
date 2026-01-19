import json
from typing import Dict, List, Any
from datetime import datetime, timedelta
from collections import defaultdict

import tldextract

import sys
sys.path.append("..")

class DABEEngine:
    def __init__(self, db_manager=None):
        self.db = db_manager
        
        self.behavior_categories = {
            "infrastructure": ["ip_change", "hosting_change", "nameserver_change", "ssl_change"],
            "rotation": ["domain_rotation", "mirror_creation", "redirect_chain"],
            "evasion": ["dns_tampering", "shadow_manipulation", "cloaking"],
            "expansion": ["subdomain_creation", "new_domain", "network_growth"]
        }
    
    def extract_domain(self, url_or_domain: str) -> str:
        extracted = tldextract.extract(url_or_domain)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def extract_behavior_patterns(self, domain: str) -> Dict[str, Any]:
        domain = self.extract_domain(domain)
        
        if not self.db:
            return {"domain": domain, "error": "No database available"}
        
        result = {
            "domain": domain,
            "analyzed_at": datetime.now().isoformat(),
            "behavior_logs": [],
            "infrastructure_changes": [],
            "patterns_detected": [],
            "behavior_timeline": [],
            "behavioral_profile": {}
        }
        
        result["behavior_logs"] = self.db.get_behavior_logs(domain)
        result["infrastructure_changes"] = self.db.get_infrastructure_changes(domain)
        
        all_events = []
        
        for log in result["behavior_logs"]:
            all_events.append({
                "timestamp": log.get("detected_at"),
                "type": log.get("behavior_type"),
                "source": "behavior_log",
                "description": log.get("description"),
                "metadata": json.loads(log.get("metadata") or "{}")
            })
        
        for change in result["infrastructure_changes"]:
            all_events.append({
                "timestamp": change.get("detected_at"),
                "type": change.get("change_type"),
                "source": "infrastructure_change",
                "description": f"Changed from {change.get('old_value')} to {change.get('new_value')}"
            })
        
        all_events.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
        result["behavior_timeline"] = all_events
        
        result["patterns_detected"] = self._detect_patterns(all_events)
        result["behavioral_profile"] = self._build_profile(result)
        
        return result
    
    def _detect_patterns(self, events: List[Dict]) -> List[Dict[str, Any]]:
        patterns = []
        
        type_counts = defaultdict(int)
        for event in events:
            type_counts[event.get("type", "unknown")] += 1
        
        if type_counts["ip_change"] >= 3:
            patterns.append({
                "pattern": "frequent_ip_rotation",
                "severity": "high",
                "count": type_counts["ip_change"],
                "description": "Domain frequently changes IP addresses (fast-flux behavior)"
            })
        
        if type_counts["hosting_change"] >= 2:
            patterns.append({
                "pattern": "hosting_hopping",
                "severity": "high",
                "count": type_counts["hosting_change"],
                "description": "Domain switches hosting providers frequently"
            })
        
        if type_counts["nameserver_change"] >= 2:
            patterns.append({
                "pattern": "ns_rotation",
                "severity": "medium",
                "count": type_counts["nameserver_change"],
                "description": "Nameservers are rotated frequently"
            })
        
        if type_counts["dns_tampering"] >= 1:
            patterns.append({
                "pattern": "evasion_tactics",
                "severity": "high",
                "count": type_counts["dns_tampering"],
                "description": "DNS tampering or manipulation detected"
            })
        
        if type_counts["shadow_manipulation"] >= 1:
            patterns.append({
                "pattern": "shadow_infrastructure",
                "severity": "high",
                "count": type_counts["shadow_manipulation"],
                "description": "Hidden subdomains or shadow infrastructure detected"
            })
        
        if len(events) > 10:
            patterns.append({
                "pattern": "high_activity",
                "severity": "medium",
                "count": len(events),
                "description": "High volume of infrastructure changes"
            })
        
        return patterns
    
    def _build_profile(self, data: Dict[str, Any]) -> Dict[str, Any]:
        profile = {
            "sophistication_level": "low",
            "primary_behaviors": [],
            "evasion_score": 0,
            "activity_level": "low",
            "risk_category": "unknown"
        }
        
        patterns = data.get("patterns_detected", [])
        events = data.get("behavior_timeline", [])
        
        if len(events) > 10:
            profile["activity_level"] = "high"
        elif len(events) > 3:
            profile["activity_level"] = "medium"
        
        behavior_types = defaultdict(int)
        for event in events:
            event_type = event.get("type", "")
            for category, types in self.behavior_categories.items():
                if event_type in types:
                    behavior_types[category] += 1
        
        profile["primary_behaviors"] = [
            {"category": cat, "count": count}
            for cat, count in sorted(behavior_types.items(), key=lambda x: -x[1])
        ]
        
        evasion_score = 0
        for pattern in patterns:
            if pattern["severity"] == "high":
                evasion_score += 25
            elif pattern["severity"] == "medium":
                evasion_score += 15
            else:
                evasion_score += 5
        
        profile["evasion_score"] = min(evasion_score, 100)
        
        if evasion_score >= 70:
            profile["sophistication_level"] = "high"
            profile["risk_category"] = "active_evasion"
        elif evasion_score >= 40:
            profile["sophistication_level"] = "medium"
            profile["risk_category"] = "moderate_risk"
        elif evasion_score > 0:
            profile["sophistication_level"] = "low"
            profile["risk_category"] = "basic_operation"
        else:
            profile["risk_category"] = "minimal_activity"
        
        return profile
    
    def compare_behavior(self, domains: List[str]) -> Dict[str, Any]:
        result = {
            "analyzed_at": datetime.now().isoformat(),
            "domains_compared": len(domains),
            "profiles": [],
            "similarities": [],
            "clusters": []
        }
        
        for domain in domains:
            behavior = self.extract_behavior_patterns(domain)
            profile = behavior.get("behavioral_profile", {})
            profile["domain"] = domain
            result["profiles"].append(profile)
        
        result["similarities"] = self._find_similarities(result["profiles"])
        result["clusters"] = self._cluster_by_behavior(result["profiles"])
        
        return result
    
    def _find_similarities(self, profiles: List[Dict]) -> List[Dict[str, Any]]:
        similarities = []
        
        for i, p1 in enumerate(profiles):
            for p2 in profiles[i+1:]:
                similarity = self._calculate_profile_similarity(p1, p2)
                if similarity > 0.5:
                    similarities.append({
                        "domain1": p1.get("domain"),
                        "domain2": p2.get("domain"),
                        "similarity": similarity,
                        "shared_traits": self._get_shared_traits(p1, p2)
                    })
        
        return sorted(similarities, key=lambda x: -x["similarity"])
    
    def _calculate_profile_similarity(self, p1: Dict, p2: Dict) -> float:
        score = 0.0
        weights = 0
        
        if p1.get("sophistication_level") == p2.get("sophistication_level"):
            score += 0.3
        weights += 0.3
        
        if p1.get("activity_level") == p2.get("activity_level"):
            score += 0.2
        weights += 0.2
        
        evasion_diff = abs(p1.get("evasion_score", 0) - p2.get("evasion_score", 0))
        if evasion_diff <= 20:
            score += 0.3 * (1 - evasion_diff/100)
        weights += 0.3
        
        behaviors1 = set(b["category"] for b in p1.get("primary_behaviors", []))
        behaviors2 = set(b["category"] for b in p2.get("primary_behaviors", []))
        
        if behaviors1 and behaviors2:
            overlap = len(behaviors1 & behaviors2) / len(behaviors1 | behaviors2)
            score += 0.2 * overlap
        weights += 0.2
        
        return score / weights if weights > 0 else 0
    
    def _get_shared_traits(self, p1: Dict, p2: Dict) -> List[str]:
        traits = []
        
        if p1.get("sophistication_level") == p2.get("sophistication_level"):
            traits.append(f"Same sophistication: {p1.get('sophistication_level')}")
        
        if p1.get("activity_level") == p2.get("activity_level"):
            traits.append(f"Same activity level: {p1.get('activity_level')}")
        
        behaviors1 = set(b["category"] for b in p1.get("primary_behaviors", []))
        behaviors2 = set(b["category"] for b in p2.get("primary_behaviors", []))
        shared = behaviors1 & behaviors2
        
        for behavior in shared:
            traits.append(f"Shared behavior: {behavior}")
        
        return traits
    
    def _cluster_by_behavior(self, profiles: List[Dict]) -> List[Dict[str, Any]]:
        clusters = defaultdict(list)
        
        for profile in profiles:
            key = (
                profile.get("sophistication_level", "unknown"),
                profile.get("activity_level", "unknown")
            )
            clusters[key].append(profile.get("domain"))
        
        return [
            {
                "sophistication": key[0],
                "activity": key[1],
                "domains": domains,
                "count": len(domains)
            }
            for key, domains in clusters.items()
            if len(domains) > 0
        ]
    
    def track_behavior_over_time(self, domain: str, days: int = 30) -> Dict[str, Any]:
        domain = self.extract_domain(domain)
        
        if not self.db:
            return {"domain": domain, "error": "No database available"}
        
        all_events = []
        
        for log in self.db.get_behavior_logs(domain):
            all_events.append({
                "timestamp": log.get("detected_at"),
                "type": log.get("behavior_type"),
                "category": self._categorize_event(log.get("behavior_type"))
            })
        
        for change in self.db.get_infrastructure_changes(domain):
            all_events.append({
                "timestamp": change.get("detected_at"),
                "type": change.get("change_type"),
                "category": self._categorize_event(change.get("change_type"))
            })
        
        daily_activity = defaultdict(lambda: defaultdict(int))
        
        for event in all_events:
            timestamp = event.get("timestamp")
            if timestamp:
                day = str(timestamp)[:10]
                daily_activity[day][event.get("category", "other")] += 1
        
        return {
            "domain": domain,
            "analyzed_at": datetime.now().isoformat(),
            "period_days": days,
            "total_events": len(all_events),
            "daily_breakdown": dict(daily_activity),
            "trend_analysis": self._analyze_activity_trend(daily_activity)
        }
    
    def _categorize_event(self, event_type: str) -> str:
        if not event_type:
            return "other"
        
        for category, types in self.behavior_categories.items():
            if event_type in types:
                return category
        return "other"
    
    def _analyze_activity_trend(self, daily_activity: Dict) -> Dict[str, Any]:
        if not daily_activity:
            return {"trend": "no_data", "peak_day": None}
        
        daily_totals = {
            day: sum(categories.values())
            for day, categories in daily_activity.items()
        }
        
        if not daily_totals:
            return {"trend": "no_data", "peak_day": None}
        
        peak_day = max(daily_totals, key=daily_totals.get)
        avg_activity = sum(daily_totals.values()) / len(daily_totals)
        
        sorted_days = sorted(daily_totals.keys())
        if len(sorted_days) >= 3:
            first_half = sum(daily_totals[d] for d in sorted_days[:len(sorted_days)//2])
            second_half = sum(daily_totals[d] for d in sorted_days[len(sorted_days)//2:])
            
            if second_half > first_half * 1.5:
                trend = "increasing"
            elif first_half > second_half * 1.5:
                trend = "decreasing"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"
        
        return {
            "trend": trend,
            "peak_day": peak_day,
            "peak_activity": daily_totals.get(peak_day, 0),
            "average_daily_activity": round(avg_activity, 2)
        }
    
    def generate_behavior_report(self, domain: str) -> Dict[str, Any]:
        domain = self.extract_domain(domain)
        
        patterns = self.extract_behavior_patterns(domain)
        timeline = self.track_behavior_over_time(domain)
        
        profile = patterns.get("behavioral_profile", {})
        
        report = {
            "domain": domain,
            "generated_at": datetime.now().isoformat(),
            "executive_summary": "",
            "risk_level": profile.get("risk_category", "unknown"),
            "sophistication": profile.get("sophistication_level", "unknown"),
            "key_findings": [],
            "recommendations": [],
            "detailed_analysis": {
                "patterns": patterns,
                "timeline": timeline
            }
        }
        
        summary_parts = [f"Domain {domain} shows {profile.get('activity_level', 'unknown')} activity level"]
        
        if profile.get("evasion_score", 0) > 50:
            summary_parts.append(f"with significant evasion tactics (score: {profile.get('evasion_score')})")
        
        report["executive_summary"] = " ".join(summary_parts) + "."
        
        for pattern in patterns.get("patterns_detected", []):
            report["key_findings"].append(pattern["description"])
        
        if profile.get("evasion_score", 0) >= 50:
            report["recommendations"].append("High priority monitoring recommended")
            report["recommendations"].append("Consider preemptive blocking")
        
        if profile.get("activity_level") == "high":
            report["recommendations"].append("Track related domains for network mapping")
        
        if self.db:
            self.db.save_behavior_log(
                domain, "behavior_report",
                f"Generated behavior report with risk level: {report['risk_level']}",
                {"report_summary": report["executive_summary"]}
            )
        
        return report
