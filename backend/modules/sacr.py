import json
import uuid
from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict

import tldextract

import sys
sys.path.append("..")

class SACREngine:
    def __init__(self, db_manager=None):
        self.db = db_manager
        
        self.event_types = {
            "domain_activation": {"weight": 10, "category": "initiation"},
            "ip_change": {"weight": 8, "category": "infrastructure"},
            "hosting_change": {"weight": 9, "category": "infrastructure"},
            "nameserver_change": {"weight": 7, "category": "infrastructure"},
            "ssl_change": {"weight": 5, "category": "security"},
            "dns_tampering": {"weight": 10, "category": "evasion"},
            "shadow_manipulation": {"weight": 9, "category": "evasion"},
            "domain_rotation": {"weight": 8, "category": "rotation"},
            "mirror_creation": {"weight": 7, "category": "rotation"},
            "redirect_chain": {"weight": 6, "category": "rotation"},
            "behavior_change": {"weight": 5, "category": "adaptation"}
        }
    
    def extract_domain(self, url_or_domain: str) -> str:
        extracted = tldextract.extract(url_or_domain)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def collect_events(self, domain: str) -> List[Dict[str, Any]]:
        domain = self.extract_domain(domain)
        events = []
        
        if not self.db:
            return events
        
        for change in self.db.get_infrastructure_changes(domain):
            events.append({
                "id": f"inf_{change.get('id')}",
                "timestamp": change.get("detected_at"),
                "type": change.get("change_type"),
                "domain": domain,
                "details": {
                    "old": change.get("old_value"),
                    "new": change.get("new_value")
                },
                "source": "infrastructure_changes"
            })
        
        for log in self.db.get_behavior_logs(domain):
            events.append({
                "id": f"beh_{log.get('id')}",
                "timestamp": log.get("detected_at"),
                "type": log.get("behavior_type"),
                "domain": domain,
                "details": {
                    "description": log.get("description"),
                    "metadata": json.loads(log.get("metadata") or "{}")
                },
                "source": "behavior_logs"
            })
        
        for relation in self.db.get_domain_relations(domain):
            if relation.get("relation_type") in ["redirect", "mirror", "potential_mirror"]:
                events.append({
                    "id": f"rel_{relation.get('id')}",
                    "timestamp": relation.get("created_at"),
                    "type": "domain_connection",
                    "domain": domain,
                    "details": {
                        "target": relation.get("target_domain"),
                        "relation_type": relation.get("relation_type"),
                        "confidence": relation.get("confidence")
                    },
                    "source": "domain_relations"
                })
        
        events.sort(key=lambda x: x.get("timestamp") or "")
        
        return events
    
    def normalize_events(self, events: List[Dict]) -> List[Dict[str, Any]]:
        normalized = []
        
        for event in events:
            event_type = event.get("type", "unknown")
            type_info = self.event_types.get(event_type, {"weight": 5, "category": "other"})
            
            normalized.append({
                "id": event.get("id"),
                "timestamp": event.get("timestamp"),
                "type": event_type,
                "category": type_info["category"],
                "weight": type_info["weight"],
                "domain": event.get("domain"),
                "details": event.get("details", {}),
                "source": event.get("source")
            })
        
        return normalized
    
    def find_event_relationships(self, events: List[Dict]) -> List[Dict[str, Any]]:
        relationships = []
        
        for i, event1 in enumerate(events):
            for event2 in events[i+1:]:
                relation = self._check_relationship(event1, event2)
                if relation:
                    relationships.append({
                        "source_event": event1["id"],
                        "target_event": event2["id"],
                        "relation_type": relation["type"],
                        "confidence": relation["confidence"],
                        "description": relation.get("description", "")
                    })
        
        return relationships
    
    def _check_relationship(self, event1: Dict, event2: Dict) -> Dict[str, Any]:
        if event1.get("category") == event2.get("category"):
            return {
                "type": "same_category",
                "confidence": 70,
                "description": f"Both events in {event1.get('category')} category"
            }
        
        if event1.get("category") == "evasion" and event2.get("category") == "infrastructure":
            return {
                "type": "evasion_to_infrastructure",
                "confidence": 80,
                "description": "Evasion tactic followed by infrastructure change"
            }
        
        if event1.get("category") == "rotation" and event2.get("category") == "infrastructure":
            return {
                "type": "rotation_infrastructure",
                "confidence": 75,
                "description": "Domain rotation followed by infrastructure change"
            }
        
        if event1.get("type") == "domain_connection":
            return {
                "type": "domain_expansion",
                "confidence": 85,
                "description": "Network expansion detected"
            }
        
        return None
    
    def build_attack_chain(self, domain: str) -> Dict[str, Any]:
        domain = self.extract_domain(domain)
        chain_id = f"chain_{uuid.uuid4().hex[:12]}"
        
        events = self.collect_events(domain)
        normalized = self.normalize_events(events)
        relationships = self.find_event_relationships(normalized)
        
        phases = self._identify_phases(normalized)
        
        timeline = []
        for event in normalized:
            timeline.append({
                "timestamp": event.get("timestamp"),
                "event_id": event.get("id"),
                "type": event.get("type"),
                "category": event.get("category"),
                "weight": event.get("weight"),
                "phase": self._get_event_phase(event, phases)
            })
        
        chain = {
            "chain_id": chain_id,
            "domain": domain,
            "generated_at": datetime.now().isoformat(),
            "total_events": len(events),
            "events": normalized,
            "relationships": relationships,
            "phases": phases,
            "timeline": timeline,
            "graph": self._build_chain_graph(normalized, relationships),
            "analysis": self._analyze_chain(normalized, relationships, phases)
        }
        
        if self.db:
            self.db.save_attack_chain(chain_id, {
                "domains": [domain],
                "events": normalized,
                "timeline": timeline,
                "analysis": chain["analysis"]
            })
        
        return chain
    
    def _identify_phases(self, events: List[Dict]) -> List[Dict[str, Any]]:
        phases = []
        
        initiation_events = [e for e in events if e.get("category") == "initiation"]
        if initiation_events:
            phases.append({
                "name": "initiation",
                "description": "Initial domain setup and activation",
                "event_count": len(initiation_events),
                "start": initiation_events[0].get("timestamp"),
                "end": initiation_events[-1].get("timestamp")
            })
        
        infra_events = [e for e in events if e.get("category") == "infrastructure"]
        if infra_events:
            phases.append({
                "name": "infrastructure_setup",
                "description": "Infrastructure configuration and changes",
                "event_count": len(infra_events),
                "start": infra_events[0].get("timestamp"),
                "end": infra_events[-1].get("timestamp")
            })
        
        rotation_events = [e for e in events if e.get("category") == "rotation"]
        if rotation_events:
            phases.append({
                "name": "expansion",
                "description": "Domain rotation and mirror creation",
                "event_count": len(rotation_events),
                "start": rotation_events[0].get("timestamp"),
                "end": rotation_events[-1].get("timestamp")
            })
        
        evasion_events = [e for e in events if e.get("category") == "evasion"]
        if evasion_events:
            phases.append({
                "name": "evasion",
                "description": "Evasion tactics and shadow manipulation",
                "event_count": len(evasion_events),
                "start": evasion_events[0].get("timestamp"),
                "end": evasion_events[-1].get("timestamp")
            })
        
        return phases
    
    def _get_event_phase(self, event: Dict, phases: List[Dict]) -> str:
        category_to_phase = {
            "initiation": "initiation",
            "infrastructure": "infrastructure_setup",
            "rotation": "expansion",
            "evasion": "evasion",
            "adaptation": "adaptation",
            "security": "infrastructure_setup"
        }
        return category_to_phase.get(event.get("category"), "other")
    
    def _build_chain_graph(self, events: List[Dict], relationships: List[Dict]) -> Dict[str, Any]:
        nodes = []
        edges = []
        
        event_id_to_idx = {}
        for i, event in enumerate(events):
            event_id_to_idx[event["id"]] = i
            nodes.append({
                "id": i,
                "event_id": event["id"],
                "type": event["type"],
                "category": event["category"],
                "weight": event["weight"],
                "timestamp": event.get("timestamp")
            })
        
        for rel in relationships:
            source_id = rel.get("source_event")
            target_id = rel.get("target_event")
            
            if source_id in event_id_to_idx and target_id in event_id_to_idx:
                edges.append({
                    "source": event_id_to_idx[source_id],
                    "target": event_id_to_idx[target_id],
                    "type": rel["relation_type"],
                    "confidence": rel["confidence"]
                })
        
        for i in range(len(events) - 1):
            sequential_exists = any(
                e["source"] == i and e["target"] == i + 1 
                for e in edges
            )
            if not sequential_exists:
                edges.append({
                    "source": i,
                    "target": i + 1,
                    "type": "sequential",
                    "confidence": 50
                })
        
        return {"nodes": nodes, "edges": edges}
    
    def _analyze_chain(self, events: List[Dict], relationships: List[Dict], phases: List[Dict]) -> Dict[str, Any]:
        analysis = {
            "chain_length": len(events),
            "phase_count": len(phases),
            "relationship_count": len(relationships),
            "category_distribution": {},
            "sophistication_score": 0,
            "key_events": [],
            "patterns_detected": [],
            "recommendations": []
        }
        
        category_counts = defaultdict(int)
        for event in events:
            category_counts[event.get("category", "other")] += 1
        analysis["category_distribution"] = dict(category_counts)
        
        total_weight = sum(e.get("weight", 0) for e in events)
        analysis["sophistication_score"] = min(
            int((total_weight / max(len(events), 1)) * 10 + len(phases) * 5),
            100
        )
        
        sorted_events = sorted(events, key=lambda x: x.get("weight", 0), reverse=True)
        analysis["key_events"] = [
            {"type": e["type"], "category": e["category"], "weight": e["weight"]}
            for e in sorted_events[:5]
        ]
        
        if category_counts.get("evasion", 0) > 2:
            analysis["patterns_detected"].append("active_evasion")
        
        if category_counts.get("rotation", 0) > 2:
            analysis["patterns_detected"].append("domain_rotation")
        
        if category_counts.get("infrastructure", 0) > 3:
            analysis["patterns_detected"].append("infrastructure_hopping")
        
        if "active_evasion" in analysis["patterns_detected"]:
            analysis["recommendations"].append("High priority monitoring - active evasion detected")
        
        if "domain_rotation" in analysis["patterns_detected"]:
            analysis["recommendations"].append("Track related domains for complete network mapping")
        
        if analysis["sophistication_score"] >= 50:
            analysis["recommendations"].append("Consider proactive blocking of related infrastructure")
        
        return analysis
    
    def reconstruct_multi_domain_chain(self, domains: List[str]) -> Dict[str, Any]:
        chain_id = f"multi_{uuid.uuid4().hex[:12]}"
        
        all_events = []
        domain_events = {}
        
        for domain in domains:
            domain = self.extract_domain(domain)
            events = self.collect_events(domain)
            normalized = self.normalize_events(events)
            
            domain_events[domain] = normalized
            all_events.extend(normalized)
        
        all_events.sort(key=lambda x: x.get("timestamp") or "")
        
        relationships = self.find_event_relationships(all_events)
        
        cross_domain_relations = []
        for rel in relationships:
            source_domain = None
            target_domain = None
            
            for domain, events in domain_events.items():
                if any(e["id"] == rel["source_event"] for e in events):
                    source_domain = domain
                if any(e["id"] == rel["target_event"] for e in events):
                    target_domain = domain
            
            if source_domain and target_domain and source_domain != target_domain:
                cross_domain_relations.append({
                    **rel,
                    "source_domain": source_domain,
                    "target_domain": target_domain
                })
        
        result = {
            "chain_id": chain_id,
            "domains": domains,
            "generated_at": datetime.now().isoformat(),
            "total_events": len(all_events),
            "events_by_domain": {d: len(e) for d, e in domain_events.items()},
            "combined_timeline": all_events,
            "relationships": relationships,
            "cross_domain_relations": cross_domain_relations,
            "network_analysis": self._analyze_domain_network(domain_events, cross_domain_relations)
        }
        
        if self.db:
            self.db.save_attack_chain(chain_id, {
                "domains": domains,
                "events": all_events,
                "timeline": all_events,
                "analysis": result["network_analysis"]
            })
        
        return result
    
    def _analyze_domain_network(self, domain_events: Dict, cross_domain: List[Dict]) -> Dict[str, Any]:
        analysis = {
            "network_size": len(domain_events),
            "cross_domain_connections": len(cross_domain),
            "central_domain": None,
            "network_pattern": "unknown",
            "coordination_level": "low"
        }
        
        domain_activity = {d: len(e) for d, e in domain_events.items()}
        if domain_activity:
            analysis["central_domain"] = max(domain_activity, key=domain_activity.get)
        
        if len(cross_domain) > len(domain_events) * 2:
            analysis["network_pattern"] = "highly_connected"
            analysis["coordination_level"] = "high"
        elif len(cross_domain) > len(domain_events):
            analysis["network_pattern"] = "moderately_connected"
            analysis["coordination_level"] = "medium"
        elif len(cross_domain) > 0:
            analysis["network_pattern"] = "loosely_connected"
            analysis["coordination_level"] = "low"
        else:
            analysis["network_pattern"] = "isolated"
            analysis["coordination_level"] = "none"
        
        return analysis
