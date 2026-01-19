import json
import re
from typing import Dict, List, Any, Set
from datetime import datetime
from urllib.parse import urlparse, urljoin
from collections import defaultdict

import requests
from bs4 import BeautifulSoup
import tldextract

import sys
sys.path.append("..")
from config import SCAN_TIMEOUT

class DRMEngine:
    def __init__(self, db_manager=None):
        self.db = db_manager
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.max_redirect_depth = 10
        self.visited_urls = set()
    
    def extract_domain(self, url: str) -> str:
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def follow_redirects(self, url: str, depth: int = 0) -> List[Dict[str, Any]]:
        if depth >= self.max_redirect_depth:
            return []
        
        if url in self.visited_urls:
            return []
        
        self.visited_urls.add(url)
        redirect_chain = []
        
        try:
            response = self.session.get(
                url, 
                timeout=SCAN_TIMEOUT, 
                allow_redirects=False
            )
            
            redirect_chain.append({
                "url": url,
                "domain": self.extract_domain(url),
                "status_code": response.status_code,
                "depth": depth
            })
            
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("Location", "")
                
                if location:
                    if not location.startswith("http"):
                        location = urljoin(url, location)
                    
                    redirect_chain[-1]["redirect_to"] = location
                    redirect_chain[-1]["redirect_type"] = response.status_code
                    
                    next_chain = self.follow_redirects(location, depth + 1)
                    redirect_chain.extend(next_chain)
            
            elif response.status_code == 200:
                meta_refresh = self._check_meta_refresh(response.text)
                js_redirect = self._check_js_redirect(response.text)
                
                if meta_refresh:
                    redirect_chain[-1]["meta_refresh"] = meta_refresh
                    next_chain = self.follow_redirects(meta_refresh, depth + 1)
                    redirect_chain.extend(next_chain)
                elif js_redirect:
                    redirect_chain[-1]["js_redirect"] = js_redirect
                    
        except Exception as e:
            redirect_chain.append({
                "url": url,
                "domain": self.extract_domain(url),
                "error": str(e),
                "depth": depth
            })
        
        return redirect_chain
    
    def _check_meta_refresh(self, html: str) -> str:
        try:
            soup = BeautifulSoup(html, "html.parser")
            meta = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
            
            if meta:
                content = meta.get("content", "")
                match = re.search(r"url\s*=\s*['\"]?([^'\">\s]+)", content, re.I)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return ""
    
    def _check_js_redirect(self, html: str) -> str:
        patterns = [
            r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"window\.location\.replace\s*\(['\"]([^'\"]+)['\"]\)",
            r"document\.location\s*=\s*['\"]([^'\"]+)['\"]"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)
        
        return ""
    
    def find_domain_mirrors(self, domain: str, html_content: str = None) -> List[Dict[str, Any]]:
        mirrors = []
        base_name = tldextract.extract(domain).domain
        
        if html_content:
            soup = BeautifulSoup(html_content, "html.parser")
            links = soup.find_all("a", href=True)
            
            for link in links:
                href = link["href"]
                if href.startswith("http"):
                    link_domain = self.extract_domain(href)
                    link_base = tldextract.extract(link_domain).domain
                    
                    if link_domain != domain:
                        similarity = self._calculate_similarity(base_name, link_base)
                        
                        if similarity > 0.5 or self._is_pattern_match(base_name, link_base):
                            mirrors.append({
                                "original_domain": domain,
                                "mirror_domain": link_domain,
                                "full_url": href,
                                "similarity": similarity,
                                "link_text": link.get_text(strip=True)[:100]
                            })
        
        pattern_variations = self._generate_domain_patterns(base_name)
        
        for variation in pattern_variations:
            for tld in ["com", "net", "org", "site", "online", "xyz", "info"]:
                test_domain = f"{variation}.{tld}"
                if test_domain != domain:
                    mirrors.append({
                        "original_domain": domain,
                        "mirror_domain": test_domain,
                        "type": "pattern_generated",
                        "verified": False
                    })
        
        return mirrors
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        if not str1 or not str2:
            return 0.0
        
        set1 = set(str1.lower())
        set2 = set(str2.lower())
        
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        return intersection / union if union > 0 else 0.0
    
    def _is_pattern_match(self, original: str, candidate: str) -> bool:
        original = original.lower()
        candidate = candidate.lower()
        
        if original in candidate or candidate in original:
            return True
        
        number_pattern = re.sub(r'\d+', '', original)
        if number_pattern and number_pattern in candidate:
            return True
        
        return False
    
    def _generate_domain_patterns(self, base_name: str) -> List[str]:
        patterns = [base_name]
        
        for num in ["88", "777", "123", "99", "168", "888"]:
            patterns.append(f"{base_name}{num}")
        
        patterns.extend([
            f"link{base_name}",
            f"daftar{base_name}",
            f"login{base_name}",
            f"alt{base_name}",
            f"mirror{base_name}",
            f"{base_name}alt",
            f"{base_name}link",
            f"{base_name}new"
        ])
        
        return patterns
    
    def build_rotation_map(self, starting_url: str) -> Dict[str, Any]:
        self.visited_urls.clear()
        
        result = {
            "starting_url": starting_url,
            "starting_domain": self.extract_domain(starting_url),
            "analyzed_at": datetime.now().isoformat(),
            "redirect_chain": [],
            "domains_in_chain": [],
            "mirrors_detected": [],
            "rotation_pattern": {},
            "graph": {"nodes": [], "edges": []}
        }
        
        result["redirect_chain"] = self.follow_redirects(starting_url)
        
        domains_seen = []
        for step in result["redirect_chain"]:
            domain = step.get("domain")
            if domain and domain not in domains_seen:
                domains_seen.append(domain)
        
        result["domains_in_chain"] = domains_seen
        
        try:
            response = self.session.get(starting_url, timeout=SCAN_TIMEOUT)
            if response.status_code == 200:
                result["mirrors_detected"] = self.find_domain_mirrors(
                    result["starting_domain"], 
                    response.text
                )
        except Exception:
            pass
        
        result["rotation_pattern"] = self._analyze_rotation_pattern(result)
        result["graph"] = self._build_graph(result)
        
        if self.db:
            for i, domain in enumerate(domains_seen):
                if i < len(domains_seen) - 1:
                    self.db.save_domain_relation(
                        domain, domains_seen[i + 1],
                        "redirect", 90,
                        json.dumps({"chain_position": i})
                    )
            
            for mirror in result["mirrors_detected"]:
                if mirror.get("verified") is not False:
                    self.db.save_domain_relation(
                        result["starting_domain"],
                        mirror["mirror_domain"],
                        "potential_mirror",
                        int(mirror.get("similarity", 0.5) * 100),
                        json.dumps(mirror)
                    )
        
        return result
    
    def _analyze_rotation_pattern(self, data: Dict[str, Any]) -> Dict[str, Any]:
        chain = data.get("redirect_chain", [])
        domains = data.get("domains_in_chain", [])
        
        pattern = {
            "chain_length": len(chain),
            "unique_domains": len(domains),
            "uses_redirect": any(step.get("redirect_type") for step in chain),
            "uses_meta_refresh": any(step.get("meta_refresh") for step in chain),
            "uses_js_redirect": any(step.get("js_redirect") for step in chain),
            "rotation_type": "none"
        }
        
        if pattern["unique_domains"] > 1:
            if pattern["uses_redirect"]:
                pattern["rotation_type"] = "http_redirect"
            elif pattern["uses_meta_refresh"]:
                pattern["rotation_type"] = "meta_refresh"
            elif pattern["uses_js_redirect"]:
                pattern["rotation_type"] = "javascript"
        
        pattern["complexity"] = "simple"
        if pattern["chain_length"] > 3:
            pattern["complexity"] = "moderate"
        if pattern["chain_length"] > 5 or pattern["unique_domains"] > 3:
            pattern["complexity"] = "complex"
        
        return pattern
    
    def _build_graph(self, data: Dict[str, Any]) -> Dict[str, Any]:
        nodes = []
        edges = []
        node_ids = {}
        
        for domain in data.get("domains_in_chain", []):
            node_id = len(nodes)
            node_ids[domain] = node_id
            nodes.append({
                "id": node_id,
                "domain": domain,
                "type": "redirect_chain"
            })
        
        chain = data.get("redirect_chain", [])
        for i, step in enumerate(chain):
            if step.get("redirect_to"):
                source = step.get("domain")
                target_url = step.get("redirect_to")
                target = self.extract_domain(target_url)
                
                if source in node_ids and target in node_ids:
                    edges.append({
                        "source": node_ids[source],
                        "target": node_ids[target],
                        "type": "redirect",
                        "status_code": step.get("redirect_type")
                    })
        
        for mirror in data.get("mirrors_detected", []):
            mirror_domain = mirror.get("mirror_domain")
            if mirror_domain and mirror_domain not in node_ids:
                node_id = len(nodes)
                node_ids[mirror_domain] = node_id
                nodes.append({
                    "id": node_id,
                    "domain": mirror_domain,
                    "type": "mirror"
                })
                
                source_domain = mirror.get("original_domain")
                if source_domain in node_ids:
                    edges.append({
                        "source": node_ids[source_domain],
                        "target": node_id,
                        "type": "mirror",
                        "similarity": mirror.get("similarity")
                    })
        
        return {"nodes": nodes, "edges": edges}
    
    def track_domain_rotation(self, domains: List[str]) -> Dict[str, Any]:
        result = {
            "analyzed_at": datetime.now().isoformat(),
            "domains_analyzed": len(domains),
            "rotation_maps": [],
            "combined_graph": {"nodes": [], "edges": []},
            "statistics": {}
        }
        
        all_nodes = {}
        all_edges = []
        
        for domain in domains:
            if not domain.startswith("http"):
                url = f"https://{domain}"
            else:
                url = domain
            
            try:
                rotation_map = self.build_rotation_map(url)
                result["rotation_maps"].append(rotation_map)
                
                for node in rotation_map["graph"]["nodes"]:
                    if node["domain"] not in all_nodes:
                        all_nodes[node["domain"]] = len(all_nodes)
                
                for edge in rotation_map["graph"]["edges"]:
                    source_domain = rotation_map["graph"]["nodes"][edge["source"]]["domain"]
                    target_domain = rotation_map["graph"]["nodes"][edge["target"]]["domain"]
                    
                    all_edges.append({
                        "source": all_nodes[source_domain],
                        "target": all_nodes[target_domain],
                        "type": edge["type"]
                    })
            except Exception:
                continue
        
        result["combined_graph"]["nodes"] = [
            {"id": idx, "domain": domain} 
            for domain, idx in all_nodes.items()
        ]
        result["combined_graph"]["edges"] = all_edges
        
        result["statistics"] = {
            "total_domains_found": len(all_nodes),
            "total_connections": len(all_edges),
            "redirect_connections": len([e for e in all_edges if e["type"] == "redirect"]),
            "mirror_connections": len([e for e in all_edges if e["type"] == "mirror"])
        }
        
        return result
