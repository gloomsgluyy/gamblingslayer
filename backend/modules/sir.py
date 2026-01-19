import socket
import ssl
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

import dns.resolver
import requests
import tldextract

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

import sys
sys.path.append("..")
from config import DNS_RESOLVERS

class SIREngine:
    def __init__(self, db_manager=None):
        self.db = db_manager
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
    
    def extract_domain(self, url_or_domain: str) -> str:
        if url_or_domain.startswith("http"):
            parsed = urlparse(url_or_domain)
            extracted = tldextract.extract(parsed.netloc)
        else:
            extracted = tldextract.extract(url_or_domain)
        
        return f"{extracted.domain}.{extracted.suffix}"
    
    def resolve_dns(self, domain: str, record_type: str = "A") -> List[Dict[str, Any]]:
        results = []
        
        for resolver_ip in DNS_RESOLVERS:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = 5
                resolver.lifetime = 10
                
                answers = resolver.resolve(domain, record_type)
                
                for rdata in answers:
                    results.append({
                        "resolver": resolver_ip,
                        "record_type": record_type,
                        "value": str(rdata),
                        "ttl": answers.rrset.ttl if answers.rrset else None
                    })
            except Exception:
                continue
        
        return results
    
    def get_all_dns_records(self, domain: str) -> Dict[str, List[Dict]]:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        all_records = {}
        
        for rtype in record_types:
            records = self.resolve_dns(domain, rtype)
            if records:
                all_records[rtype] = records
                
                if self.db:
                    for record in records:
                        self.db.save_dns_record(
                            domain, rtype, record["value"],
                            record["resolver"], record.get("ttl")
                        )
        
        return all_records
    
    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        if not WHOIS_AVAILABLE:
            return {"error": "whois library not available"}
        
        try:
            w = whois.whois(domain)
            
            def safe_str(val):
                if val is None:
                    return None
                if isinstance(val, list):
                    return [str(v) for v in val]
                return str(val)
            
            return {
                "domain": domain,
                "registrar": safe_str(w.registrar),
                "creation_date": safe_str(w.creation_date),
                "expiration_date": safe_str(w.expiration_date),
                "updated_date": safe_str(w.updated_date),
                "nameservers": safe_str(w.name_servers),
                "status": safe_str(w.status),
                "emails": safe_str(w.emails),
                "org": safe_str(w.org),
                "country": safe_str(w.country)
            }
        except Exception as e:
            return {"domain": domain, "error": str(e)}
    
    def get_ssl_info(self, domain: str, port: int = 443) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    
                    return {
                        "domain": domain,
                        "subject_cn": subject.get("commonName"),
                        "issuer_cn": issuer.get("commonName"),
                        "issuer_org": issuer.get("organizationName"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "serial_number": cert.get("serialNumber"),
                        "version": cert.get("version"),
                        "san": [x[1] for x in cert.get("subjectAltName", [])]
                    }
        except Exception as e:
            return {"domain": domain, "error": str(e)}
    
    def get_ip_info(self, ip: str) -> Dict[str, Any]:
        try:
            response = self.session.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    "ip": ip,
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as"),
                    "asn": data.get("as", "").split()[0] if data.get("as") else None
                }
        except Exception as e:
            return {"ip": ip, "error": str(e)}
        
        return {"ip": ip, "error": "lookup failed"}
    
    def get_http_headers(self, url: str) -> Dict[str, Any]:
        if not url.startswith("http"):
            url = f"https://{url}"
        
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            
            return {
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "server": response.headers.get("Server"),
                "powered_by": response.headers.get("X-Powered-By"),
                "content_type": response.headers.get("Content-Type"),
                "redirected": url != response.url
            }
        except Exception as e:
            return {"url": url, "error": str(e)}
    
    def find_related_domains(self, domain: str) -> List[Dict[str, Any]]:
        relations = []
        
        dns_records = self.get_all_dns_records(domain)
        
        ip_addresses = []
        for record in dns_records.get("A", []):
            ip_addresses.append(record["value"])
        
        nameservers = []
        for record in dns_records.get("NS", []):
            ns_domain = record["value"].rstrip(".")
            nameservers.append(ns_domain)
            relations.append({
                "source": domain,
                "target": ns_domain,
                "relation_type": "nameserver",
                "confidence": 70
            })
        
        ssl_info = self.get_ssl_info(domain)
        if ssl_info.get("san"):
            for san in ssl_info["san"]:
                if san != domain and not san.startswith("*"):
                    relations.append({
                        "source": domain,
                        "target": san,
                        "relation_type": "ssl_san",
                        "confidence": 85
                    })
        
        for ip in ip_addresses:
            ip_info = self.get_ip_info(ip)
            if ip_info.get("asn"):
                relations.append({
                    "source": domain,
                    "target": ip,
                    "relation_type": "resolves_to",
                    "confidence": 100,
                    "metadata": ip_info
                })
        
        if self.db:
            for rel in relations:
                self.db.save_domain_relation(
                    rel["source"], rel["target"],
                    rel["relation_type"], rel["confidence"],
                    json.dumps(rel.get("metadata", {}))
                )
        
        return relations
    
    def analyze_infrastructure(self, url_or_domain: str) -> Dict[str, Any]:
        domain = self.extract_domain(url_or_domain)
        
        result = {
            "domain": domain,
            "analyzed_at": datetime.now().isoformat(),
            "dns_records": {},
            "whois": {},
            "ssl": {},
            "ip_info": [],
            "http_headers": {},
            "relations": [],
            "risk_indicators": []
        }
        
        result["dns_records"] = self.get_all_dns_records(domain)
        result["whois"] = self.get_whois_info(domain)
        result["ssl"] = self.get_ssl_info(domain)
        
        if url_or_domain.startswith("http"):
            result["http_headers"] = self.get_http_headers(url_or_domain)
        else:
            result["http_headers"] = self.get_http_headers(f"https://{domain}")
        
        ip_addresses = []
        for record in result["dns_records"].get("A", []):
            ip = record["value"]
            if ip not in [info.get("ip") for info in result["ip_info"]]:
                ip_info = self.get_ip_info(ip)
                result["ip_info"].append(ip_info)
                ip_addresses.append(ip)
        
        result["relations"] = self.find_related_domains(domain)
        
        result["risk_indicators"] = self._analyze_risk_indicators(result)
        
        if self.db:
            domain_info = {
                "ip_addresses": ip_addresses,
                "nameservers": [r["value"] for r in result["dns_records"].get("NS", [])],
                "registrar": result["whois"].get("registrar"),
                "creation_date": str(result["whois"].get("creation_date")),
                "expiration_date": str(result["whois"].get("expiration_date")),
                "ssl_issuer": result["ssl"].get("issuer_org"),
                "ssl_expiry": result["ssl"].get("not_after"),
                "asn": result["ip_info"][0].get("asn") if result["ip_info"] else None,
                "hosting_provider": result["ip_info"][0].get("isp") if result["ip_info"] else None,
                "metadata": {
                    "headers": result["http_headers"],
                    "risk_indicators": result["risk_indicators"]
                }
            }
            self.db.save_domain_info(domain, domain_info)
        
        return result
    
    def _analyze_risk_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        indicators = []
        
        whois = data.get("whois", {})
        if whois.get("creation_date"):
            try:
                creation = whois["creation_date"]
                if isinstance(creation, list):
                    creation = creation[0]
            except Exception:
                pass
        
        if whois.get("error"):
            indicators.append({
                "type": "whois_hidden",
                "severity": "medium",
                "description": "WHOIS information is hidden or unavailable"
            })
        
        ssl = data.get("ssl", {})
        if ssl.get("error"):
            indicators.append({
                "type": "ssl_error",
                "severity": "high",
                "description": "SSL certificate error or not present"
            })
        
        issuer = ssl.get("issuer_org", "")
        if issuer and "let's encrypt" in issuer.lower():
            indicators.append({
                "type": "free_ssl",
                "severity": "low",
                "description": "Using free SSL certificate (common for gambling sites)"
            })
        
        headers = data.get("http_headers", {})
        if headers.get("redirected"):
            indicators.append({
                "type": "redirect_detected",
                "severity": "medium",
                "description": f"Redirects to different URL: {headers.get('final_url')}"
            })
        
        ip_info = data.get("ip_info", [])
        high_risk_countries = ["RU", "CN", "VN", "PH", "MY"]
        for info in ip_info:
            if info.get("country_code") in high_risk_countries:
                indicators.append({
                    "type": "high_risk_hosting",
                    "severity": "high",
                    "description": f"Hosted in high-risk country: {info.get('country')}"
                })
        
        ns_records = data.get("dns_records", {}).get("NS", [])
        ns_domains = set()
        for record in ns_records:
            ns_domain = tldextract.extract(record["value"]).registered_domain
            ns_domains.add(ns_domain)
        
        if len(ns_domains) > 1:
            indicators.append({
                "type": "multiple_ns_providers",
                "severity": "low",
                "description": "Using nameservers from multiple providers"
            })
        
        return indicators
    
    def compare_with_history(self, domain: str) -> Dict[str, Any]:
        if not self.db:
            return {"domain": domain, "changes": [], "error": "No database available"}
        
        current = self.analyze_infrastructure(domain)
        previous = self.db.get_domain_info(domain)
        
        if not previous:
            return {"domain": domain, "changes": [], "is_new": True, "current": current}
        
        changes = []
        
        current_ips = set()
        for record in current["dns_records"].get("A", []):
            current_ips.add(record["value"])
        previous_ips = set(previous.get("ip_addresses", []))
        
        if current_ips != previous_ips:
            changes.append({
                "type": "ip_change",
                "old": list(previous_ips),
                "new": list(current_ips)
            })
            
            if self.db:
                self.db.save_infrastructure_change(
                    domain, "ip_change",
                    json.dumps(list(previous_ips)),
                    json.dumps(list(current_ips))
                )
        
        current_ns = set()
        for record in current["dns_records"].get("NS", []):
            current_ns.add(record["value"].rstrip("."))
        previous_ns = set(previous.get("nameservers", []))
        
        if current_ns != previous_ns:
            changes.append({
                "type": "nameserver_change",
                "old": list(previous_ns),
                "new": list(current_ns)
            })
            
            if self.db:
                self.db.save_infrastructure_change(
                    domain, "nameserver_change",
                    json.dumps(list(previous_ns)),
                    json.dumps(list(current_ns))
                )
        
        current_hosting = current["ip_info"][0].get("isp") if current["ip_info"] else None
        previous_hosting = previous.get("hosting_provider")
        
        if current_hosting and previous_hosting and current_hosting != previous_hosting:
            changes.append({
                "type": "hosting_change",
                "old": previous_hosting,
                "new": current_hosting
            })
            
            if self.db:
                self.db.save_infrastructure_change(
                    domain, "hosting_change",
                    previous_hosting, current_hosting
                )
        
        return {
            "domain": domain,
            "changes": changes,
            "has_changes": len(changes) > 0,
            "current": current,
            "previous_snapshot": previous
        }
