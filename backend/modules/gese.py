import re
import uuid
import time
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
from datetime import datetime

import requests
from bs4 import BeautifulSoup
import tldextract

import sys
sys.path.append("..")
from config import (
    GAMBLING_KEYWORDS, TRUSTED_DOMAINS, SCORE_THRESHOLDS,
    SCAN_TIMEOUT, MAX_PAGES_TO_SCAN, OPENROUTER_API_KEY, 
    OPENROUTER_MODEL, OPENROUTER_BASE_URL
)

class GESEEngine:
    def __init__(self, db_manager=None):
        self.db = db_manager
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        self.keywords = GAMBLING_KEYWORDS.copy()
        
        self.ai_available = bool(OPENROUTER_API_KEY)
        self.ai_api_key = OPENROUTER_API_KEY
        self.ai_model = OPENROUTER_MODEL
        self.ai_base_url = OPENROUTER_BASE_URL
    
    def _call_openrouter_ai(self, prompt: str) -> str:
        if not self.ai_available:
            return ""
        
        try:
            headers = {
                "Authorization": f"Bearer {self.ai_api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://gamblingslayer.site",
                "X-Title": "Gambling Slayer"
            }
            
            payload = {
                "model": self.ai_model,
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            }
            
            response = requests.post(
                f"{self.ai_base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return ""
        except Exception:
            return ""
    
    def generate_scan_id(self) -> str:
        return f"scan_{uuid.uuid4().hex[:12]}"
    
    async def expand_keywords_with_ai(self, base_keywords: List[str]) -> List[str]:
        if not self.ai_available:
            variations = []
            for kw in base_keywords[:5]:
                variations.extend([
                    f"{kw}88", f"{kw}777", f"{kw}123",
                    f"situs {kw}", f"link {kw}", f"daftar {kw}"
                ])
            return list(set(base_keywords + variations))
        
        try:
            prompt = f"""Generate 20 variations of these gambling-related Indonesian keywords for search: {', '.join(base_keywords[:10])}
            Include common patterns like adding numbers (88, 777), prefixes (situs, link, daftar), and slang variations.
            Return only the keywords, one per line, no explanations."""
            
            response_text = self._call_openrouter_ai(prompt)
            if response_text:
                expanded = response_text.strip().split("\n")
                expanded = [kw.strip() for kw in expanded if kw.strip()]
                return list(set(base_keywords + expanded))
            return base_keywords
        except Exception:
            return base_keywords
    
    def search_duckduckgo(self, keyword: str, max_pages: int = 3) -> List[str]:
        urls = []
        try:
            search_url = f"https://html.duckduckgo.com/html/?q={keyword}"
            response = self.session.get(search_url, timeout=SCAN_TIMEOUT)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                for link in soup.select("a.result__url"):
                    href = link.get("href", "")
                    if href and href.startswith("http"):
                        urls.append(href)
                
                for link in soup.select("a.result__a"):
                    href = link.get("href", "")
                    if href and href.startswith("http"):
                        urls.append(href)
        except Exception:
            pass
        
        return list(set(urls))[:50]
    
    def extract_domain_info(self, url: str) -> Dict[str, str]:
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            return {
                "url": url,
                "domain": f"{extracted.domain}.{extracted.suffix}",
                "subdomain": extracted.subdomain,
                "suffix": extracted.suffix,
                "full_domain": parsed.netloc
            }
        except Exception:
            return {"url": url, "domain": "", "subdomain": "", "suffix": "", "full_domain": ""}
    
    def is_trusted_domain(self, domain_info: Dict[str, str]) -> bool:
        suffix = domain_info.get("suffix", "")
        domain = domain_info.get("domain", "")
        
        for trusted in TRUSTED_DOMAINS:
            if suffix.endswith(trusted) or domain.endswith(trusted):
                return True
        return False
    
    def fetch_page_content(self, url: str) -> Dict[str, Any]:
        result = {
            "url": url,
            "title": "",
            "content": "",
            "meta_description": "",
            "links": [],
            "images": [],
            "scripts": [],
            "success": False,
            "error": None
        }
        
        try:
            response = self.session.get(url, timeout=SCAN_TIMEOUT, allow_redirects=True)
            result["final_url"] = response.url
            result["status_code"] = response.status_code
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                
                title_tag = soup.find("title")
                result["title"] = title_tag.get_text(strip=True) if title_tag else ""
                
                meta_desc = soup.find("meta", attrs={"name": "description"})
                if meta_desc:
                    result["meta_description"] = meta_desc.get("content", "")
                
                for script in soup(["script", "style", "noscript"]):
                    script.decompose()
                
                result["content"] = soup.get_text(separator=" ", strip=True)[:10000]
                
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    if href.startswith("http"):
                        result["links"].append(href)
                    elif href.startswith("/"):
                        result["links"].append(urljoin(url, href))
                
                for img in soup.find_all("img", src=True):
                    result["images"].append(img["src"])
                
                result["success"] = True
        except requests.Timeout:
            result["error"] = "timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def calculate_content_score(self, content: Dict[str, Any]) -> Dict[str, Any]:
        text = f"{content.get('title', '')} {content.get('meta_description', '')} {content.get('content', '')}".lower()
        
        keyword_weights = {
            "slot": 15, "gacor": 20, "judol": 25, "judi": 20, "togel": 20,
            "casino": 15, "poker": 10, "deposit": 10, "withdraw": 10,
            "bonus": 8, "jackpot": 12, "rtp": 15, "maxwin": 18,
            "scatter": 12, "pragmatic": 15, "pg soft": 12, "habanero": 10,
            "slot88": 20, "gacor88": 22, "slot777": 20, "zeus": 10,
            "olympus": 8, "starlight": 8, "sweet bonanza": 15,
            "gates of": 10, "wild west": 8, "aztec": 6,
            "daftar": 8, "login": 5, "link alternatif": 18,
            "rtp live": 20, "bocoran": 15, "pola": 10
        }
        
        score = 0
        detected_keywords = []
        
        for keyword, weight in keyword_weights.items():
            count = text.count(keyword)
            if count > 0:
                score += min(weight * count, weight * 3)
                detected_keywords.append({"keyword": keyword, "count": count, "weight": weight})
        
        gambling_patterns = [
            r"slot\s*\d+", r"gacor\s*\d+", r"rtp\s*\d+%",
            r"bonus\s*\d+%", r"deposit\s*(pulsa|dana|ovo|gopay)",
            r"withdraw\s*\d+", r"jackpot\s*\d+"
        ]
        
        for pattern in gambling_patterns:
            if re.search(pattern, text):
                score += 10
                detected_keywords.append({"keyword": f"pattern:{pattern}", "count": 1, "weight": 10})
        
        score = min(score, 100)
        
        return {
            "score": score,
            "detected_keywords": detected_keywords,
            "keyword_count": len(detected_keywords)
        }
    
    async def verify_with_ai(self, url: str, content: Dict[str, Any], manual_score: int) -> Dict[str, Any]:
        if not self.ai_available:
            return {
                "ai_score": manual_score,
                "ai_category": self.categorize_score(manual_score, False),
                "ai_confidence": 50,
                "ai_reasoning": "AI verification not available"
            }
        
        try:
            prompt = f"""Analyze this website for online gambling content:
URL: {url}
Title: {content.get('title', 'N/A')}
Description: {content.get('meta_description', 'N/A')}
Content Preview: {content.get('content', '')[:2000]}

Rate from 0-100 how likely this is an online gambling site.
Respond in this exact format:
SCORE: [number]
CATEGORY: [direct_gambling/deface/suspected/clean]
CONFIDENCE: [number 0-100]
REASONING: [one line explanation]"""

            text = self._call_openrouter_ai(prompt)
            
            if not text:
                return {
                    "ai_score": manual_score,
                    "ai_category": "unknown",
                    "ai_confidence": 30,
                    "ai_reasoning": "AI response empty"
                }
            
            score_match = re.search(r"SCORE:\s*(\d+)", text)
            category_match = re.search(r"CATEGORY:\s*(\w+)", text)
            confidence_match = re.search(r"CONFIDENCE:\s*(\d+)", text)
            reasoning_match = re.search(r"REASONING:\s*(.+)", text)
            
            return {
                "ai_score": int(score_match.group(1)) if score_match else manual_score,
                "ai_category": category_match.group(1) if category_match else "unknown",
                "ai_confidence": int(confidence_match.group(1)) if confidence_match else 50,
                "ai_reasoning": reasoning_match.group(1) if reasoning_match else "No reasoning provided"
            }
        except Exception:
            return {
                "ai_score": manual_score,
                "ai_category": "unknown",
                "ai_confidence": 30,
                "ai_reasoning": "AI verification failed"
            }
    
    def categorize_score(self, score: int, is_trusted: bool) -> str:
        if is_trusted and score >= SCORE_THRESHOLDS["suspected"]:
            return "deface_forward"
        elif score >= SCORE_THRESHOLDS["direct_judol"]:
            return "direct_judol"
        elif score >= SCORE_THRESHOLDS["suspected"]:
            return "suspected"
        else:
            return "false_positive"
    
    def combine_scores(self, manual_score: int, ai_result: Dict[str, Any]) -> Dict[str, Any]:
        ai_score = ai_result.get("ai_score", manual_score)
        
        if abs(manual_score - ai_score) <= 20:
            final_score = (manual_score + ai_score) // 2
            agreement = "agreed"
        else:
            final_score = max(manual_score, ai_score)
            agreement = "disagreed"
        
        return {
            "manual_score": manual_score,
            "ai_score": ai_score,
            "final_score": final_score,
            "agreement": agreement
        }
    
    async def scan_url(self, url: str) -> Dict[str, Any]:
        domain_info = self.extract_domain_info(url)
        is_trusted = self.is_trusted_domain(domain_info)
        
        content = self.fetch_page_content(url)
        
        if not content["success"]:
            return {
                "url": url,
                "domain": domain_info.get("domain"),
                "status": "failed",
                "error": content.get("error"),
                "category": "scan_failed",
                "score": 0
            }
        
        score_result = self.calculate_content_score(content)
        manual_score = score_result["score"]
        
        ai_result = await self.verify_with_ai(url, content, manual_score)
        combined = self.combine_scores(manual_score, ai_result)
        
        category = self.categorize_score(combined["final_score"], is_trusted)
        
        return {
            "url": url,
            "final_url": content.get("final_url", url),
            "domain": domain_info.get("domain"),
            "full_domain": domain_info.get("full_domain"),
            "is_trusted_tld": is_trusted,
            "title": content.get("title"),
            "content_preview": content.get("content", "")[:500],
            "category": category,
            "score": manual_score,
            "ai_score": ai_result.get("ai_score"),
            "final_score": combined["final_score"],
            "agreement": combined["agreement"],
            "ai_reasoning": ai_result.get("ai_reasoning"),
            "detected_keywords": score_result["detected_keywords"],
            "links_found": len(content.get("links", [])),
            "scanned_at": datetime.now().isoformat()
        }
    
    async def run_full_scan(self, keywords: List[str] = None, callback=None) -> Dict[str, Any]:
        scan_id = self.generate_scan_id()
        
        if keywords:
            search_keywords = await self.expand_keywords_with_ai(keywords)
        else:
            search_keywords = await self.expand_keywords_with_ai(self.keywords[:10])
        
        if self.db:
            self.db.create_scan(scan_id, search_keywords)
        
        all_urls = set()
        for keyword in search_keywords[:20]:
            urls = self.search_duckduckgo(keyword, MAX_PAGES_TO_SCAN)
            all_urls.update(urls)
            if callback:
                callback({"status": "searching", "keyword": keyword, "found": len(urls)})
        
        if self.db:
            self.db.update_scan_status(scan_id, "running", 0, len(all_urls))
        
        results = {
            "scan_id": scan_id,
            "started_at": datetime.now().isoformat(),
            "keywords_used": len(search_keywords),
            "urls_found": len(all_urls),
            "direct_judol": [],
            "deface_forward": [],
            "suspected": [],
            "false_positive": [],
            "scan_failed": [],
            "statistics": {}
        }
        
        scanned_count = 0
        for url in list(all_urls):
            try:
                scan_result = await self.scan_url(url)
                category = scan_result.get("category", "scan_failed")
                
                if category in results:
                    results[category].append(scan_result)
                
                if self.db:
                    self.db.add_scan_result(scan_id, scan_result)
                
                scanned_count += 1
                if self.db:
                    self.db.update_scan_status(scan_id, "running", scanned_count)
                
                if callback:
                    progress = (scanned_count / len(all_urls)) * 100
                    callback({
                        "status": "scanning",
                        "progress": progress,
                        "current_url": url,
                        "scanned": scanned_count,
                        "total": len(all_urls)
                    })
                
                await asyncio.sleep(0.5)
            except Exception:
                results["scan_failed"].append({"url": url, "error": "scan_exception"})
        
        results["completed_at"] = datetime.now().isoformat()
        results["statistics"] = {
            "total_scanned": scanned_count,
            "direct_judol_count": len(results["direct_judol"]),
            "deface_forward_count": len(results["deface_forward"]),
            "suspected_count": len(results["suspected"]),
            "false_positive_count": len(results["false_positive"]),
            "failed_count": len(results["scan_failed"])
        }
        
        if self.db:
            self.db.update_scan_status(scan_id, "completed", scanned_count)
        
        return results
    
    async def quick_scan_url(self, url: str) -> Dict[str, Any]:
        return await self.scan_url(url)
