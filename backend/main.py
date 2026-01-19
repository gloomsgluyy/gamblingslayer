import os
import sys
import uuid
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from jose import jwt, JWTError
from passlib.context import CryptContext

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from database import db

from modules.gese import GESEEngine
from modules.sir import SIREngine
from modules.dtsm import DTSMEngine
from modules.drm import DRMEngine
from modules.cme import CMEEngine
from modules.dabe import DABEEngine
from modules.iwld import IWLDEngine
from modules.sacr import SACREngine
from modules.nere import NEREEngine

app = FastAPI(
    title="Gambling Slayer API",
    description="OSINT-based platform for detecting and analyzing online gambling websites",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

gese = GESEEngine(db)
sir = SIREngine(db)
dtsm = DTSMEngine(db)
drm = DRMEngine(db)
cme = CMEEngine(db)
dabe = DABEEngine(db)
iwld = IWLDEngine(db)
sacr = SACREngine(db)
nere = NEREEngine(db)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

active_scans = {}

class URLInput(BaseModel):
    url: str

class URLListInput(BaseModel):
    urls: List[str]

class ScanInput(BaseModel):
    keywords: Optional[List[str]] = None

class ReportInput(BaseModel):
    url: str
    description: Optional[str] = None
    reporter_type: Optional[str] = "anonymous"

class LoginInput(BaseModel):
    username: str
    password: str

class RegisterInput(BaseModel):
    username: str
    password: str
    role: Optional[str] = "user"

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return None
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            return None
        return {"username": username, "role": payload.get("role", "user")}
    except JWTError:
        return None

def require_auth(user = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user

def require_admin(user = Depends(get_current_user)):
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

@app.get("/")
async def root():
    return {
        "name": "Gambling Slayer API",
        "version": "1.0.0",
        "status": "operational",
        "modules": ["GESE", "SIR", "DTSM", "DRM", "CME", "DABE", "IWLD", "SACR", "NERE"]
    }

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/api/statistics")
async def get_statistics():
    return db.get_statistics()

@app.post("/api/auth/register")
async def register(data: RegisterInput):
    conn = db.get_connection() if hasattr(db, 'get_connection') else None
    if conn:
        from database import get_connection
        conn = get_connection()
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (data.username,)).fetchone()
        if existing:
            conn.close()
            raise HTTPException(status_code=400, detail="Username already exists")
        
        password_hash = pwd_context.hash(data.password)
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (data.username, password_hash, data.role)
        )
        conn.commit()
        conn.close()
    
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
async def login(data: LoginInput):
    from database import get_connection
    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", 
        (data.username,)
    ).fetchone()
    conn.close()
    
    if not user or not pwd_context.verify(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/api/scan/quick")
async def quick_scan(data: URLInput):
    result = await gese.quick_scan_url(data.url)
    return result

@app.post("/api/scan/full")
async def start_full_scan(data: ScanInput, background_tasks: BackgroundTasks):
    scan_id = gese.generate_scan_id()
    
    active_scans[scan_id] = {
        "status": "queued",
        "progress": 0,
        "started_at": datetime.now().isoformat()
    }
    
    async def run_scan():
        def progress_callback(info):
            active_scans[scan_id]["status"] = info.get("status", "running")
            active_scans[scan_id]["progress"] = info.get("progress", 0)
        
        try:
            result = await gese.run_full_scan(data.keywords, progress_callback)
            active_scans[scan_id]["status"] = "completed"
            active_scans[scan_id]["result"] = result
        except Exception as e:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = str(e)
    
    background_tasks.add_task(lambda: asyncio.run(run_scan()))
    
    return {"scan_id": scan_id, "status": "queued"}

@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    if scan_id in active_scans:
        return active_scans[scan_id]
    
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan

@app.get("/api/scan/{scan_id}/results")
async def get_scan_results(scan_id: str, category: Optional[str] = None):
    results = db.get_scan_results(scan_id, category)
    return {"scan_id": scan_id, "results": results, "count": len(results)}

@app.post("/api/report")
async def submit_report(data: ReportInput):
    report_id = f"report_{uuid.uuid4().hex[:12]}"
    success = db.create_report(report_id, data.url, data.description, data.reporter_type)
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to create report")
    
    return {"report_id": report_id, "status": "pending"}

@app.get("/api/reports")
async def get_reports(status: Optional[str] = None, limit: int = Query(default=100, le=500)):
    reports = db.get_reports(status, limit)
    return {"reports": reports, "count": len(reports)}

@app.put("/api/report/{report_id}/status")
async def update_report_status(report_id: str, status: str, user = Depends(require_auth)):
    db.update_report_status(report_id, status)
    return {"report_id": report_id, "status": status}

@app.post("/api/analyze/infrastructure")
async def analyze_infrastructure(data: URLInput):
    result = sir.analyze_infrastructure(data.url)
    return result

@app.post("/api/analyze/dns")
async def analyze_dns(data: URLInput):
    result = dtsm.full_dns_analysis(data.url)
    return result

@app.post("/api/analyze/rotation")
async def analyze_rotation(data: URLInput):
    result = drm.build_rotation_map(data.url)
    return result

@app.post("/api/analyze/rotation/batch")
async def analyze_rotation_batch(data: URLListInput):
    result = drm.track_domain_rotation(data.urls)
    return result

@app.post("/api/analyze/mobility")
async def analyze_mobility(data: URLInput):
    result = cme.detect_mobility(data.url)
    return result

@app.post("/api/analyze/mobility/batch")
async def analyze_mobility_batch(data: URLListInput):
    result = cme.track_multiple_domains(data.urls)
    return result

@app.post("/api/analyze/behavior")
async def analyze_behavior(data: URLInput):
    result = dabe.extract_behavior_patterns(data.url)
    return result

@app.post("/api/analyze/behavior/report")
async def get_behavior_report(data: URLInput):
    result = dabe.generate_behavior_report(data.url)
    return result

@app.post("/api/analyze/weaklinks")
async def analyze_weak_links(data: URLInput):
    result = iwld.analyze_weak_links(data.url)
    return result

@app.post("/api/analyze/weaklinks/batch")
async def analyze_weak_links_batch(data: URLListInput):
    result = iwld.compare_weak_links(data.urls)
    return result

@app.post("/api/analyze/blocklist")
async def get_priority_blocklist(data: URLListInput):
    result = iwld.get_priority_blocking_list(data.urls)
    return result

@app.post("/api/analyze/attackchain")
async def build_attack_chain(data: URLInput):
    result = sacr.build_attack_chain(data.url)
    return result

@app.post("/api/analyze/attackchain/network")
async def build_network_attack_chain(data: URLListInput):
    result = sacr.reconstruct_multi_domain_chain(data.urls)
    return result

@app.post("/api/evidence/report")
async def generate_evidence_report(data: URLInput):
    result = nere.generate_evidence_report(data.url)
    return result

@app.post("/api/evidence/network")
async def generate_network_report(data: URLListInput):
    result = nere.generate_network_report(data.urls)
    return result

@app.get("/api/domain/{domain}")
async def get_domain_info(domain: str):
    info = db.get_domain_info(domain)
    if not info:
        raise HTTPException(status_code=404, detail="Domain not found")
    return info

@app.get("/api/domain/{domain}/dns")
async def get_domain_dns_history(domain: str):
    history = db.get_dns_history(domain)
    return {"domain": domain, "dns_history": history}

@app.get("/api/domain/{domain}/relations")
async def get_domain_relations(domain: str):
    relations = db.get_domain_relations(domain)
    return {"domain": domain, "relations": relations}

@app.get("/api/domain/{domain}/changes")
async def get_domain_changes(domain: str):
    changes = db.get_infrastructure_changes(domain)
    return {"domain": domain, "changes": changes}

@app.get("/api/domain/{domain}/behavior")
async def get_domain_behavior(domain: str):
    logs = db.get_behavior_logs(domain)
    return {"domain": domain, "behavior_logs": logs}

@app.get("/api/domain/{domain}/weaklinks")
async def get_domain_weak_links(domain: str):
    weak_links = db.get_weak_links(domain)
    return {"domain": domain, "weak_links": weak_links}

@app.post("/api/comprehensive")
async def comprehensive_analysis(data: URLInput, background_tasks: BackgroundTasks):
    analysis_id = f"analysis_{uuid.uuid4().hex[:12]}"
    
    active_scans[analysis_id] = {
        "status": "running",
        "progress": 0,
        "started_at": datetime.now().isoformat()
    }
    
    async def run_analysis():
        try:
            results = {}
            
            active_scans[analysis_id]["progress"] = 10
            results["quick_scan"] = await gese.quick_scan_url(data.url)
            
            active_scans[analysis_id]["progress"] = 25
            results["infrastructure"] = sir.analyze_infrastructure(data.url)
            
            active_scans[analysis_id]["progress"] = 40
            results["dns_analysis"] = dtsm.full_dns_analysis(data.url)
            
            active_scans[analysis_id]["progress"] = 55
            results["rotation_map"] = drm.build_rotation_map(data.url)
            
            active_scans[analysis_id]["progress"] = 70
            results["behavior"] = dabe.extract_behavior_patterns(data.url)
            
            active_scans[analysis_id]["progress"] = 85
            results["weak_links"] = iwld.analyze_weak_links(data.url)
            
            active_scans[analysis_id]["progress"] = 95
            results["evidence_report"] = nere.generate_evidence_report(data.url)
            
            active_scans[analysis_id]["status"] = "completed"
            active_scans[analysis_id]["progress"] = 100
            active_scans[analysis_id]["result"] = results
            
        except Exception as e:
            active_scans[analysis_id]["status"] = "failed"
            active_scans[analysis_id]["error"] = str(e)
    
    background_tasks.add_task(lambda: asyncio.run(run_analysis()))
    
    return {"analysis_id": analysis_id, "status": "running"}

@app.get("/api/analysis/{analysis_id}")
async def get_analysis_status(analysis_id: str):
    if analysis_id not in active_scans:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return active_scans[analysis_id]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
