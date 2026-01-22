import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
DB_PATH = DATA_DIR / "gambling_slayer.db"

DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

OPENROUTER_API_KEY = os.getenv
OPENROUTER_MODEL = "xiaomi/mimo-v2-flash:free"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

DNS_RESOLVERS = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "208.67.222.222"
]

GAMBLING_KEYWORDS = [
    "slot", "gacor", "judol", "judi", "togel", "casino", "poker",
    "deposit", "withdraw", "bonus", "jackpot", "rtp", "maxwin",
    "scatter", "pragmatic", "pg soft", "habanero", "slot88",
    "gacor88", "slot777", "zeus", "olympus", "starlight"
]

TRUSTED_DOMAINS = ["edu", "gov", "go.id", "ac.id", "or.id", "mil.id"]

SCORE_THRESHOLDS = {
    "direct_judol": 80,
    "suspected": 50,
    "false_positive": 50
}

SCAN_TIMEOUT = 30
MAX_PAGES_TO_SCAN = 5
MAX_URLS_PER_KEYWORD = 50

SELENIUM_OPTIONS = {
    "headless": True,
    "disable_gpu": True,
    "no_sandbox": True,
    "disable_dev_shm": True
}

SECRET_KEY = os.getenv("SECRET_KEY", "gambling-slayer-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
