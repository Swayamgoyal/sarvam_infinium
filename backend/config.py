"""Settings, model names, languages and paths."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
DEMO_CACHE = ROOT / "backend" / ".cache" / "demo_audio"
DEMO_CACHE.mkdir(parents=True, exist_ok=True)

load_dotenv(ROOT / ".env")

API_KEY = os.getenv("SARVAM_API_KEY", "")
BASE = "https://api.sarvam.ai"
HEADERS = {"api-subscription-key": API_KEY}

STT_MODEL = os.getenv("STT_MODEL", "saaras:v4")
LLM_MODEL = os.getenv("LLM_MODEL", "sarvam-105b-conversations")
TTS_MODEL = os.getenv("TTS_MODEL", "bulbul:v3")
WARN_SPEAKER = os.getenv("WARN_SPEAKER", "priya")
TALKBACK_SPEAKER = os.getenv("TALKBACK_SPEAKER", "kabir")

RISK_THRESHOLD = 70

TTS_LANGS = {"bn-IN", "en-IN", "gu-IN", "hi-IN", "kn-IN", "ml-IN", "mr-IN", "od-IN", "pa-IN", "ta-IN", "te-IN"}
LANG_NAMES = {
    "hi-IN": "Hindi", "ta-IN": "Tamil", "te-IN": "Telugu", "kn-IN": "Kannada", "ml-IN": "Malayalam",
    "mr-IN": "Marathi", "bn-IN": "Bengali", "gu-IN": "Gujarati", "pa-IN": "Punjabi", "od-IN": "Odia",
    "en-IN": "English",
}
