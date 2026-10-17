"""Kavach - live guard against digital-arrest / fake-KYC scam calls.

Pipeline per audio chunk:
  Saaras (speech-to-text, auto language) -> Sarvam-105B (scam risk JSON) -> Bulbul (spoken warning)
"""
import asyncio
import base64
import hashlib
import json
import os
import re
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

load_dotenv()

API_KEY = os.getenv("SARVAM_API_KEY", "")
BASE = "https://api.sarvam.ai"
STT_MODEL = os.getenv("STT_MODEL", "saaras:v4")
LLM_MODEL = os.getenv("LLM_MODEL", "sarvam-105b-conversations")
TTS_MODEL = os.getenv("TTS_MODEL", "bulbul:v3")
WARN_SPEAKER = os.getenv("WARN_SPEAKER", "priya")
RISK_THRESHOLD = 70

TTS_LANGS = {"bn-IN", "en-IN", "gu-IN", "hi-IN", "kn-IN", "ml-IN", "mr-IN", "od-IN", "pa-IN", "ta-IN", "te-IN"}
LANG_NAMES = {
    "hi-IN": "Hindi", "ta-IN": "Tamil", "te-IN": "Telugu", "kn-IN": "Kannada", "ml-IN": "Malayalam",
    "mr-IN": "Marathi", "bn-IN": "Bengali", "gu-IN": "Gujarati", "pa-IN": "Punjabi", "od-IN": "Odia",
    "en-IN": "English",
}

ROOT = Path(__file__).parent
STATIC = ROOT / "static"
DEMO_CACHE = STATIC / "demo_cache"
DEMO_CACHE.mkdir(parents=True, exist_ok=True)

HEADERS = {"api-subscription-key": API_KEY}

FLAGS = ["fake_authority", "secrecy", "urgency_threat", "money_transfer", "otp_kyc", "video_call_arrest", "remote_app"]

SYSTEM_PROMPT = f"""You are Kavach, a scam-call detector protecting elderly Indians.
You receive a live, possibly code-mixed transcript of a phone call (Hindi, Tamil, English, etc.).
Detect "digital arrest", fake KYC, bank, courier/parcel, lottery or tech-support scam patterns.

Red flags (use these exact keys):
- fake_authority: caller claims to be police, CBI, ED, customs, RBI, TRAI, court, bank official / customer care
- secrecy: tells victim not to tell family / anyone, "confidential", stay alone
- urgency_threat: arrest, FIR, case, account block, jail threats, extreme time pressure
- money_transfer: asks to transfer money, "safe account", fine, verification payment, UPI
- otp_kyc: asks for OTP, PIN, Aadhaar, PAN, card details, KYC update
- video_call_arrest: asks to stay on video call / Skype, "digital arrest"
- remote_app: asks to install AnyDesk, TeamViewer, an APK or screen share

Score risk 0-100 for the WHOLE conversation so far. Normal family / friend / business talk = low (0-15),
even if it mentions money, medicines or the bank casually. One weak flag = 20-45.
Authority + threat = 50-75. Any money/OTP demand together with authority, threat or secrecy = 85-100.

Reply ONLY with JSON:
{{"risk": <int>,
 "flags": [<keys from {FLAGS}>],
 "evidence": [{{"flag": "<key>", "quote": "<exact short phrase from the transcript, max 8 words>"}}],
 "scam_type": "<2-4 words English, or 'None'>",
 "reason": "<one short English sentence for the dashboard>",
 "warning": "<if risk >= {RISK_THRESHOLD}: 1-2 short sentences spoken TO the elderly listener in {{LANG}}, in that language's native script, respectful, telling them to hang up now, never share OTP or send money, real police never arrest on a video call. Else empty string>",
 "family_alert": "<if risk >= {RISK_THRESHOLD}: one English SMS sentence to the elder's family describing the scam and what the caller demanded. Else empty string>",
 "english": "<faithful English translation of ONLY the LATEST LINE>"}}"""

# Spoken TO the scammer once a scam is detected, in the caller's own language.
TALKBACK = {
    "hi-IN": "सावधान! यह कॉल कवच द्वारा रिकॉर्ड की जा रही है और साइबर क्राइम हेल्पलाइन 1930 पर रिपोर्ट कर दी गई है।",
    "ta-IN": "எச்சரிக்கை! இந்த அழைப்பு கவச் மூலம் பதிவு செய்யப்படுகிறது, சைபர் கிரைம் உதவி எண் 1930-க்கு புகார் அளிக்கப்பட்டுள்ளது.",
    "en-IN": "Warning! This call is being recorded by Kavach and has been reported to the cyber crime helpline 1930.",
}
TALKBACK_SPEAKER = os.getenv("TALKBACK_SPEAKER", "kabir")

LESSON_PROMPT = """You are Kavach, a caring scam-safety teacher for elderly Indians.
Given a phone-call transcript and the red flags detected, explain to the elder in {LANG} (native script),
in 3-4 short, simple, warm sentences: which tricks the caller used, in the order they used them,
and the one rule to remember next time. No markdown, no lists. Reply with only the spoken text."""

app = FastAPI(title="Kavach")


def _require_key():
    if not API_KEY:
        raise HTTPException(500, "SARVAM_API_KEY missing in .env")


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


# One shared client keeps connections warm (lower latency); retries ride out venue Wi-Fi blips.
CLIENT = httpx.AsyncClient(timeout=60, transport=httpx.AsyncHTTPTransport(retries=3))


async def _post(url: str, **kw) -> httpx.Response:
    last = None
    for attempt in range(3):
        try:
            return await CLIENT.post(url, **kw)
        except httpx.TransportError as e:
            last = e
            await asyncio.sleep(0.6 * (attempt + 1))
    raise HTTPException(503, f"Network problem reaching Sarvam: {last}")


async def stt(audio: bytes, filename: str, content_type: str) -> dict:
    ct = (content_type or "audio/wav").split(";")[0].strip()
    r = await _post(
        f"{BASE}/speech-to-text",
        headers=HEADERS,
        files={"file": (filename, audio, ct)},
        data={"model": STT_MODEL, "language_code": "unknown"},
    )
    if r.status_code != 200:
        raise HTTPException(502, f"STT error {r.status_code}: {r.text[:300]}")
    return r.json()


async def analyze(conversation: str, latest: str, warn_lang: str) -> dict:
    body = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT.replace("{LANG}", LANG_NAMES.get(warn_lang, "Hindi"))},
            {"role": "user", "content": f"Call transcript so far:\n{conversation[-3000:]}\n\nLATEST LINE:\n{latest}"},
        ],
        "temperature": 0.1,
        "max_tokens": 500,
        "response_format": {"type": "json_object"},
        "reasoning_effort": None,
    }
    headers = {**HEADERS, "Authorization": f"Bearer {API_KEY}"}
    r = await _post(f"{BASE}/v1/chat/completions", headers=headers, json=body)
    if r.status_code != 200:
        raise HTTPException(502, f"LLM error {r.status_code}: {r.text[:300]}")
    content = r.json()["choices"][0]["message"].get("content") or "{}"
    m = re.search(r"\{.*\}", content, re.S)
    try:
        data = json.loads(m.group(0) if m else content)
    except json.JSONDecodeError:
        data = {}
    evidence = [
        {"flag": e.get("flag"), "quote": str(e.get("quote", ""))[:120]}
        for e in data.get("evidence", []) or []
        if isinstance(e, dict) and e.get("flag") in FLAGS
    ]
    return {
        "risk": max(0, min(100, int(data.get("risk", 0) or 0))),
        "flags": [f for f in data.get("flags", []) or [] if f in FLAGS],
        "evidence": evidence,
        "scam_type": data.get("scam_type", "None"),
        "reason": data.get("reason", ""),
        "warning": data.get("warning", ""),
        "family_alert": data.get("family_alert", ""),
        "english": data.get("english", ""),
    }


async def tts(text: str, lang: str, speaker: str) -> str:
    body = {
        "text": text,
        "language_code": lang if lang in TTS_LANGS else "hi-IN",
        "model": TTS_MODEL,
        "speaker": speaker,
    }
    r = await _post(f"{BASE}/text-to-speech", headers=HEADERS, json=body)
    if r.status_code != 200:
        raise HTTPException(502, f"TTS error {r.status_code}: {r.text[:300]}")
    return r.json()["audios"][0]


@app.post("/api/listen")
async def listen(
    file: UploadFile = File(...),
    history: str = Form(""),
    warned: str = Form("false"),
    warn_lang: str = Form("auto"),
):
    """One audio chunk in -> transcript, risk analysis and (once) a spoken warning out."""
    _require_key()
    audio = await file.read()
    if len(audio) < 2000:
        return {"transcript": "", "skipped": True}

    timings = {}
    t0 = time.perf_counter()
    s = await stt(audio, file.filename or "chunk.wav", file.content_type)
    timings["stt"] = _ms(t0)
    text = (s.get("transcript") or "").strip()
    lang = s.get("language_code") or "hi-IN"
    if not text:
        return {"transcript": "", "language_code": lang, "skipped": True}

    target = lang if warn_lang == "auto" else warn_lang
    if target not in TTS_LANGS:
        target = "hi-IN"

    t0 = time.perf_counter()
    result = await analyze((history + "\n" + text).strip(), text, target)
    timings["llm"] = _ms(t0)

    audio_b64 = talkback_b64 = None
    if result["risk"] >= RISK_THRESHOLD and warned != "true" and result["warning"]:
        t0 = time.perf_counter()
        tb_lang = lang if lang in TALKBACK else "en-IN"
        audio_b64, talkback_b64 = await asyncio.gather(
            tts(result["warning"], target, WARN_SPEAKER),
            tts(TALKBACK[tb_lang], tb_lang, TALKBACK_SPEAKER),
        )
        timings["tts"] = _ms(t0)

    return {
        "transcript": text, "language_code": lang, "warn_lang": target, **result,
        "warning_audio": audio_b64, "talkback_audio": talkback_b64, "timings": timings,
    }


@app.post("/api/lesson")
async def lesson(history: str = Form(...), flags: str = Form(""), lang: str = Form("hi-IN")):
    """After the call: Bulbul explains to the elder, in their language, which tricks were used."""
    _require_key()
    lang = lang if lang in TTS_LANGS else "hi-IN"
    body = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": LESSON_PROMPT.replace("{LANG}", LANG_NAMES[lang])},
            {"role": "user", "content": f"Red flags: {flags}\n\nTranscript:\n{history[-3000:]}"},
        ],
        "temperature": 0.3,
        "max_tokens": 400,
        "reasoning_effort": None,
    }
    headers = {**HEADERS, "Authorization": f"Bearer {API_KEY}"}
    r = await _post(f"{BASE}/v1/chat/completions", headers=headers, json=body)
    if r.status_code != 200:
        raise HTTPException(502, f"LLM error {r.status_code}: {r.text[:300]}")
    text = (r.json()["choices"][0]["message"].get("content") or "").strip()
    return {"text": text, "lang": lang, "audio": await tts(text[:1500], lang, WARN_SPEAKER)}


# Scenario scripts voiced by Bulbul so the stage demo works even without a live mic.
DEMOS = {
    "hindi_arrest": {
        "title": "Hindi · Digital arrest",
        "caller": "+91 87xx xx4821 · Unknown",
        "lang": "hi-IN", "speaker": "rahul",
        "lines": [
            "नमस्ते, मैं मुंबई साइबर क्राइम ब्रांच से इंस्पेक्टर राजेश शर्मा बोल रहा हूँ।",
            "आपके आधार कार्ड से एक पार्सल बुक हुआ है जिसमें ड्रग्स मिले हैं, आपके नाम पर FIR दर्ज हो गई है।",
            "यह मामला बहुत गंभीर है, आप अपने परिवार को भी कुछ नहीं बताएंगे, वरना आज ही गिरफ्तारी होगी।",
            "अभी वीडियो कॉल पर बने रहिए, आप डिजिटल अरेस्ट में हैं।",
            "जांच के लिए अपने खाते के सारे पैसे RBI के सुरक्षित खाते में ट्रांसफर कीजिए, और जो OTP आया है वो बताइए।",
        ],
    },
    "tamil_kyc": {
        "title": "Tamil (code-mixed) · KYC fraud",
        "caller": "+91 90xx xx1177 · Unknown",
        "lang": "ta-IN", "speaker": "aditya",
        "lines": [
            "வணக்கம், நான் State Bank of India customer care-ல இருந்து பேசுறேன்.",
            "உங்க KYC update ஆகலை, இன்னைக்கு ராத்திரிக்குள்ள உங்க account block ஆயிடும்.",
            "இத யார்கிட்டயும் சொல்லாதீங்க, இது ஒரு confidential process.",
            "உங்க phone-க்கு ஒரு OTP வந்திருக்கும், அத உடனே சொல்லுங்க, இல்லனா உங்க பணம் எல்லாம் போயிடும்.",
        ],
    },
    "safe_son": {
        "title": "Hindi · Safe call from son",
        "caller": "Rahul (Son) ❤️",
        "lang": "hi-IN", "speaker": "rohan",
        "lines": [
            "हेलो माँ, मैं राहुल बोल रहा हूँ, कैसी हो आप?",
            "मैं इस रविवार घर आ रहा हूँ, आपकी दवाइयाँ भी लेता आऊँगा।",
            "और हाँ, खाना टाइम पे खा लेना, पापा को मेरा नमस्ते बोलना।",
        ],
    },
}


@app.get("/api/demos")
async def demos():
    return {k: {"title": v["title"], "caller": v["caller"], "lines": v["lines"]} for k, v in DEMOS.items()}


@app.get("/api/demo/{name}/{i}")
async def demo_audio(name: str, i: int):
    """Scenario line voiced by Bulbul, cached on disk so each line costs credits only once."""
    d = DEMOS.get(name)
    if not d or not 0 <= i < len(d["lines"]):
        raise HTTPException(404)
    text = d["lines"][i]
    key = hashlib.md5(f"{d['speaker']}|{d['lang']}|{text}".encode()).hexdigest()[:10]
    path = DEMO_CACHE / f"{name}_{i}_{key}.wav"
    if not path.exists():
        _require_key()
        path.write_bytes(base64.b64decode(await tts(text, d["lang"], d["speaker"])))
    return FileResponse(path, media_type="audio/wav")


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
