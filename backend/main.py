"""Kavach - live guard against digital-arrest / fake-KYC scam calls.

Pipeline per audio chunk:
  Saaras (speech-to-text, auto language) -> Sarvam-105B (scam risk JSON) -> Bulbul (spoken warning)

Run from the project root:  python -m uvicorn backend.main:app --port 8000
"""
import asyncio
import base64
import hashlib
import time

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import API_KEY, DEMO_CACHE, FRONTEND, LANG_NAMES, RISK_THRESHOLD, TALKBACK_SPEAKER, TTS_LANGS, WARN_SPEAKER
from .demos import DEMOS
from .prompts import LESSON_PROMPT, TALKBACK
from .sarvam import analyze, chat, stt, tts

app = FastAPI(title="Kavach")


def _require_key():
    if not API_KEY:
        raise HTTPException(500, "SARVAM_API_KEY missing in .env")


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


@app.post("/api/listen")
async def listen(
    file: UploadFile = File(...),
    history: str = Form(""),
    warned: str = Form("false"),
    warn_lang: str = Form("auto"),
):
    """One audio chunk in -> transcript, risk analysis and (once) spoken warning + talk-back out."""
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
    text = (await chat(
        [
            {"role": "system", "content": LESSON_PROMPT.replace("{LANG}", LANG_NAMES[lang])},
            {"role": "user", "content": f"Red flags: {flags}\n\nTranscript:\n{history[-3000:]}"},
        ],
        max_tokens=400, temperature=0.3,
    )).strip()
    return {"text": text, "lang": lang, "audio": await tts(text[:1500], lang, WARN_SPEAKER)}


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
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND), name="static")
