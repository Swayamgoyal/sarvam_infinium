"""Thin async client for the three Sarvam APIs: Saaras (STT), Sarvam-105B (chat), Bulbul (TTS)."""
import asyncio
import json
import re

import httpx
from fastapi import HTTPException

from .config import API_KEY, BASE, HEADERS, LANG_NAMES, LLM_MODEL, STT_MODEL, TTS_LANGS, TTS_MODEL
from .prompts import FLAGS, SYSTEM_PROMPT

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
    """Saaras v4 speech-to-text with automatic language detection."""
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


async def chat(messages: list, max_tokens: int = 500, temperature: float = 0.1, json_mode: bool = False) -> str:
    """Sarvam-105B chat completion; returns the message content."""
    body = {
        "model": LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "reasoning_effort": None,
    }
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    headers = {**HEADERS, "Authorization": f"Bearer {API_KEY}"}
    r = await _post(f"{BASE}/v1/chat/completions", headers=headers, json=body)
    if r.status_code != 200:
        raise HTTPException(502, f"LLM error {r.status_code}: {r.text[:300]}")
    return r.json()["choices"][0]["message"].get("content") or ""


async def analyze(conversation: str, latest: str, warn_lang: str) -> dict:
    """Score the whole call so far for scam risk and return a cleaned JSON verdict."""
    content = await chat(
        [
            {"role": "system", "content": SYSTEM_PROMPT.replace("{LANG}", LANG_NAMES.get(warn_lang, "Hindi"))},
            {"role": "user", "content": f"Call transcript so far:\n{conversation[-3000:]}\n\nLATEST LINE:\n{latest}"},
        ],
        json_mode=True,
    )
    m = re.search(r"\{.*\}", content, re.S)
    try:
        data = json.loads(m.group(0) if m else content or "{}")
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
    """Bulbul v3 text-to-speech; returns base64 WAV."""
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
