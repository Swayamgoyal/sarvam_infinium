# Kavach (कवच): a real-time shield against scam calls for elders

Kavach listens to a phone call on speaker and detects **"digital arrest"**, **fake-KYC** and **bank-impersonation** scams as they happen. Before any money or OTP changes hands, it interrupts the call with a loud spoken warning **in the elder's own language**.

It runs entirely on Sarvam AI models: **Saaras v4** (speech-to-text), **Sarvam-105B** (reasoning and scam detection) and **Bulbul v3** (text-to-speech). It works on Hindi, Tamil and code-mixed speech out of the box.

Built at the Sarvam build-along (open-ended projects on Sarvam APIs, about 45 minutes to ship a prototype).

---

## The problem

"Digital arrest" scams are among the fastest-growing frauds in India. The scammer usually follows the same script:

1. **Hook:** an unknown number calls.
2. **Authority:** the caller claims to be CBI, police, cyber cell, RBI, customs or bank customer care.
3. **Fear:** "A parcel in your name has drugs", "an FIR has been filed", "your account will be blocked tonight".
4. **Isolation:** "Don't tell your family", "stay on video call, you are under digital arrest".
5. **Extraction:** "Transfer your money to the RBI safe account" or "tell me the OTP".

The victims are often elderly. The calls happen in their regional language and the pressure is intense. Most victims realise it was a scam only **after** the money is gone. Kavach is built to break the script at step 3 or 4, before step 5.

---

## How it works

```
 Call on speaker
       │  mic audio (browser)
       ▼
 16 kHz mono WAV chunk every 5 s   (silent chunks skipped, so no credits used)
       │
       ▼
 ┌──────────────────────┐   transcript + detected language (hi-IN, ta-IN, …)
 │ Saaras v4  (STT)     │──────────────────────────────────────────┐
 └──────────────────────┘                                          │
                                                                   ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ Sarvam-105B (sarvam-105b-conversations), reading the WHOLE call so far │
 │ → risk 0-100, red flags, evidence quotes, scam type, reason,           │
 │   warning text in the elder's language, family SMS draft  (JSON mode)  │
 └────────────────────────────────────────────────────────────────────────┘
       │ risk ≥ 70 (first time only)
       ▼
 ┌──────────────────────┐
 │ Bulbul v3  (TTS)     │ → loud spoken warning + alarm + full-screen alert
 └──────────────────────┘
```

### Which model does what

| Step | Sarvam model | Role |
|---|---|---|
| Hear | **Saaras v4** (`/speech-to-text`, `language_code=unknown`) | Transcribes each chunk and auto-detects the language. Handles code-mixed speech such as "KYC update ஆகலை, account block ஆயிடும்". |
| **Detect the scam** | **Sarvam-105B** (`sarvam-105b-conversations`, `/v1/chat/completions`, JSON mode) | Reads the full running transcript and reasons about the scam pattern in context. It does **not** use a keyword list, which is why a son talking about "medicines" and "home" scores 5/100. |
| Speak | **Bulbul v3** (`/text-to-speech`) | Speaks the warning in the chosen language. Also voices the demo scammer scripts. |

### Red flags the LLM looks for

| Key | Meaning |
|---|---|
| `fake_authority` | Claims to be police, CBI, ED, RBI, TRAI, court, bank or customer care |
| `urgency_threat` | Arrest, FIR, case or account-block threats, extreme time pressure |
| `secrecy` | "Don't tell your family", "confidential process" |
| `video_call_arrest` | "Stay on video call", "digital arrest" |
| `money_transfer` | Transfer to a "safe account", fine, verification payment, UPI |
| `otp_kyc` | Asks for OTP, PIN, Aadhaar, PAN, card details or a KYC update |
| `remote_app` | Asks to install AnyDesk, TeamViewer, an APK or to share the screen |

Risk calibration (from the system prompt): normal family or business talk scores 0–15. One weak flag scores 20–45. Authority plus a threat scores 50–75. A money or OTP demand combined with authority, threat or secrecy scores 85–100. **The alert fires at 70.**

---

## Features

- **Live mic mode:** put any call on speaker next to the laptop. Audio is captured in the browser, converted to 16 kHz WAV and analysed every 5 seconds.
- **Explainable red flags:** every detected flag shows the **exact phrase** the caller used, in the original script.
- **Scam-stage ladder:** Hook → Authority → Fear → Isolation → Extraction lights up as the call moves along.
- **Risk-over-time chart:** a sparkline of the risk score across the call, with the alert line at 70.
- **Warning in the elder's language:** auto mode uses the caller's language, or you can pick any of 11 languages (Hindi, Tamil, Telugu, Kannada, Malayalam, Bengali, Marathi, Gujarati, Punjabi, Odia, English). A Hindi-speaking scammer can be countered with a Tamil warning.
- **Full-screen alert:** a flashing red screen, an alarm tone and then the spoken Bulbul warning, with a replay button.
- **Family alert:** an SMS draft for the family describing the scam and what was demanded, with a copy button.
- **Detect → Warn → Act:** the alert screen has a one-tap **📞 Call 1930** button (India's National Cyber Crime Helpline) and an **📄 Evidence report** download. The report includes the caller, call duration, verdict and peak risk, scam pattern, each red flag with the scammer's exact words, a timestamped transcript with per-line risk, the warning Kavach issued, and next steps (1930, cybercrime.gov.in, Sanchar Saathi / Chakshu). It is ready to attach to a cybercrime complaint.
- **English subtitles:** every Hindi/Tamil line is shown with its English translation, produced in the same Sarvam-105B call at no extra cost, so non-speakers can follow the call.
- **Kavach talks back to the scammer:** right after warning the elder, a second Bulbul voice (`kabir`) tells the caller, in the caller's own language, that the call is recorded by Kavach and reported to the 1930 cyber helpline.
- **Check a voice note:** upload a WhatsApp voice note or any recording (ogg, opus, mp3, m4a, wav). The browser decodes it, splits it into 20-second 16 kHz WAV pieces and runs it through the same pipeline.
- **After-call lesson for the elder:** `/api/lesson` has Sarvam-105B explain, in 3–4 warm sentences in the elder's language, which tricks were used and in what order, and the one rule to remember. Bulbul speaks it aloud.
- **Per-step latency:** each transcript line shows the STT, LLM and TTS time in ms.
- **Three built-in demo scenarios,** voiced by Bulbul and run through the **same** STT → LLM pipeline:
  - Hindi digital arrest (fake Mumbai cyber-crime inspector → drugs parcel → "don't tell family" → video-call arrest → RBI safe account + OTP)
  - Tamil code-mixed KYC fraud (fake SBI customer care → account block tonight → "confidential" → OTP)
  - Safe call from a son (a control case to show there are no false alarms)
- **Credit and stage safety:** silent chunks are skipped, the warning is generated once per call, demo audio is cached on disk after the first play, and the mic is muted while the warning plays so Kavach never transcribes itself.
- **Venue Wi-Fi resilience:** one shared HTTP client keeps connections warm and retries automatically on DNS or network blips.

---

## Test results (real Sarvam API calls)

| Scenario | Outcome |
|---|---|
| Hindi digital arrest, final line | Risk **95**, flags `fake_authority`, `money_transfer`, `otp_kyc`, Hindi warning spoken |
| Tamil KYC fraud | Risk **35** on line 1 (only "SBI customer care"), then **85** on line 2 ("account block tonight"), with a Tamil warning and family SMS |
| Safe call from son | Risk **5** on every line, no flags, no alert |

Typical latency per 5-second chunk once connections are warm: STT about 0.6–1.0 s, LLM about 0.3–0.4 s.

---

## Project structure

```
sarvam_infinium/
├── app.py               # FastAPI backend: Sarvam STT → LLM → TTS pipeline, demo scenarios
├── static/
│   └── index.html       # Single-page dashboard (vanilla HTML/CSS/JS, no build step)
├── requirements.txt
├── .env.example         # Copy to .env and add your key
└── .gitignore           # .env, old_files/, demo audio cache, *.exe
```

Not committed: `.env` (the API key), `static/demo_cache/` (Bulbul demo audio, regenerated on first use) and `old_files/` (a local archive folder).

### API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard |
| `POST` | `/api/listen` | Form fields: `file` (audio chunk), `history` (transcript so far), `warned`, `warn_lang` (`auto` or e.g. `ta-IN`). Returns the transcript, language, risk, flags, evidence, scam type, reason, warning, family alert, `warning_audio` (base64 WAV, only the first time risk ≥ 70) and timings. |
| `POST` | `/api/lesson` | Form fields: `history`, `flags`, `lang`. Returns the lesson text plus Bulbul audio explaining the scam to the elder. |
| `GET` | `/api/demos` | The demo scenarios and their scripts |
| `GET` | `/api/demo/{name}/{i}` | Line `i` of a scenario voiced by Bulbul (cached as WAV) |

---

## Run it

Requires Python 3.10 or later.

```bash
pip install -r requirements.txt
cp .env.example .env          # then put your Sarvam key in .env
python -m uvicorn app:app --port 8000
```

Open http://127.0.0.1:8000 and then:

1. **Demo:** pick a scenario and press **▶ Play demo call**.
2. **Live:** press **🎙️ Live mic**, allow microphone access, and play or speak a call near the laptop.
3. Use **Warn the elder in** to choose the warning language.

Optional settings in `.env`: `STT_MODEL`, `LLM_MODEL`, `TTS_MODEL`, `WARN_SPEAKER`.

---

## Build log

1. **Picking the idea:** we went through the event's idea library and chose an original, high-impact problem that isn't on it: real-time digital-arrest scam interception for elders. It uses all three Sarvam model families in one loop and gives a live stage moment.
2. **Checking the API:** we checked Sarvam's current docs. STT is `saaras:v4`, the chat endpoint serves `sarvam-105b` and `sarvam-105b-conversations`, and TTS is `bulbul:v3` with its own speaker set. We chose `sarvam-105b-conversations` because it's tuned for voice-agent latency, with reasoning turned off and JSON output mode on.
3. **v1 pipeline:** FastAPI backend with STT, the LLM risk JSON and a TTS warning, plus a basic single-page UI. Smoke-tested end to end on a Bulbul-generated Hindi scam line (risk 95).
4. **Bug fix:** Chrome's `MediaRecorder` produces `audio/webm;codecs=opus`, which Saaras rejects. We replaced it with raw PCM capture in the browser (ScriptProcessor), downsampled to 16 kHz mono 16-bit WAV, which is also the format STT handles best.
5. **v2 product:** a redesigned dashboard (phone panel, gauge, stage ladder, sparkline, evidence-backed flags, family alert, latency), a warning-language picker, three demo scenarios including a safe control call, silence skipping, and muting the mic during the warning.
6. **Hardening:** venue Wi-Fi caused `getaddrinfo failed` errors, so we added a shared HTTP client with automatic retries. Connection reuse also cut per-chunk latency from about 8 s to about 1 s.
7. **Iteration 2, from detection to action:** a one-tap 1930 cyber-helpline call and a downloadable evidence report (timestamped transcript plus the scammer's exact quotes per red flag), so the elder or family can file at cybercrime.gov.in straight away.
8. **Iteration 3, protect, push back, teach:** English subtitles for judges and non-speakers, a voice that talks back to the scammer in their own language, scanning of uploaded voice notes, and a spoken after-call lesson for the elder. Tested live on the Tamil scenario: risk 25, then 95 on line 2, with the Tamil warning, the talk-back audio and a Tamil lesson all generated.

---

## Roadmap

- Android app that runs on-call (call-screening or accessibility service) instead of the speakerphone setup
- Automatic WhatsApp/SMS dispatch of the family alert
- Streaming STT for sub-second detection
- A crowd-sourced scam-script library to improve the prompt and few-shot examples
- A feature-phone version through an IVR "conference-in Kavach" number

## Security

Keep the Sarvam API key in `.env` and never commit it. `.env` is already listed in `.gitignore`.
