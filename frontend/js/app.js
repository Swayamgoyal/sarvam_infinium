const FLAGS = {
  fake_authority:    ["👮", "Impersonating police / CBI / bank"],
  urgency_threat:    ["⛓️", "Arrest / FIR / account-block threat"],
  secrecy:           ["🤫", "Asks to hide it from family"],
  video_call_arrest: ["📹", "'Digital arrest' on video call"],
  money_transfer:    ["💸", "Demands money transfer"],
  otp_kyc:           ["🔑", "Asks for OTP / KYC / Aadhaar"],
  remote_app:        ["📲", "Asks to install remote-access app"],
};
const STAGES = [
  ["Hook", s => s.risk >= 20],
  ["Authority", s => s.seen.has("fake_authority")],
  ["Fear", s => s.seen.has("urgency_threat")],
  ["Isolation", s => s.seen.has("secrecy") || s.seen.has("video_call_arrest")],
  ["Extraction", s => s.seen.has("money_transfer") || s.seen.has("otp_kyc") || s.seen.has("remote_app")],
];
const CHUNK_SEC = 5, SILENCE_RMS = 0.012, THRESH = 70;
const $ = id => document.getElementById(id);

let S, demos = {}, queue = Promise.resolve(), lastWarning = null, timerId = null;
let mic = null;   // {stream, ctx, proc}
let muted = false;

function fresh() {
  S = { history: [], risk: 0, series: [], seen: new Set(), evidence: {}, warned: false, start: 0, active: false,
        lines: [], scamType: "", warnText: "", warnLang: "", familyText: "", caller: "" };
}

/* ---------- rendering ---------- */
function color(r) { return r >= THRESH ? "var(--danger)" : r >= 40 ? "var(--warn)" : "var(--safe)"; }

function renderFlags() {
  $("flags").innerHTML = Object.entries(FLAGS).map(([k, [ic, nm]]) => {
    const hit = S.seen.has(k), q = S.evidence[k];
    return `<div class="flag ${hit ? "hit" : ""}"><div class="ic">${ic}</div>
      <div><div class="nm">${nm}</div><div class="q">${q ? "“" + esc(q) + "”" : ""}</div></div>
      <div class="st">${hit ? "DETECTED" : "—"}</div></div>`;
  }).join("");
}

function renderRisk(reason, scamType) {
  const c = color(S.risk);
  $("gauge").style.setProperty("--p", S.risk);
  $("gauge").style.setProperty("--c", c);
  $("riskNum").textContent = S.risk; $("riskNum").style.color = c;
  $("verdict").style.color = c;
  $("verdict").textContent = S.risk >= THRESH ? "🚨 Scam detected" : S.risk >= 40 ? "⚠️ Suspicious call" : "Call looks safe";
  if (reason) $("reason").textContent = reason;
  $("stype").innerHTML = scamType && scamType !== "None" && S.risk >= 40 ? `<span class="scamtype">${esc(scamType)}</span>` : "";
  $("ladder").innerHTML = STAGES.map(([n, f], i) => `<div class="step ${f(S) ? "on" : ""}"><div class="n">0${i + 1}</div><div class="s">${n}</div></div>`).join("");
  $("phone").classList.toggle("danger", S.risk >= THRESH);
  $("avatar").textContent = S.risk >= THRESH ? "⚠️" : "📞";
  renderSpark();
}

function renderSpark() {
  const pts = [0, ...S.series], n = Math.max(pts.length - 1, 1);
  const xy = pts.map((r, i) => [(i / n) * 300, 60 - (r / 100) * 56]);
  const line = xy.map(p => p.join(",")).join(" ");
  const c = color(S.risk).replace("var(", "").replace(")", "");
  $("spark").innerHTML = `
    <line x1="0" x2="300" y1="${60 - THRESH * .56}" y2="${60 - THRESH * .56}" stroke="#ef4444" stroke-opacity=".45" stroke-dasharray="4 4" vector-effect="non-scaling-stroke"/>
    <polygon points="0,60 ${line} 300,60" fill="var(${c})" fill-opacity=".14"/>
    <polyline points="${line}" fill="none" stroke="var(${c})" stroke-width="2.5" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>`;
}

function addMsg(d) {
  if ($("tx").querySelector(".empty")) $("tx").innerHTML = "";
  const t = d.timings || {};
  const el = document.createElement("div");
  el.className = "msg";
  el.innerHTML = `<div class="bar" style="background:${color(d.risk)}"></div><div>
    <div class="meta"><span>${clock()}</span><span>${d.language_code || ""}</span>
    <span class="r" style="color:${color(d.risk)}">risk ${d.risk}</span>
    <span>STT ${t.stt ?? "–"} ms · LLM ${t.llm ?? "–"} ms${t.tts ? " · TTS " + t.tts + " ms" : ""}</span></div>
    <div class="txt"></div></div>`;
  el.querySelector(".txt").textContent = d.transcript;
  if (d.english && d.language_code !== "en-IN") {
    const en = document.createElement("div");
    en.className = "en"; en.textContent = "EN · " + d.english;
    el.querySelector(".txt").after(en);
  }
  $("tx").appendChild(el);
  $("tx").scrollTop = 1e9;
  $("lat").textContent = t.stt ? `last check ${((t.stt + t.llm) / 1000).toFixed(1)} s` : "";
}

function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function clock() { const s = S.start ? Math.floor((Date.now() - S.start) / 1000) : 0; return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`; }

function downloadReport() {
  const now = new Date();
  const L = [
    "KAVACH - SCAM CALL EVIDENCE REPORT",
    "==================================",
    `Generated     : ${now.toLocaleString("en-IN")}`,
    `Caller        : ${S.caller || "Unknown"}`,
    `Call duration : ${clock()}`,
    `Verdict       : ${S.risk >= THRESH ? "SCAM DETECTED" : S.risk >= 40 ? "SUSPICIOUS" : "No scam detected"} (peak risk ${S.risk}/100)`,
    `Scam pattern  : ${S.scamType || "-"}`,
    "",
    "RED FLAGS (with the caller's exact words)",
    "-----------------------------------------",
    ...(S.seen.size ? [...S.seen].map(k => `- ${FLAGS[k][1]}${S.evidence[k] ? `: "${S.evidence[k]}"` : ""}`) : ["- none"]),
    "",
    "TIMESTAMPED TRANSCRIPT",
    "----------------------",
    ...S.lines.map(l => `[${l.t}] (${l.lang}, risk ${l.risk}) ${l.text}`),
    "",
    "ACTION TAKEN BY KAVACH",
    "----------------------",
    S.warnText ? `Spoken warning (${S.warnLang}): ${S.warnText}` : "No warning issued.",
    S.familyText ? `Family alert: ${S.familyText}` : "",
    "",
    "NEXT STEPS",
    "----------",
    "1. Do NOT share any OTP, PIN or transfer money. Police never arrest anyone over a video call.",
    "2. Call the National Cyber Crime Helpline: 1930",
    "3. File a complaint at https://cybercrime.gov.in and attach this report.",
    "4. Block the number and report it on Sanchar Saathi (Chakshu): https://sancharsaathi.gov.in",
    "",
    "Analysis: Saaras v4 (speech-to-text) -> Sarvam-105B (scam reasoning) -> Bulbul v3 (voice warning)",
  ];
  const blob = new Blob([L.join("\n")], { type: "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `kavach_report_${now.toISOString().slice(0, 16).replace(/[:T]/g, "-")}.txt`;
  a.click();
}

function startCall(name, meta) {
  S.active = true; S.start = Date.now(); S.caller = name;
  $("caller").textContent = name;
  $("phone").classList.add("ringing");
  clearInterval(timerId);
  timerId = setInterval(() => $("callmeta").textContent = `${meta} · ${clock()}`, 500);
}
function endCall() {
  S.active = false; clearInterval(timerId);
  $("phone").classList.remove("ringing");
  $("callmeta").textContent = S.history.length ? `Call ended · ${clock()}` : "Kavach is standing by";
  $("wave").classList.remove("anim"); setWave(0);
}

const WAVE_N = 28;
$("wave").innerHTML = "<i></i>".repeat(WAVE_N);
[...$("wave").children].forEach((b, i) => b.style.animationDelay = `${(i % 7) * 0.09}s`);
function setWave(level) {
  [...$("wave").children].forEach((b, i) => {
    const h = 4 + Math.min(1, level * 9) * 28 * (0.4 + 0.6 * Math.abs(Math.sin(i * 1.7 + Date.now() / 120)));
    b.style.height = h + "px"; b.style.background = level > SILENCE_RMS ? "var(--accent2)" : "var(--dim)";
  });
}

/* ---------- alerts ---------- */
function alarm() {
  try {
    const ctx = new AudioContext();
    [0, .3, .6, .9].forEach(t => {
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.type = "square"; o.frequency.value = t % .6 ? 660 : 990; g.gain.value = .12;
      o.connect(g).connect(ctx.destination); o.start(ctx.currentTime + t); o.stop(ctx.currentTime + t + .22);
    });
  } catch (e) {}
}
function playB64(b64) {
  return new Promise(res => {
    muted = true;
    const a = new Audio("data:audio/wav;base64," + b64);
    const done = () => { muted = false; res(); };
    a.onended = done; a.onerror = done; a.play().catch(done);
  });
}

/* ---------- pipeline ---------- */
async function handle(d) {
  if (!d || d.skipped || !d.transcript) return;
  S.history.push(d.transcript);
  S.lines.push({ t: clock(), lang: d.language_code, risk: d.risk, text: d.transcript });
  if (d.scam_type && d.scam_type !== "None") S.scamType = d.scam_type;
  if (d.family_alert && !S.familyText) S.familyText = d.family_alert;
  $("btnReport").disabled = false;
  S.series.push(d.risk);
  S.risk = Math.max(S.risk, d.risk);
  (d.flags || []).forEach(f => S.seen.add(f));
  (d.evidence || []).forEach(e => { if (e.quote && !S.evidence[e.flag]) S.evidence[e.flag] = e.quote; });
  addMsg(d);
  renderFlags();
  renderRisk(d.reason, d.scam_type);
  if (d.family_alert && !$("family").classList.contains("show")) {
    $("familyTxt").textContent = d.family_alert;
    $("family").classList.add("show");
  }
  if (d.warning_audio && !S.warned) {
    S.warned = true;
    S.warnText = d.warning; S.warnLang = d.warn_lang;
    lastWarning = d.warning_audio;
    $("warnTxt").textContent = d.warning;
    $("warnMeta").textContent = `${d.scam_type && d.scam_type !== "None" ? d.scam_type + " · " : ""}spoken in ${d.warn_lang}`;
    $("overlay").classList.add("show");
    alarm();
    await new Promise(r => setTimeout(r, 1300));
    await playB64(d.warning_audio);
    if (d.talkback_audio) {
      $("warnMeta").textContent = "🗣️ Kavach is now speaking to the scammer: call recorded & reported to 1930";
      await new Promise(r => setTimeout(r, 500));
      await playB64(d.talkback_audio);
    }
    $("btnLesson").disabled = false;
  }
}

function send(blob, name) {
  const fd = new FormData();
  fd.append("file", blob, name);
  fd.append("history", S.history.join("\n"));
  fd.append("warned", String(S.warned));
  fd.append("warn_lang", $("wlang").value);
  const p = fetch("/api/listen", { method: "POST", body: fd })
    .then(async r => { if (!r.ok) throw new Error((await r.text()).slice(0, 220)); return r.json(); })
    .catch(e => { hint(String(e.message || e), true); return null; });
  queue = queue.then(() => p).then(handle);   // keep transcript order
  return p;
}

function hint(t, err) { $("hint").textContent = t; $("hint").classList.toggle("err", !!err); }

/* ---------- live mic → 16 kHz WAV chunks ---------- */
function toWav(f32, inRate, outRate = 16000) {
  const ratio = inRate / outRate, n = Math.floor(f32.length / ratio), pcm = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    const a = Math.floor(i * ratio), b = Math.min(f32.length, Math.floor((i + 1) * ratio));
    let s = 0; for (let j = a; j < b; j++) s += f32[j];
    const v = Math.max(-1, Math.min(1, s / Math.max(1, b - a)));
    pcm[i] = v < 0 ? v * 0x8000 : v * 0x7fff;
  }
  const buf = new ArrayBuffer(44 + pcm.length * 2), v = new DataView(buf);
  const w = (o, s) => [...s].forEach((c, i) => v.setUint8(o + i, c.charCodeAt(0)));
  w(0, "RIFF"); v.setUint32(4, 36 + pcm.length * 2, true); w(8, "WAVE"); w(12, "fmt ");
  v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true);
  v.setUint32(24, outRate, true); v.setUint32(28, outRate * 2, true); v.setUint16(32, 2, true); v.setUint16(34, 16, true);
  w(36, "data"); v.setUint32(40, pcm.length * 2, true);
  new Int16Array(buf, 44).set(pcm);
  return new Blob([buf], { type: "audio/wav" });
}

async function startMic() {
  const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: false, noiseSuppression: true, autoGainControl: true } });
  const ctx = new AudioContext();
  const src = ctx.createMediaStreamSource(stream);
  const proc = ctx.createScriptProcessor(4096, 1, 1);
  let parts = [], len = 0, energy = 0;
  proc.onaudioprocess = e => {
    const d = e.inputBuffer.getChannelData(0);
    let sq = 0; for (let i = 0; i < d.length; i++) sq += d[i] * d[i];
    const rms = Math.sqrt(sq / d.length);
    setWave(rms);
    if (muted) { parts = []; len = 0; energy = 0; return; }   // don't transcribe our own warning
    parts.push(new Float32Array(d)); len += d.length; energy += sq;
    if (len >= ctx.sampleRate * CHUNK_SEC) {
      const all = new Float32Array(len); let o = 0;
      parts.forEach(p => { all.set(p, o); o += p.length; });
      const chunkRms = Math.sqrt(energy / len);
      parts = []; len = 0; energy = 0;
      if (chunkRms < SILENCE_RMS) { hint("Listening… (silence skipped, no credits used)"); return; }
      hint("Listening… analysing last 5 s");
      send(toWav(all, ctx.sampleRate), "chunk.wav");
    }
  };
  src.connect(proc); proc.connect(ctx.destination);
  mic = { stream, ctx, proc };
}
function stopMic() {
  if (!mic) return;
  mic.proc.disconnect(); mic.stream.getTracks().forEach(t => t.stop()); mic.ctx.close(); mic = null;
}

$("btnMic").onclick = async () => {
  if (mic) {
    stopMic(); endCall();
    $("btnMic").textContent = "🎙️ Live mic"; $("btnMic").classList.remove("on"); $("btnDemo").disabled = false;
    hint("Mic stopped.");
    return;
  }
  try { await startMic(); } catch (e) { hint("Microphone permission denied.", true); return; }
  if (!S.history.length) startCall("Live call on speaker", "Kavach listening");
  $("btnMic").textContent = "⏹ Stop mic"; $("btnMic").classList.add("on"); $("btnDemo").disabled = true;
  hint("Listening… speak or play the call near the mic.");
};

/* ---------- demo scenarios (Bulbul-voiced, same STT→LLM pipeline) ---------- */
$("btnDemo").onclick = async () => {
  const key = $("scenario").value, d = demos[key];
  reset();
  $("btnDemo").disabled = true; $("btnMic").disabled = true;
  startCall(d.caller, "On speaker · Kavach listening");
  $("wave").classList.add("anim");
  try {
    for (let i = 0; i < d.lines.length; i++) {
      hint(`Caller speaking · line ${i + 1}/${d.lines.length}`);
      const blob = await (await fetch(`/api/demo/${key}/${i}`)).blob();
      const a = new Audio(URL.createObjectURL(blob));
      const played = new Promise(r => { a.onended = r; a.onerror = r; });
      send(blob, `${key}_${i}.wav`);        // analyse while the line plays
      await a.play(); await played;
      await queue;
      if (S.warned) break;
    }
    hint(S.warned ? "Scam stopped before money or OTP was shared." : "Call finished. No scam detected ✅");
  } catch (e) { hint(String(e).slice(0, 200), true); }
  endCall();
  $("btnDemo").disabled = false; $("btnMic").disabled = false;
};

function reset() {
  fresh(); lastWarning = null; $("btnReport").disabled = true; $("btnLesson").disabled = true;
  $("lesson").classList.remove("show");
  $("tx").innerHTML = '<div class="empty">The call transcript will stream here.</div>';
  $("reason").textContent = "Waiting for the conversation to start.";
  $("family").classList.remove("show"); $("overlay").classList.remove("show");
  $("caller").textContent = "No active call"; $("lat").textContent = "";
  endCall(); renderFlags(); renderRisk();
}
$("btnReset").onclick = () => { if (mic) $("btnMic").click(); reset(); hint("Ready."); };
$("btnReplay").onclick = () => lastWarning && playB64(lastWarning);
$("btnClose").onclick = () => $("overlay").classList.remove("show");
$("btnCopy").onclick = () => navigator.clipboard?.writeText($("familyTxt").textContent).then(() => $("btnCopy").textContent = "Copied ✓");

/* ---------- check a voice note: decode any audio → 16 kHz WAV pieces → same pipeline ---------- */
$("btnUpload").onclick = () => $("fileIn").click();
$("fileIn").onchange = async () => {
  const f = $("fileIn").files[0]; $("fileIn").value = "";
  if (!f) return;
  reset();
  $("btnUpload").disabled = $("btnDemo").disabled = $("btnMic").disabled = true;
  startCall("Voice note: " + f.name.slice(0, 28), "Scanning recording");
  $("wave").classList.add("anim");
  try {
    const ctx = new AudioContext();
    const buf = await ctx.decodeAudioData(await f.arrayBuffer());
    const data = buf.getChannelData(0), step = buf.sampleRate * 20;   // 20 s pieces
    for (let o = 0, k = 1; o < data.length; o += step, k++) {
      hint(`Scanning voice note · part ${k}/${Math.ceil(data.length / step)}`);
      send(toWav(data.subarray(o, o + step), buf.sampleRate), `note_${k}.wav`);
      await queue;
      if (S.warned) break;
    }
    ctx.close();
    hint(S.warned ? "Scam voice note detected." : "Voice note scanned. No scam detected ✅");
  } catch (e) { hint("Could not read this audio file: " + e, true); }
  endCall();
  $("btnUpload").disabled = $("btnDemo").disabled = $("btnMic").disabled = false;
};

/* ---------- after-call lesson for the elder ---------- */
$("btnLesson").onclick = async () => {
  $("btnLesson").disabled = true; hint("Preparing a lesson for the elder…");
  const fd = new FormData();
  fd.append("history", S.history.join("\n"));
  fd.append("flags", [...S.seen].map(k => FLAGS[k][1]).join(", "));
  fd.append("lang", S.warnLang || ($("wlang").value !== "auto" ? $("wlang").value : S.lines.at(-1)?.lang) || "hi-IN");
  try {
    const r = await fetch("/api/lesson", { method: "POST", body: fd });
    if (!r.ok) throw new Error((await r.text()).slice(0, 200));
    const j = await r.json();
    $("overlay").classList.remove("show");
    $("lessonTxt").textContent = j.text; $("lesson").classList.add("show");
    hint("Bulbul is explaining the scam to the elder…");
    await playB64(j.audio);
    hint("Lesson done.");
  } catch (e) { hint(String(e.message || e), true); }
  $("btnLesson").disabled = false;
};

fetch("/api/demos").then(r => r.json()).then(j => {
  demos = j;
  $("scenario").innerHTML = Object.entries(j).map(([k, v]) => `<option value="${k}">${v.title}</option>`).join("");
});
fresh(); reset(); hint("Live mic: put the real call on speaker near the laptop.");
