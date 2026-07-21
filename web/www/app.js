import init, * as stg from "./pkg/stegno_web.js";

const $ = (id) => document.getElementById(id);
const bytesOf = async (file) => new Uint8Array(await file.arrayBuffer());
function toU8(x) { return x instanceof Uint8Array ? x : new Uint8Array(x); }
function download(bytes, name, mime = "application/octet-stream") {
  const url = URL.createObjectURL(new Blob([toU8(bytes)], { type: mime }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}
function esc(s) { return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function banner(ok, html) { return `<div class="result-banner ${ok ? "ok" : "bad"}">${html}</div>`; }
function fail(el, e) { el.innerHTML = `<div class="result-banner bad">⚠️ ${esc(e.message || e)}</div>`; }
function spin(el, label) { el.innerHTML = `<span class="spinner"></span>${esc(label)}`; }
function defer(fn) { setTimeout(fn, 30); }
const hex = (arr) => [...toU8(arr)].map((b) => b.toString(16).padStart(2, "0")).join("");

/* ---------------- Theme ---------------- */
function effectiveTheme() {
  const t = document.documentElement.getAttribute("data-theme");
  if (t) return t;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
function applyTheme(t) {
  if (t) document.documentElement.setAttribute("data-theme", t);
  else document.documentElement.removeAttribute("data-theme");
  $("themeToggle").textContent = effectiveTheme() === "dark" ? "☀️" : "🌙";
}
(function initTheme() {
  applyTheme(localStorage.getItem("stegno-theme"));
  $("themeToggle").addEventListener("click", () => {
    const next = effectiveTheme() === "dark" ? "light" : "dark";
    localStorage.setItem("stegno-theme", next);
    applyTheme(next);
  });
})();

/* ---------------- Grouped tabs ---------------- */
const GROUPS = [
  { id: "hide", label: "🔒 Hide", subs: [{ id: "compose", label: "🔒 Hide" }] },
  { id: "reveal", label: "🔑 Reveal", subs: [{ id: "reveal", label: "🔑 Reveal" }] },
  { id: "analyze", label: "🔬 Analyze", subs: [
    { id: "analyze", label: "🔍 Inspect" }, { id: "lab", label: "🧪 Lab" },
    { id: "keys", label: "🔐 Key-shares" }, { id: "clean", label: "🧼 Clean" }] },
];
function showPanel(id) {
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "panel-" + id));
  document.querySelectorAll("#subtabs button").forEach((b) => b.classList.toggle("active", b.dataset.sub === id));
}
function selectGroup(gid) {
  const g = GROUPS.find((x) => x.id === gid);
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.group === gid));
  const sub = $("subtabs");
  if (g.subs.length > 1) {
    sub.hidden = false;
    sub.innerHTML = g.subs.map((s) => `<button data-sub="${s.id}">${s.label}</button>`).join("");
  } else { sub.hidden = true; sub.innerHTML = ""; }
  showPanel(g.subs[0].id);
}
$("tabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-group]"); if (b) selectGroup(b.dataset.group); });
$("subtabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-sub]"); if (b) showPanel(b.dataset.sub); });
selectGroup("hide");

/* ---------------- File drop helpers ---------------- */
function wireDrop(dropId, inputId, onFile) {
  const drop = $(dropId), input = $(inputId);
  drop.addEventListener("click", () => input.click());
  input.addEventListener("change", async () => {
    const f = input.files[0];
    if (!f) return;
    drop.classList.add("has");
    drop.innerHTML = `<span class="big">✅</span>${esc(f.name)} <span class="small">(${(f.size / 1024).toFixed(0)} KB)</span>`;
    onFile(f);
  });
}
/// Collects several files, keeping each name so stego output can be named after
/// the cover it came from.
function wireDropMulti(dropId, inputId, onFiles) {
  const drop = $(dropId), input = $(inputId);
  drop.addEventListener("click", () => input.click());
  input.addEventListener("change", async () => {
    const files = [...input.files];
    if (!files.length) return;
    drop.classList.add("has");
    drop.innerHTML = `<span class="big">✅</span>${files.length} file(s) selected`;
    onFiles(await Promise.all(files.map(async (f) => ({ name: f.name, bytes: await bytesOf(f) }))));
  });
}

/* --------- carrier-aware naming --------- */
/** Base name without its extension. */
function stemOf(name) { return name.replace(/\.[^.]+$/, ""); }
/** Original extension including the dot, or "" when there isn't one. */
function extOf(name) { return name.match(/\.[^.]+$/)?.[0] || ""; }

/**
 * What a stego file made from `cover` should be called. Photos are re-encoded
 * to PNG (lossless is mandatory for LSB survival) so they take a .png name;
 * every other carrier keeps its own container, so a .pdf cover stays a .pdf and
 * a clip stays playable under its original extension.
 */
function stegoNameFor(cover, info, fallbackStem) {
  const stem = cover?.name ? stemOf(cover.name) : fallbackStem;
  if (info?.preservesContainer && cover?.name) return `${stem}-hidden${extOf(cover.name)}`;
  return `${stem}-hidden.${info?.extension || "png"}`;
}

/** Human label for a carrier kind, for the capacity readout. */
const KIND_LABEL = {
  image: "photo", audio: "audio", text: "text",
  video: "video (frame-level)", bytes: "file (appended)",
};

/* ---------------- Boot ---------------- */
let IMAGE_METHODS = [], ALL_METHODS = [];
async function boot() {
  await init();
  const methods = stg.listMethods();
  ALL_METHODS = methods;
  $("engineInfo").textContent = `· ${methods.length} methods`;
  IMAGE_METHODS = methods.filter((m) => m.media === "Image");
  // Detectability is an image analysis, so it keeps image methods only.
  IMAGE_METHODS.forEach((m) => { const o = document.createElement("option"); o.value = m.id; o.textContent = m.displayName; $("detMethod").appendChild(o); });
  // The composer's single-hide can target ANY carrier, so list every method,
  // labelled by the cover type it works on (photo / text / audio / file).
  const cm = $("cmpMethod");
  methods.forEach((m) => { const o = document.createElement("option"); o.value = m.id; o.textContent = `${m.displayName} · ${m.media.toLowerCase()}`; cm.appendChild(o); });
  const seeded = methods.find((m) => m.id === "lsb_seeded"); if (seeded) cm.value = seeded.id;
  setupCompose(); setupReveal(); setupAnalyze(); setupLab(); setupKeys(); setupClean();
}

/* ---------------- HIDE (composer) ---------------- */
let composeCovers = [];
let entries = [{ type: "text", text: "", files: [], pass: "" }];
function setupCompose() {
  renderEntries();
  wireDropMulti("cmpCoversDrop", "cmpCoversInput", (arr) => {
    // Ask the engine what each cover actually is, so capacity and the eventual
    // filename reflect the real carrier rather than assuming a photo.
    composeCovers = arr.map((c) => {
      let info = null;
      try { info = stg.coverInfo(c.bytes); } catch { /* engine will report on embed */ }
      return { ...c, info };
    });
    // A new cover is a new situation, so go back to choosing automatically.
    methodIsAuto = true;
    inputsChanged();
  });
  $("cmpAddEntry").addEventListener("click", () => {
    if (entries.length < 8) { entries.push({ type: "text", text: "", files: [], pass: "" }); renderEntries(); inputsChanged(); }
  });
  // A manual pick wins until the cover or secret changes again.
  $("cmpMethod").addEventListener("change", () => { methodIsAuto = false; refreshCompose(); });
  $("cmpPlanBtn").addEventListener("click", doPlan);
  $("cmpBtn").addEventListener("click", doCompose);
}
function isSingle() { return entries.length === 1 && composeCovers.length === 1; }

/** Something the user changed: refresh the form and re-pick the method. */
function inputsChanged() {
  refreshCompose();
  scheduleAutoMethod();
}

/* --------- automatic method choice --------- */
// True while the shown method is the engine's pick rather than the user's.
let methodIsAuto = true;
let autoMethodTimer = null;

/** Payload size of the first entry, which is what a single hide will carry. */
function firstEntryLen() {
  const e = entries[0];
  if (!e) return 0;
  return e.type === "text"
    ? new TextEncoder().encode(e.text).length
    : e.files.reduce((n, f) => n + f.bytes.length, 0);
}

/**
 * Re-pick the best method for the current cover and secret.
 *
 * Debounced and deferred because planning asks every method for its capacity,
 * and the image methods each decode the cover — about 1.8s on a 6-megapixel
 * photo. Running that per keystroke would lock the page, so it settles first
 * and reports progress while it works.
 */
function scheduleAutoMethod() {
  if (autoMethodTimer) clearTimeout(autoMethodTimer);
  const note = $("cmpAutoNote");
  if (!methodIsAuto || !isSingle() || !composeCovers.length) {
    note.textContent = methodIsAuto ? "" : "Method chosen by you.";
    return;
  }
  note.textContent = "Choosing the best method…";
  autoMethodTimer = setTimeout(() => {
    try {
      const recs = stg.planEmbedding(composeCovers[0].bytes, firstEntryLen());
      const best = recs.find((r) => r.fits);
      if (best) {
        $("cmpMethod").value = best.methodId;
        note.innerHTML = `Chosen for you: <b>${esc(best.displayName || best.methodId)}</b> — ${esc(best.note)}`;
      } else {
        note.textContent = "No method fits this secret in this cover.";
      }
    } catch {
      note.textContent = "";
    }
    refreshCompose();
  }, 400);
}
function doPlan() {
  if (!composeCovers.length) return;
  const out = $("cmpPlanOut");
  try {
    const payloadLen = entries[0].type === "text" ? new TextEncoder().encode(entries[0].text).length
      : entries[0].files.reduce((n, f) => n + f.bytes.length, 0);
    const recs = stg.planEmbedding(composeCovers[0].bytes, payloadLen);
    const byId = Object.fromEntries(ALL_METHODS.map((m) => [m.id, m.displayName]));
    out.innerHTML = recs.slice(0, 4).map((r) =>
      `<button class="rec" data-id="${esc(r.methodId)}"><b>${r.fits ? "✅" : "⚠️"} ${esc(byId[r.methodId] || r.methodId)}</b><span class="tag ${r.stealthTier >= 2 ? "ok" : r.stealthTier === 1 ? "warn" : "bad"}">stealth ${r.stealthTier}/3</span><span class="small">${esc(r.note)}</span></button>`).join("");
    out.querySelectorAll("button.rec").forEach((b) => b.addEventListener("click", () => { $("cmpMethod").value = b.dataset.id; out.innerHTML = ""; refreshCompose(); }));
  } catch (e) { fail(out, e); }
}
function renderEntries() {
  const wrap = $("cmpEntries");
  wrap.innerHTML = entries.map((e, i) => `
    <div class="recip" data-i="${i}">
      <div class="seg e-type">
        <button data-t="text" class="${e.type === "text" ? "active" : ""}">Text</button>
        <button data-t="file" class="${e.type === "file" ? "active" : ""}">File(s)</button>
        ${entries.length > 1 ? `<button class="e-del" title="Remove" style="margin-left:auto;border:0;background:transparent;color:var(--muted);cursor:pointer;font-weight:700">✕</button>` : ""}
      </div>
      ${e.type === "text"
        ? `<textarea class="e-text" placeholder="Secret message">${esc(e.text)}</textarea>`
        : `<div class="drop mini e-filedrop">${e.files.length ? `✅ ${e.files.length} file(s)` : "📎 Choose file(s)"}</div>`}
      <input type="password" class="e-pass" placeholder="Password for this secret" value="${esc(e.pass)}" style="margin-top:8px" />
      <div class="meter"><span class="e-str" style="width:0"></span></div>
      <div class="small e-strtext">Strength shows as you type.</div>
    </div>`).join("");
  wrap.querySelectorAll(".recip").forEach((row) => {
    const i = +row.dataset.i;
    row.querySelectorAll(".e-type button[data-t]").forEach((b) => b.addEventListener("click", () => { entries[i].type = b.dataset.t; renderEntries(); inputsChanged(); }));
    const del = row.querySelector(".e-del"); if (del) del.addEventListener("click", () => { entries.splice(i, 1); renderEntries(); inputsChanged(); });
    const ta = row.querySelector(".e-text"); if (ta) ta.addEventListener("input", () => { entries[i].text = ta.value; inputsChanged(); });
    const pass = row.querySelector(".e-pass");
    pass.addEventListener("input", () => { entries[i].pass = pass.value; updateStrength(row, pass.value); refreshCompose(); });
    updateStrength(row, e.pass);
    const fd = row.querySelector(".e-filedrop"); if (fd) fd.addEventListener("click", () => pickEntryFiles(i));
  });
}
function updateStrength(row, val) {
  const bar = row.querySelector(".e-str"), txt = row.querySelector(".e-strtext");
  if (!val) { bar.style.width = "0"; txt.textContent = "Strength shows as you type."; return; }
  const s = stg.passphraseStrength(val);
  const colors = ["var(--bad)", "var(--bad)", "var(--warn)", "var(--ok)", "var(--ok)"];
  const labels = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];
  bar.style.width = ((s.score + 1) / 5 * 100) + "%";
  bar.style.background = colors[s.score];
  txt.innerHTML = `<b>${labels[s.score]}</b> · ~${s.entropyBits.toFixed(0)} bits · cracks in ${esc(s.crackTimeDisplay)}${s.warning ? ` · <span class="err">${esc(s.warning)}</span>` : ""}`;
}
function pickEntryFiles(i) {
  const inp = document.createElement("input");
  inp.type = "file"; inp.multiple = true;
  inp.addEventListener("change", async () => {
    entries[i].files = await Promise.all([...inp.files].map(async (f) => ({ name: f.name, bytes: await bytesOf(f) })));
    renderEntries(); inputsChanged();
  });
  inp.click();
}
function entryToJs(e) {
  return e.type === "text"
    ? { passphrase: e.pass, text: e.text }
    : { passphrase: e.pass, files: e.files.map((f) => ({ name: f.name, bytes: f.bytes })) };
}
function refreshCompose() {
  const single = isSingle();
  // The method picker only governs a single-secret hide: a mix is placed by the
  // layered region scheme instead. Disable it rather than removing it, and say
  // which scheme is in play, so nothing silently disappears from the form.
  const method = $("cmpMethod"), plan = $("cmpPlanBtn");
  method.disabled = !single;
  plan.disabled = !single;
  $("cmpSingle").classList.toggle("inactive", !single);
  if (!single) $("cmpPlanOut").innerHTML = "";
  $("cmpScheme").innerHTML = composeCovers.length ? describeScheme() : "";

  if (composeCovers.length) {
    try {
      const bytes = composeCovers.map((c) => c.bytes);
      const cap = single
        ? stg.capacity(method.value, bytes[0])
        : stg.compositeCapacity(bytes, Math.max(entries.length, 1));
      const kinds = composeCovers
        .map((c) => KIND_LABEL[c.info?.kind] || "file")
        .filter((k, i, a) => a.indexOf(k) === i)
        .join(", ");
      $("cmpCap").textContent =
        `Carrier: ${kinds}. Room for about ${cap.toLocaleString()} bytes${single ? "" : " per secret"}.`;
    } catch { $("cmpCap").textContent = ""; }
  } else $("cmpCap").textContent = "";

  const ready = composeCovers.length >= 1 && entries.length >= 1 &&
    entries.every((e) => e.pass && (e.type === "text" ? e.text : e.files.length > 0));
  $("cmpBtn").disabled = !ready;
}

/** Plain-language summary of what the current cover/secret counts will do. */
function describeScheme() {
  const covers = composeCovers.length, secrets = entries.length;
  const parts = [];
  if (secrets === 1) parts.push("one secret");
  else parts.push(`${secrets} secrets, each with its own password (hand one over as a decoy)`);
  if (covers === 1) parts.push("in one cover");
  else parts.push(`split across ${covers} covers — all of them are needed to rebuild`);
  const scheme = isSingle() ? "Chosen method." : "Layered region scheme (method is chosen for you).";
  return `<b>${esc(scheme)}</b> ${esc(parts.join(", "))}.`;
}
function doCompose() {
  const out = $("cmpOut"); spin(out, "Hiding…");
  const robust = parseInt($("cmpRobust").value, 10), compress = $("cmpCompress").checked;
  defer(() => {
    try {
      if (isSingle()) {
        const cover = composeCovers[0];
        const stego = stg.embedAdvancedEntry($("cmpMethod").value, cover.bytes, entryToJs(entries[0]), robust, compress);
        // A chosen method may re-encode (image methods emit PNG); trust the
        // engine's own view of the result rather than the cover's.
        let info = cover.info;
        try { info = stg.coverInfo(toU8(stego)); } catch { /* keep the cover's */ }
        download(stego, stegoNameFor(cover, info, "stego"), info?.mime || "application/octet-stream");
        out.innerHTML = banner(true, "✅ Hid your secret.");
      } else {
        const parts = stg.embedComposite(composeCovers.map((c) => c.bytes), entries.map(entryToJs), robust, compress);
        parts.forEach((p, i) => {
          const cover = composeCovers[i];
          download(p, stegoNameFor(cover, cover?.info, `part${i + 1}`), cover?.info?.mime || "application/octet-stream");
        });
        out.innerHTML = banner(true, parts.length > 1
          ? `✅ Hid ${entries.length} secret(s) across ${parts.length} covers (all needed to rebuild).`
          : `✅ Hid ${entries.length} secret(s) in one cover.`);
      }
    } catch (e) { fail(out, e); }
  });
}

/* ---------------- REVEAL ---------------- */
let revealBytes = [];
function setupReveal() {
  wireDropMulti("revealDrop", "revealFile", (arr) => { revealBytes = arr.map((f) => f.bytes); $("revealBtn").disabled = !revealBytes.length; });
  $("revealBtn").addEventListener("click", () => {
    const out = $("revealOut"); spin(out, "Revealing…");
    defer(() => {
      try {
        let r = stg.extractComposite(revealBytes, $("revealPass").value);
        if (r.kind === "none" && revealBytes.length === 1) {
          r = stg.extractAuto(revealBytes[0], $("revealPass").value).revealed;
        }
        renderRevealed(out, r);
      } catch (e) { fail(out, e); }
    });
  });
}
function renderRevealed(out, rv) {
  if (rv.kind === "none") { out.innerHTML = banner(false, "🔎 No hidden data found (or wrong password)."); return; }
  if (rv.kind === "text") { out.innerHTML = banner(true, "🔓 Revealed") + `<pre>${esc(rv.text)}</pre>`; }
  else if (rv.kind === "file") { download(rv.bytes, rv.name); out.innerHTML = banner(true, `🔓 Recovered file <b>${esc(rv.name)}</b>. Downloaded.`); }
  else if (rv.kind === "files") { rv.files.forEach((f) => download(f.bytes, f.name)); out.innerHTML = banner(true, `🔓 Recovered ${rv.files.length} files.`); }
}

/* ---------------- INSPECT ---------------- */
let analyzeBytes = null;
function setupAnalyze() {
  wireDrop("analyzeDrop", "analyzeFile", async (f) => { analyzeBytes = await bytesOf(f); $("analyzeBtn").disabled = !analyzeBytes; });
  $("analyzeBtn").addEventListener("click", doAnalyze);
}
function statRow(k, v) { return `<div class="stat"><span>${esc(k)}</span><b>${esc(v)}</b></div>`; }
function doAnalyze() {
  const out = $("analyzeOut");
  try {
    const scan = stg.scanStructure(analyzeBytes);
    const guesses = stg.fingerprint(analyzeBytes);
    let html = banner(!scan.suspicious, scan.suspicious ? "⚠️ Signs of hidden data found" : "✅ Nothing obvious found") +
      `<div class="small" style="margin-top:8px">Format: <b>${esc(scan.format)}</b></div>`;
    if (scan.findings.length) {
      html += "<table><tr><th>Signal</th><th>Detail</th></tr>";
      scan.findings.forEach((f) => { html += `<tr><td>${esc(f.kind)} ${f.severity >= 2 ? '<span class="tag bad">strong</span>' : ""}</td><td>${esc(f.detail)}</td></tr>`; });
      html += "</table>";
    }
    if (guesses.length) {
      html += `<label>Likely method</label><table>`;
      guesses.slice(0, 4).forEach((g) => { html += `<tr><td>${(g.confidence * 100).toFixed(0)}%</td><td>${esc(g.label)}</td></tr>`; });
      html += "</table>";
    }
    try {
      const d = stg.detectLsb(analyzeBytes);
      html += `<label>Statistical LSB analysis</label><div class="small" style="margin-bottom:4px">Likelihood of hidden data: <b>${(d.mlConfidence * 100).toFixed(0)}%</b></div>` +
        statRow("Chi-square p", d.chiSquareP.toFixed(3)) + statRow("RS regularity gap", d.rsRegularityGap.toFixed(3)) + statRow("Sample-pair rate", d.samplePairRate.toFixed(3));
    } catch { /* not an image */ }
    out.innerHTML = html;
  } catch (e) { fail(out, e); }
}

/* ---------------- LAB ---------------- */
let planeBytes = null, cmpCoverBytes = null, cmpStegoBytes = null, detBytes = null;
function setupLab() {
  wireDrop("planeDrop", "planeFile", async (f) => { planeBytes = await bytesOf(f); $("planeBtn").disabled = !planeBytes; });
  $("planeBtn").addEventListener("click", () => {
    try {
      const png = stg.bitPlane(planeBytes, parseInt($("planeChannel").value, 10), parseInt($("planePlane").value, 10));
      const img = $("planeImg");
      img.src = URL.createObjectURL(new Blob([toU8(png)], { type: "image/png" }));
      img.hidden = false;
    } catch (e) { fail($("planeImg").parentElement, e); }
  });

  wireDrop("cmpCoverDrop", "cmpCover", async (f) => { cmpCoverBytes = await bytesOf(f); $("cmpCompareBtn").disabled = !(cmpCoverBytes && cmpStegoBytes); });
  wireDrop("cmpStegoDrop", "cmpStego", async (f) => { cmpStegoBytes = await bytesOf(f); $("cmpCompareBtn").disabled = !(cmpCoverBytes && cmpStegoBytes); });
  $("cmpCompareBtn").addEventListener("click", () => {
    const out = $("cmpCompareOut"); spin(out, "Comparing…");
    defer(() => {
      try {
        const rate = stg.changeRate(cmpCoverBytes, cmpStegoBytes);
        const q = stg.quality(cmpCoverBytes, cmpStegoBytes);
        let html = statRow("Pixels changed", (rate * 100).toFixed(2) + "%") + statRow("PSNR", q.psnrDb.toFixed(1) + " dB") + statRow("SSIM", q.ssim.toFixed(4)) + statRow("MSE", q.mse.toFixed(3));
        try { const map = stg.changeMap(cmpCoverBytes, cmpStegoBytes); html += `<label>Change map</label><img class="render" src="${URL.createObjectURL(new Blob([toU8(map)], { type: "image/png" }))}" alt="" />`; } catch { /* size mismatch */ }
        out.innerHTML = html;
      } catch (e) { fail(out, e); }
    });
  });

  wireDrop("detDrop", "detCover", async (f) => { detBytes = await bytesOf(f); $("detBtn").disabled = !detBytes; });
  $("detBtn").addEventListener("click", () => {
    const out = $("detOut"); spin(out, "Estimating…");
    defer(() => {
      try {
        const d = stg.detectability($("detMethod").value, detBytes, parseInt($("detPayload").value, 10) || 0);
        out.innerHTML = banner(d.delta < 0.15, esc(d.verdict)) +
          statRow("Suspicion (clean)", (d.cleanConfidence * 100).toFixed(0) + "%") + statRow("Suspicion (with payload)", (d.stegoConfidence * 100).toFixed(0) + "%") +
          statRow("Increase", (d.delta * 100).toFixed(0) + "%") + statRow("PSNR", d.psnrDb.toFixed(1) + " dB");
      } catch (e) { fail(out, e); }
    });
  });

  $("doctorBtn").addEventListener("click", () => {
    const out = $("labDiagOut"); spin(out, "Testing every method…");
    defer(() => {
      try {
        const rs = stg.runSelfTest();
        const passed = rs.filter((r) => r.ok).length;
        out.innerHTML = banner(passed === rs.length, `${passed} of ${rs.length} methods passed`) +
          "<table>" + rs.map((r) => `<tr><td>${r.ok ? "✅" : "❌"} ${esc(r.methodId)}</td><td class="small">${esc(r.detail)}</td></tr>`).join("") + "</table>";
      } catch (e) { fail(out, e); }
    });
  });
  $("benchBtn").addEventListener("click", () => {
    const out = $("labDiagOut"); spin(out, "Benchmarking…");
    defer(() => {
      try {
        const b = stg.benchmarkKdf();
        out.innerHTML = banner(b.verdict !== "weak", esc(b.verdict)) +
          `<div class="small" style="margin:6px 0 10px">${esc(b.explanation)}</div>` +
          statRow("Time", b.millis.toFixed(0) + " ms") + statRow("Memory", (b.memoryKib / 1024).toFixed(0) + " MiB") + statRow("Iterations", String(b.iterations));
      } catch (e) { fail(out, e); }
    });
  });
}

/* ---------------- KEYS (Shamir secret sharing) ---------------- */
let keysFileBytes = null;
function setupKeys() {
  for (let n = 2; n <= 8; n++) {
    $("keysThreshold").add(new Option(`${n} shares`, n));
    $("keysShares").add(new Option(`${n} shares`, n));
  }
  $("keysThreshold").value = 2; $("keysShares").value = 3;
  $("keysThreshold").addEventListener("change", () => { if (+$("keysShares").value < +$("keysThreshold").value) $("keysShares").value = $("keysThreshold").value; });
  $("keysSeg").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-mode]"); if (!b) return;
    $("keysSeg").querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === b));
    $("keysSplit").hidden = b.dataset.mode !== "split";
    $("keysCombine").hidden = b.dataset.mode !== "combine";
  });
  $("keysType").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-t]"); if (!b) return;
    $("keysType").querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === b));
    const isText = b.dataset.t === "text";
    $("keysSecret").hidden = !isText;
    $("keysFileWrap").hidden = isText;
    refreshKeysSplitBtn();
  });
  wireDrop("keysFileDrop", "keysFile", async (f) => { keysFileBytes = { name: f.name, bytes: await bytesOf(f) }; refreshKeysSplitBtn(); });
  $("keysSecret").addEventListener("input", refreshKeysSplitBtn);
  $("keysCombineText").addEventListener("input", () => { $("keysCombineBtn").disabled = !$("keysCombineText").value.trim(); });
  $("keysSplitBtn").addEventListener("click", doKeysSplit);
  $("keysCombineBtn").addEventListener("click", doKeysCombine);
}
function keysUsingText() { return !$("keysSecret").hidden; }
function refreshKeysSplitBtn() { $("keysSplitBtn").disabled = keysUsingText() ? !$("keysSecret").value : !keysFileBytes; }
function doKeysSplit() {
  const out = $("keysSplitOut");
  const threshold = +$("keysThreshold").value, shares = Math.max(+$("keysShares").value, threshold);
  try {
    // Split the *typed* secret so a shared file recombines under its own name
    // rather than as anonymous bytes.
    const entry = keysUsingText()
      ? { text: $("keysSecret").value }
      : { files: [{ name: keysFileBytes.name, bytes: keysFileBytes.bytes }] };
    const list = stg.sssSplitSecret(entry, threshold, shares);
    out.innerHTML = `<div class="small" style="margin-bottom:8px">Any ${threshold} of ${shares} rebuild the secret.</div>` +
      list.map((s, i) => {
        const str = `${s.x}-${hex(s.y)}`;
        return `<div class="share-line"><div><span class="small">Share ${i + 1}</span><code>${esc(str)}</code></div><button class="ghost copy" data-v="${esc(str)}">Copy</button></div>`;
      }).join("");
    out.querySelectorAll("button.copy").forEach((b) => b.addEventListener("click", () => { navigator.clipboard?.writeText(b.dataset.v); b.textContent = "Copied"; setTimeout(() => b.textContent = "Copy", 1200); }));
  } catch (e) { fail(out, e); }
}
function parseShare(line) {
  const t = line.trim(), dash = t.indexOf("-");
  if (dash <= 0) return null;
  const x = parseInt(t.slice(0, dash), 10);
  const h = t.slice(dash + 1).trim();
  if (!Number.isInteger(x) || x < 1 || x > 255 || !h || h.length % 2) return null;
  const y = new Uint8Array(h.length / 2);
  for (let i = 0; i < y.length; i++) { const v = parseInt(h.substr(i * 2, 2), 16); if (Number.isNaN(v)) return null; y[i] = v; }
  return { x, y };
}
function doKeysCombine() {
  const out = $("keysCombineOut");
  try {
    const shares = $("keysCombineText").value.split("\n").map(parseShare).filter(Boolean);
    if (shares.length < 2) { out.innerHTML = banner(false, "Need at least 2 valid shares."); return; }
    // Restores whatever was split — a message, or a file under its own name.
    renderRevealed(out, stg.sssCombineSecret(shares));
  } catch (e) { fail(out, e); }
}

/* ---------------- CLEAN ---------------- */
let cleanBytes = null, cleanName = "file";
function setupClean() {
  wireDrop("cleanDrop", "cleanFile", async (f) => { cleanBytes = await bytesOf(f); cleanName = f.name; $("cleanBtn").disabled = !cleanBytes; });
  $("cleanBtn").addEventListener("click", () => {
    const out = $("cleanOut");
    try {
      const r = stg.sanitize(cleanBytes);
      const base = cleanName.replace(/\.[^.]+$/, "");
      const ext = r.format === "image" ? ".png" : (cleanName.match(/\.[^.]+$/)?.[0] || ".txt");
      download(r.cleaned, `${base}-clean${ext}`, r.format === "image" ? "image/png" : "text/plain");
      let html = banner(true, r.changed ? "🧼 Cleaned. Hidden payload destroyed." : "✅ Nothing hidden was found; copied as-is.");
      if (r.actions.length) html += "<ul class='small'>" + r.actions.map((a) => `<li>${esc(a)}</li>`).join("") + "</ul>";
      out.innerHTML = html;
    } catch (e) { fail(out, e); }
  });
}

boot().catch((e) => { document.querySelector("main").innerHTML = `<div class="card"><div class="result-banner bad">Failed to start engine: ${esc(e.message || e)}</div></div>`; });
if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
