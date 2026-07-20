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
function esc(s) { return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
function banner(ok, html) { return `<div class="result-banner ${ok ? "ok" : "bad"}">${html}</div>`; }
function fail(el, e) { el.innerHTML = `<div class="result-banner bad">⚠️ ${esc(e.message || e)}</div>`; }
function spin(el, label) { el.innerHTML = `<span class="spinner"></span>${esc(label)}`; }
/** Run heavy work off the paint frame so the spinner shows. */
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

/* ---------------- Tabs & segmented controls ---------------- */
$("tabs").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-tab]");
  if (!b) return;
  document.querySelectorAll("nav.tabs button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "panel-" + b.dataset.tab));
});
function wireSeg(segId, onMode) {
  const seg = $(segId);
  seg.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-mode]");
    if (!b) return;
    seg.querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === b));
    onMode(b.dataset.mode);
  });
}

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
function wireDropMulti(dropId, inputId, onFiles) {
  const drop = $(dropId), input = $(inputId);
  drop.addEventListener("click", () => input.click());
  input.addEventListener("change", async () => {
    const files = [...input.files];
    if (!files.length) return;
    drop.classList.add("has");
    drop.innerHTML = `<span class="big">✅</span>${files.length} photos selected`;
    onFiles(await Promise.all(files.map(bytesOf)));
  });
}

/* ---------------- Boot ---------------- */
let IMAGE_METHODS = [];
function fillMethods(selectId) {
  const sel = $(selectId);
  IMAGE_METHODS.forEach((m) => {
    const o = document.createElement("option");
    o.value = m.id; o.textContent = m.displayName;
    sel.appendChild(o);
  });
  const seeded = IMAGE_METHODS.find((m) => m.id === "lsb_seeded");
  if (seeded) sel.value = seeded.id;
}
async function boot() {
  await init();
  const methods = stg.listMethods();
  $("engineInfo").textContent = `· engine v0.1 · ${methods.length} methods`;
  IMAGE_METHODS = methods.filter((m) => m.media === "Image");
  ["hideMethod", "splitMethod", "splitRevealMethod", "detMethod"].forEach(fillMethods);
  setupHide(); setupReveal(); setupShare(); setupSplit(); setupKeys();
  setupAnalyze(); setupLab(); setupClean();
}

/* ---------------- HIDE ---------------- */
let hideCoverBytes = null;
function setupHide() {
  wireDrop("hideDrop", "hideCover", async (f) => { hideCoverBytes = await bytesOf(f); refreshCapacity(); refreshHideBtn(); });
  $("hidePass").addEventListener("input", (e) => {
    const s = stg.passphraseStrength(e.target.value);
    const colors = ["var(--bad)", "var(--bad)", "var(--warn)", "var(--ok)", "var(--ok)"];
    $("strengthBar").style.width = ((s.score + 1) / 5 * 100) + "%";
    $("strengthBar").style.background = colors[s.score];
    const labels = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];
    $("strengthText").innerHTML = e.target.value
      ? `<b>${labels[s.score]}</b> · ~${s.entropyBits.toFixed(0)} bits · cracks in ${esc(s.crackTimeDisplay)}${s.warning ? ` · <span class="err">${esc(s.warning)}</span>` : ""}`
      : "Strength appears as you type.";
    refreshHideBtn();
  });
  $("hideDecoy").addEventListener("change", (e) => {
    const on = e.target.checked;
    $("decoyFields").hidden = !on;
    $("hideAdvanced").style.display = on ? "none" : "";
    $("hideToughRow").style.display = on ? "none" : "";
    refreshCapacity(); refreshHideBtn();
  });
  ["hideDecoyText", "hideDecoyPass"].forEach((id) => $(id).addEventListener("input", refreshHideBtn));
  $("hideMethod").addEventListener("change", refreshCapacity);
  $("hideText").addEventListener("input", refreshHideBtn);
  $("planBtn").addEventListener("click", doPlan);
  $("hideBtn").addEventListener("click", doHide);
}
function refreshCapacity() {
  if (!hideCoverBytes) return;
  try {
    const cap = $("hideDecoy").checked ? stg.decoyCapacity(hideCoverBytes) : stg.capacity($("hideMethod").value, hideCoverBytes);
    $("capacityText").textContent = `Room for about ${cap.toLocaleString()} bytes${$("hideDecoy").checked ? " per slot" : ""}.`;
  } catch { $("capacityText").textContent = ""; }
}
function refreshHideBtn() {
  const decoy = $("hideDecoy").checked;
  const base = hideCoverBytes && $("hideText").value && $("hidePass").value;
  $("hideBtn").disabled = !(base && (!decoy || ($("hideDecoyText").value && $("hideDecoyPass").value)));
}
function doPlan() {
  if (!hideCoverBytes) return;
  const out = $("planOut");
  try {
    const recs = stg.planEmbedding(hideCoverBytes, new TextEncoder().encode($("hideText").value).length);
    const byId = Object.fromEntries(IMAGE_METHODS.map((m) => [m.id, m.displayName]));
    out.innerHTML = recs.slice(0, 4).map((r) =>
      `<button class="rec" data-id="${esc(r.methodId)}">
        <b>${r.fits ? "✅" : "⚠️"} ${esc(byId[r.methodId] || r.methodId)}</b>
        <span class="tag ${r.stealthTier >= 2 ? "ok" : r.stealthTier === 1 ? "warn" : "bad"}">stealth ${r.stealthTier}/3</span>
        <span class="small">${esc(r.note)}</span></button>`).join("");
    out.querySelectorAll("button.rec").forEach((b) => b.addEventListener("click", () => {
      $("hideMethod").value = b.dataset.id; refreshCapacity(); out.innerHTML = "";
    }));
  } catch (e) { fail(out, e); }
}
function doHide() {
  const out = $("hideOut"); spin(out, "Hiding…");
  const decoy = $("hideDecoy").checked;
  defer(() => {
    try {
      const stego = decoy
        ? stg.embedWithDecoyText(hideCoverBytes, $("hideText").value, $("hidePass").value, $("hideDecoyText").value, $("hideDecoyPass").value)
        : stg.embedAdvancedText($("hideMethod").value, hideCoverBytes, $("hideText").value, $("hidePass").value, parseInt($("hideRobust").value, 10), $("hideCompress").checked);
      download(stego, "stego.png", "image/png");
      out.innerHTML = banner(true, `✅ Hidden in a ${(stego.length / 1024).toFixed(0)} KB image — download started.`);
    } catch (e) { fail(out, e); }
  });
}

/* ---------------- REVEAL ---------------- */
let revealBytes = null;
function setupReveal() {
  wireDrop("revealDrop", "revealFile", async (f) => { revealBytes = await bytesOf(f); $("revealBtn").disabled = !revealBytes; });
  $("revealBtn").addEventListener("click", () => {
    const out = $("revealOut"); spin(out, "Revealing…");
    defer(() => {
      try { renderRevealed(out, stg.extractAuto(revealBytes, $("revealPass").value)); }
      catch (e) { fail(out, e); }
    });
  });
}
function renderRevealed(out, r) {
  const rv = r.revealed;
  if (rv.kind === "none") { out.innerHTML = banner(false, "🔎 No hidden data found (or wrong password)."); return; }
  if (rv.kind === "text") {
    out.innerHTML = banner(true, `🔓 Revealed via <b>${esc(r.methodId || "split")}</b>`) + `<pre>${esc(rv.text)}</pre>`;
  } else if (rv.kind === "file") {
    download(rv.bytes, rv.name);
    out.innerHTML = banner(true, `🔓 Recovered file <b>${esc(rv.name)}</b> — download started.`);
  } else if (rv.kind === "files") {
    rv.files.forEach((f) => download(f.bytes, f.name));
    out.innerHTML = banner(true, `🔓 Recovered ${rv.files.length} files.`);
  }
}

/* ---------------- SHARE (multi-recipient) ---------------- */
let shareCoverBytes = null;
function setupShare() {
  wireDrop("shareDrop", "shareCover", async (f) => { shareCoverBytes = await bytesOf(f); refreshShareBtn(); });
  $("addRecip").addEventListener("click", () => addRecipRow());
  addRecipRow(); addRecipRow();
  $("shareBtn").addEventListener("click", doShare);
}
function addRecipRow() {
  const div = document.createElement("div");
  div.className = "recip";
  div.innerHTML = `<div class="row">
    <input type="text" placeholder="Message for this person" class="r-msg" />
    <input type="password" placeholder="Their password" class="r-pass" />
    <button class="ghost r-del" title="Remove">✕</button></div>`;
  div.querySelector(".r-del").addEventListener("click", () => { div.remove(); refreshShareBtn(); });
  div.querySelectorAll("input").forEach((i) => i.addEventListener("input", refreshShareBtn));
  $("recipients").appendChild(div);
}
function currentRecipients() {
  return [...document.querySelectorAll("#recipients .recip")].map((d) => ({
    text: d.querySelector(".r-msg").value, passphrase: d.querySelector(".r-pass").value,
  })).filter((r) => r.text && r.passphrase);
}
function refreshShareBtn() { $("shareBtn").disabled = !(shareCoverBytes && currentRecipients().length >= 2); }
function doShare() {
  const out = $("shareOut"), recips = currentRecipients();
  spin(out, `Hiding ${recips.length} messages…`);
  defer(() => {
    try {
      const stego = stg.embedMultiText(shareCoverBytes, recips);
      download(stego, "shared.png", "image/png");
      out.innerHTML = banner(true, `✅ Hid ${recips.length} separate messages in one photo — each opens only with its own password.`);
    } catch (e) { fail(out, e); }
  });
}

/* ---------------- SPLIT (across covers) ---------------- */
let splitHideBytes = [], splitRevealBytes = [];
function setupSplit() {
  wireSeg("splitSeg", (m) => { $("splitHide").hidden = m !== "hide"; $("splitReveal").hidden = m !== "reveal"; });
  wireDropMulti("splitHideDrop", "splitHideFiles", (arr) => { splitHideBytes = arr; refreshSplitHideBtn(); });
  wireDropMulti("splitRevealDrop", "splitRevealFiles", (arr) => { splitRevealBytes = arr; refreshSplitRevealBtn(); });
  ["splitText", "splitPass"].forEach((id) => $(id).addEventListener("input", refreshSplitHideBtn));
  $("splitRevealPass").addEventListener("input", refreshSplitRevealBtn);
  $("splitHideBtn").addEventListener("click", doSplitHide);
  $("splitRevealBtn").addEventListener("click", doSplitReveal);
}
function refreshSplitHideBtn() { $("splitHideBtn").disabled = !(splitHideBytes.length >= 2 && $("splitText").value && $("splitPass").value); }
function refreshSplitRevealBtn() { $("splitRevealBtn").disabled = !(splitRevealBytes.length >= 2 && $("splitRevealPass").value); }
function doSplitHide() {
  const out = $("splitHideOut"); spin(out, "Splitting…");
  defer(() => {
    try {
      const parts = stg.embedSplitText($("splitMethod").value, splitHideBytes, $("splitText").value, $("splitPass").value);
      parts.forEach((p, i) => download(p, `part${i + 1}.png`, "image/png"));
      out.innerHTML = banner(true, `✅ Saved ${parts.length} photos — all are needed to rebuild.`);
    } catch (e) { fail(out, e); }
  });
}
function doSplitReveal() {
  const out = $("splitRevealOut"); spin(out, "Rebuilding…");
  defer(() => {
    try {
      const r = stg.extractSplit($("splitRevealMethod").value, splitRevealBytes, $("splitRevealPass").value);
      if (r.kind === "none") { out.innerHTML = banner(false, "🔎 Nothing found (wrong password, method, or missing a photo)."); return; }
      renderRevealed(out, { methodId: "split", revealed: r });
    } catch (e) { fail(out, e); }
  });
}

/* ---------------- KEYS (Shamir secret sharing) ---------------- */
function setupKeys() {
  for (let n = 2; n <= 8; n++) {
    $("keysThreshold").add(new Option(`${n} shares`, n));
    $("keysShares").add(new Option(`${n} shares`, n));
  }
  $("keysThreshold").value = 2; $("keysShares").value = 3;
  $("keysThreshold").addEventListener("change", () => {
    if (+$("keysShares").value < +$("keysThreshold").value) $("keysShares").value = $("keysThreshold").value;
  });
  wireSeg("keysSeg", (m) => { $("keysSplit").hidden = m !== "split"; $("keysCombine").hidden = m !== "combine"; });
  $("keysSecret").addEventListener("input", () => { $("keysSplitBtn").disabled = !$("keysSecret").value; });
  $("keysCombineText").addEventListener("input", () => { $("keysCombineBtn").disabled = !$("keysCombineText").value.trim(); });
  $("keysSplitBtn").addEventListener("click", doKeysSplit);
  $("keysCombineBtn").addEventListener("click", doKeysCombine);
}
function doKeysSplit() {
  const out = $("keysSplitOut");
  const threshold = +$("keysThreshold").value, shares = Math.max(+$("keysShares").value, threshold);
  try {
    const secret = new TextEncoder().encode($("keysSecret").value);
    const list = stg.sssSplit(secret, threshold, shares);
    out.innerHTML = `<div class="small" style="margin-bottom:8px">Give each person one share. Any ${threshold} of ${shares} rebuild the secret.</div>` +
      list.map((s, i) => {
        const str = `${s.x}-${hex(s.y)}`;
        return `<div class="share-line"><div><span class="small">Share ${i + 1}</span><code>${esc(str)}</code></div><button class="ghost copy" data-v="${esc(str)}">Copy</button></div>`;
      }).join("");
    out.querySelectorAll("button.copy").forEach((b) => b.addEventListener("click", () => {
      navigator.clipboard?.writeText(b.dataset.v); b.textContent = "Copied"; setTimeout(() => b.textContent = "Copy", 1200);
    }));
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
    const bytes = stg.sssCombine(shares);
    out.innerHTML = banner(true, "🔓 Reconstructed the secret.") + `<pre>${esc(new TextDecoder().decode(toU8(bytes)))}</pre>`;
  } catch (e) { fail(out, e); }
}

/* ---------------- INSPECT ---------------- */
let analyzeBytes = null;
function setupAnalyze() {
  wireDrop("analyzeDrop", "analyzeFile", async (f) => { analyzeBytes = await bytesOf(f); $("analyzeBtn").disabled = !analyzeBytes; });
  $("analyzeBtn").addEventListener("click", doAnalyze);
}
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
      html += `<label>Statistical LSB analysis</label>
        <div class="small" style="margin-bottom:4px">Overall likelihood of hidden data: <b>${(d.mlConfidence * 100).toFixed(0)}%</b></div>` +
        statRow("Chi-square p", d.chiSquareP.toFixed(3)) + statRow("RS regularity gap", d.rsRegularityGap.toFixed(3)) +
        statRow("Sample-pair rate", d.samplePairRate.toFixed(3));
    } catch { /* not an image — skip */ }
    out.innerHTML = html;
  } catch (e) { fail(out, e); }
}
function statRow(k, v) { return `<div class="stat"><span>${esc(k)}</span><b>${esc(v)}</b></div>`; }

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

  wireDrop("cmpCoverDrop", "cmpCover", async (f) => { cmpCoverBytes = await bytesOf(f); $("cmpBtn").disabled = !(cmpCoverBytes && cmpStegoBytes); });
  wireDrop("cmpStegoDrop", "cmpStego", async (f) => { cmpStegoBytes = await bytesOf(f); $("cmpBtn").disabled = !(cmpCoverBytes && cmpStegoBytes); });
  $("cmpBtn").addEventListener("click", () => {
    const out = $("cmpOut"); spin(out, "Comparing…");
    defer(() => {
      try {
        const rate = stg.changeRate(cmpCoverBytes, cmpStegoBytes);
        const q = stg.quality(cmpCoverBytes, cmpStegoBytes);
        let html = statRow("Pixels changed", (rate * 100).toFixed(2) + "%") + statRow("PSNR", q.psnrDb.toFixed(1) + " dB") +
          statRow("SSIM", q.ssim.toFixed(4)) + statRow("MSE", q.mse.toFixed(3));
        try {
          const map = stg.changeMap(cmpCoverBytes, cmpStegoBytes);
          html += `<label>Change map</label><img class="render" src="${URL.createObjectURL(new Blob([toU8(map)], { type: "image/png" }))}" alt="" />`;
        } catch { /* size mismatch */ }
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
          statRow("Suspicion (clean)", (d.cleanConfidence * 100).toFixed(0) + "%") +
          statRow("Suspicion (with payload)", (d.stegoConfidence * 100).toFixed(0) + "%") +
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
        out.innerHTML = banner(true, esc(b.verdict)) +
          statRow("Time", b.millis.toFixed(0) + " ms") + statRow("Memory", (b.memoryKib / 1024).toFixed(0) + " MiB") +
          statRow("Iterations", String(b.iterations));
      } catch (e) { fail(out, e); }
    });
  });
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
      let html = banner(true, r.changed ? "🧼 Cleaned — any hidden payload destroyed." : "✅ Nothing hidden was found; copied as-is.");
      if (r.actions.length) html += "<ul class='small'>" + r.actions.map((a) => `<li>${esc(a)}</li>`).join("") + "</ul>";
      out.innerHTML = html;
    } catch (e) { fail(out, e); }
  });
}

boot().catch((e) => { document.querySelector("main").innerHTML = `<div class="card"><div class="result-banner bad">Failed to start engine: ${esc(e.message || e)}</div></div>`; });

/* Service worker for offline use */
if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
