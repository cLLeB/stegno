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

/* ---------------- Tabs ---------------- */
$("tabs").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-tab]");
  if (!b) return;
  document.querySelectorAll("nav.tabs button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "panel-" + b.dataset.tab));
});

/* ---------------- File drop helper ---------------- */
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

/* ---------------- Boot ---------------- */
let IMAGE_METHODS = [];
async function boot() {
  await init();
  const methods = stg.listMethods();
  $("engineInfo").textContent = `· engine v0.1 · ${methods.length} methods`;
  IMAGE_METHODS = methods.filter((m) => m.media === "Image");
  const sel = $("hideMethod");
  IMAGE_METHODS.forEach((m) => {
    const o = document.createElement("option");
    o.value = m.id; o.textContent = m.displayName;
    sel.appendChild(o);
  });
  setupHide(); setupReveal(); setupShare(); setupAnalyze(); setupClean();
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
  $("hideMethod").addEventListener("change", refreshCapacity);
  $("hideText").addEventListener("input", refreshHideBtn);
  $("hideBtn").addEventListener("click", doHide);
}
function refreshCapacity() {
  if (!hideCoverBytes) return;
  try {
    const cap = stg.capacity($("hideMethod").value, hideCoverBytes);
    $("capacityText").textContent = `Room for about ${cap.toLocaleString()} bytes.`;
  } catch (e) { $("capacityText").textContent = ""; }
}
function refreshHideBtn() {
  $("hideBtn").disabled = !(hideCoverBytes && $("hideText").value && $("hidePass").value);
}
function doHide() {
  const out = $("hideOut"); out.innerHTML = `<span class="spinner"></span>Hiding…`;
  setTimeout(() => {
    try {
      const stego = stg.embedAdvancedText(
        $("hideMethod").value, hideCoverBytes, $("hideText").value, $("hidePass").value,
        parseInt($("hideRobust").value, 10), $("hideCompress").checked
      );
      download(stego, "stego.png", "image/png");
      out.innerHTML = banner(true, `✅ Hidden in a ${(stego.length / 1024).toFixed(0)} KB image — download started.`);
    } catch (e) { fail(out, e); }
  }, 30);
}

/* ---------------- REVEAL ---------------- */
let revealBytes = null;
function setupReveal() {
  wireDrop("revealDrop", "revealFile", async (f) => { revealBytes = await bytesOf(f); $("revealBtn").disabled = !revealBytes; });
  $("revealBtn").addEventListener("click", () => {
    const out = $("revealOut"); out.innerHTML = `<span class="spinner"></span>Revealing…`;
    setTimeout(() => {
      try {
        const r = stg.extractAuto(revealBytes, $("revealPass").value);
        const rv = r.revealed;
        if (rv.kind === "none") { out.innerHTML = banner(false, "🔎 No hidden data found (or wrong password)."); return; }
        if (rv.kind === "text") {
          out.innerHTML = banner(true, `🔓 Revealed via <b>${esc(r.methodId)}</b>`) + `<pre>${esc(rv.text)}</pre>`;
        } else if (rv.kind === "file") {
          download(rv.bytes, rv.name);
          out.innerHTML = banner(true, `🔓 Recovered file <b>${esc(rv.name)}</b> via ${esc(r.methodId)} — download started.`);
        } else if (rv.kind === "files") {
          rv.files.forEach((f) => download(f.bytes, f.name));
          out.innerHTML = banner(true, `🔓 Recovered ${rv.files.length} files.`);
        }
      } catch (e) { fail(out, e); }
    }, 30);
  });
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
  const wrap = $("recipients");
  const div = document.createElement("div");
  div.className = "recip";
  div.innerHTML = `<div class="row">
    <input type="text" placeholder="Message for this person" class="r-msg" />
    <input type="password" placeholder="Their password" class="r-pass" />
    <button class="ghost r-del" title="Remove">✕</button></div>`;
  div.querySelector(".r-del").addEventListener("click", () => { div.remove(); refreshShareBtn(); });
  div.querySelectorAll("input").forEach((i) => i.addEventListener("input", refreshShareBtn));
  wrap.appendChild(div);
}
function currentRecipients() {
  return [...document.querySelectorAll("#recipients .recip")].map((d) => ({
    text: d.querySelector(".r-msg").value, passphrase: d.querySelector(".r-pass").value,
  })).filter((r) => r.text && r.passphrase);
}
function refreshShareBtn() { $("shareBtn").disabled = !(shareCoverBytes && currentRecipients().length >= 2); }
function doShare() {
  const out = $("shareOut"), recips = currentRecipients();
  out.innerHTML = `<span class="spinner"></span>Hiding ${recips.length} messages…`;
  setTimeout(() => {
    try {
      const stego = stg.embedMultiText(shareCoverBytes, recips);
      download(stego, "shared.png", "image/png");
      out.innerHTML = banner(true, `✅ Hid ${recips.length} separate messages in one photo — each opens only with its own password.`);
    } catch (e) { fail(out, e); }
  }, 30);
}

/* ---------------- INSPECT ---------------- */
let analyzeBytes = null;
function setupAnalyze() {
  wireDrop("analyzeDrop", "analyzeFile", async (f) => { analyzeBytes = await bytesOf(f); $("analyzeBtn").disabled = !analyzeBytes; });
  $("analyzeBtn").addEventListener("click", doAnalyze);
  $("planeBtn").addEventListener("click", () => {
    try {
      const png = stg.bitPlane(analyzeBytes, parseInt($("planeChannel").value, 10), parseInt($("planePlane").value, 10));
      const img = $("planeImg");
      img.src = URL.createObjectURL(new Blob([toU8(png)], { type: "image/png" }));
      img.hidden = false;
    } catch (e) { fail($("analyzeOut"), e); }
  });
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
    html += `<label>Likely method</label><table>`;
    guesses.slice(0, 4).forEach((g) => { html += `<tr><td>${(g.confidence * 100).toFixed(0)}%</td><td>${esc(g.label)}</td></tr>`; });
    html += "</table>";
    out.innerHTML = html;
    $("planeCard").style.display = ["png", "jpeg", "gif"].includes(scan.format) ? "block" : "none";
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
      let html = banner(true, r.changed ? "🧼 Cleaned — any hidden payload destroyed." : "✅ Nothing hidden was found; copied as-is.");
      if (r.actions.length) html += "<ul class='small'>" + r.actions.map((a) => `<li>${esc(a)}</li>`).join("") + "</ul>";
      out.innerHTML = html;
    } catch (e) { fail(out, e); }
  });
}

boot().catch((e) => { document.querySelector("main").innerHTML = `<div class="card"><div class="result-banner bad">Failed to start engine: ${esc(e.message || e)}</div></div>`; });

/* Service worker for offline use */
if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
