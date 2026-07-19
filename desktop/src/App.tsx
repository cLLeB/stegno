import { useEffect, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  capacity,
  decoyCapacity,
  detectLsb,
  embedSecret,
  embedSplit,
  embedWithDecoy,
  extract,
  extractSplit,
  listMethods,
  quality,
  readFile,
  writeFile,
  type Detection,
  type MethodInfo,
  type Quality,
  type Revealed,
} from "./api";

type Tab = "hide" | "extract" | "analyze";
type SecretMode = "text" | "file";

function textBytes(value: string): number {
  return new TextEncoder().encode(value).length;
}

/// Output file extension for a method. Most image methods emit PNG, but a few
/// produce a different container (e.g. jpeg_jsteg emits a real JPEG), so the
/// method id takes precedence over the carrier medium.
function outputExtension(methodId: string, media: string, originalName?: string): string {
  switch (methodId) {
    case "jpeg_jsteg":
    case "jpeg_f5":
    case "jpeg_outguess":
    case "jpeg_mc":
      return "jpg";
  }
  switch (media) {
    case "Image":
      return "png";
    case "Audio":
      return "wav";
    case "Text":
      return "txt";
    default:
      if (originalName && originalName.includes(".")) {
        return originalName.split(".").pop() || "bin";
      }
      return "bin";
  }
}

function autoSelectMethod(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase() ?? "";
  switch (ext) {
    case "jpg":
    case "jpeg":
      return "jpeg_f5"; // Best for JPEGs
    case "png":
    case "bmp":
    case "webp":
      return "lsb_image"; // Robust for lossless images
    case "wav":
      return "wav_lsb";
    case "txt":
      return "whitespace";
    default:
      return "append_eof"; // Universal fallback
  }
}

export default function App() {
  const [tab, setTab] = useState<Tab>("hide");
  const [methods, setMethods] = useState<MethodInfo[]>([]);
  const [methodId, setMethodId] = useState<string>("lsb_image");

  useEffect(() => {
    listMethods()
      .then((ms) => {
        setMethods(ms);
        if (ms.length > 0 && !ms.some((m) => m.id === methodId)) {
          setMethodId(ms[0].id);
        }
      })
      .catch(() => setMethods([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const method = methods.find((m) => m.id === methodId);

  return (
    <div className="app">
      <header>
        <h1>Stegno</h1>
        <p className="sub">Offline steganography · {methods.length} methods</p>
      </header>

      {/* Global method selector removed; handled inside tabs now */}

      <div className="tabs">
        <button className={tab === "hide" ? "on" : ""} onClick={() => setTab("hide")}>
          Hide
        </button>
        <button className={tab === "extract" ? "on" : ""} onClick={() => setTab("extract")}>
          Extract
        </button>
        <button className={tab === "analyze" ? "on" : ""} onClick={() => setTab("analyze")}>
          Analyze
        </button>
      </div>

      {methods.length === 0 && <p className="warn">Engine not available.</p>}
      {tab === "hide" && <HideTab methodId={methodId} media={method?.media ?? "File"} setMethodId={setMethodId} methods={methods} />}
      {tab === "extract" && <ExtractTab methodId={methodId} setMethodId={setMethodId} methods={methods} />}
      {tab === "analyze" && <AnalyzeTab />}

      <footer>Argon2id + AES-256-GCM · nothing leaves this device.</footer>
    </div>
  );
}

interface HideTabProps {
  methodId: string;
  media: string;
  setMethodId: (id: string) => void;
  methods: MethodInfo[];
}

function HideTab({ methodId, media, setMethodId, methods }: HideTabProps) {
  const [covers, setCovers] = useState<{ name: string; bytes: number[] }[]>([]);
  const cover = covers.length > 0 ? covers[0].bytes : null;
  const [cap, setCap] = useState<number | null>(null);
  
  const [splitMode, setSplitMode] = useState(false);
  const [realMode, setRealMode] = useState<SecretMode>("text");
  const [realText, setRealText] = useState("");
  const [realFiles, setRealFiles] = useState<{ name: string; bytes: number[] }[]>([]);
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  
  // Decoy mode: hide a second "fake" message under a different password.
  const [decoy, setDecoy] = useState(false);
  const [decoyMode, setDecoyMode] = useState<SecretMode>("text");
  const [decoyText, setDecoyText] = useState("");
  const [decoyFiles, setDecoyFiles] = useState<{ name: string; bytes: number[] }[]>([]);
  const [decoyPass, setDecoyPass] = useState("");
  
  const [showAdvanced, setShowAdvanced] = useState(false);
  const currentMethodInfo = methods.find(m => m.id === methodId);

  useEffect(() => {
    if (covers.length === 0) {
      setCap(null);
      return;
    }
    if (splitMode) {
      Promise.all(covers.map(c => capacity(methodId, c.bytes)))
        .then(caps => setCap(Math.min(...caps) * covers.length))
        .catch(() => setCap(null));
      return;
    }
    const p = decoy ? decoyCapacity(covers[0].bytes) : capacity(methodId, covers[0].bytes);
    p.then(setCap).catch(() => setCap(null));
  }, [covers, methodId, decoy, splitMode]);

  async function pickCover() {
    const paths = await open({ multiple: splitMode });
    if (!paths) return;
    const pathsArr = Array.isArray(paths) ? paths : [paths];
    const results = await Promise.all(
      pathsArr.map(async (p) => ({
        name: p.split(/[\\/]/).pop() ?? "cover",
        bytes: await readFile(p),
      }))
    );
    setCovers(results);
    setMsg(null);
    setErr(null);
    if (results.length > 0) {
      setMethodId(autoSelectMethod(results[0].name));
    }
  }

  async function pickRealFile() {
    const paths = await open({ multiple: true });
    if (!paths) return;
    const pathsArr = Array.isArray(paths) ? paths : [paths];
    const results = await Promise.all(
      pathsArr.map(async (p) => ({
        name: p.split(/[\\/]/).pop() ?? "file",
        bytes: await readFile(p),
      }))
    );
    setRealFiles(results);
  }

  async function pickDecoyFile() {
    const paths = await open({ multiple: true });
    if (!paths) return;
    const pathsArr = Array.isArray(paths) ? paths : [paths];
    const results = await Promise.all(
      pathsArr.map(async (p) => ({
        name: p.split(/[\\/]/).pop() ?? "file",
        bytes: await readFile(p),
      }))
    );
    setDecoyFiles(results);
  }

  async function doEmbed() {
    if (covers.length === 0 || !pass) return;
    setBusy(true);
    setMsg(null);
    setErr(null);
    try {
      if (splitMode) {
        const secretInput = realMode === "text"
          ? { kind: "text" as const, text: realText }
          : { kind: "files" as const, files: realFiles };
        const outList = await embedSplit(methodId, covers.map(c => c.bytes), secretInput, pass);
        
        for (let i = 0; i < outList.length; i++) {
          const out = outList[i];
          const ext = outputExtension(methodId, media, covers[i]?.name);
          const path = await save({
            defaultPath: `stego_part${i + 1}.${ext}`,
            filters: [{ name: ext.toUpperCase(), extensions: [ext] }],
          });
          if (typeof path === "string") {
            await writeFile(path, out);
          }
        }
        setMsg(`Saved ${outList.length} split files.`);
      } else {
        const secretInput = realMode === "text"
          ? { kind: "text" as const, text: realText }
          : realFiles.length === 1
            ? { kind: "file" as const, name: realFiles[0].name, bytes: realFiles[0].bytes }
            : { kind: "files" as const, files: realFiles };
            
        let out;
        if (decoy) {
          const decoyInput = decoyMode === "text"
            ? { kind: "text" as const, text: decoyText }
            : decoyFiles.length === 1
              ? { kind: "file" as const, name: decoyFiles[0].name, bytes: decoyFiles[0].bytes }
              : { kind: "files" as const, files: decoyFiles };
          out = await embedWithDecoy(cover!, secretInput, pass, decoyInput, decoyPass);
        } else {
          // If we have single file or text, embedSecret handles it natively via api.ts wrapper
          out = await embedSecret(methodId, cover!, secretInput, pass);
        }
        
        const ext = decoy ? "png" : outputExtension(methodId, media, covers[0]?.name);
        const path = await save({
          defaultPath: `stego.${ext}`,
          filters: [{ name: ext.toUpperCase(), extensions: [ext] }],
        });
        if (typeof path === "string") {
          await writeFile(path, out);
          setMsg(`Saved ${out.length.toLocaleString()} bytes → ${path}`);
        }
      }
    } catch (e) {
      setErr(String(e));
    }
    setBusy(false);
  }

  const realSize = realMode === "text" ? textBytes(realText) : realFiles.reduce((acc, f) => acc + f.bytes.length, 0);
  const decoySize = decoyMode === "text" ? textBytes(decoyText) : decoyFiles.reduce((acc, f) => acc + f.bytes.length, 0);
  const realOverflow = cap != null ? Math.max(0, realSize - cap) : 0;
  const decoyOverflow = cap != null ? Math.max(0, decoySize - cap) : 0;
  const withinCapacity = cap == null || (realOverflow === 0 && (!decoy || decoyOverflow === 0));
  const canEmbed =
    !busy &&
    covers.length > 0 &&
    !!pass &&
    withinCapacity &&
    (decoy
      ? (realMode === "text" ? realText.length > 0 : realFiles.length > 0) &&
        (decoyMode === "text" ? decoyText.length > 0 : decoyFiles.length > 0) &&
        decoyPass.length > 0 &&
        decoyPass !== pass
      : realMode === "text"
        ? realText.length > 0
        : realFiles.length > 0);

  return (
    <div className="panel">
      <label className="decoy-toggle">
        <input type="checkbox" checked={splitMode} onChange={(e) => { 
          setSplitMode(e.target.checked); 
          if (e.target.checked) setDecoy(false); 
          setCovers([]); 
        }} />
        Split across multiple covers
      </label>
      <label className="decoy-toggle">
        <input type="checkbox" checked={decoy} onChange={(e) => { 
          setDecoy(e.target.checked); 
          if (e.target.checked) setSplitMode(false); 
          setCovers([]); 
        }} />
        Add a decoy message
      </label>
      
      {splitMode && (
        <p className="hint">
          Splits the secret into chunks and embeds them across multiple covers. You must provide all resulting files to extract the secret later.
        </p>
      )}
      {decoy && (
        <p className="hint">
          Hides two messages in one photo. The real password reveals the real message; the
          decoy password reveals a harmless fake — so you can safely hand over the decoy
          password if forced. (Saved as a PNG photo.)
        </p>
      )}

      <button className="picker" onClick={pickCover}>
        {covers.length > 0 
          ? `Covers: ${covers.length} selected (${covers.map(c => c.name).join(", ")})` 
          : splitMode ? "Choose cover files…" : "Choose cover file…"}
      </button>

      {covers.length > 0 && currentMethodInfo && !showAdvanced && (
        <p className="ok" style={{ margin: "4px 0 0 0", fontSize: "0.9rem" }}>
          ✓ Auto-selected best method for {currentMethodInfo.media.toUpperCase()} files ({currentMethodInfo.displayName})
        </p>
      )}

      {covers.length > 0 && (
        <div style={{ marginTop: "8px" }}>
          <button 
            className="link-button" 
            style={{ fontSize: "0.85rem", padding: 0, background: "none", border: "none", color: "#646cff", cursor: "pointer", textDecoration: "underline" }}
            onClick={() => setShowAdvanced(!showAdvanced)}
          >
            {showAdvanced ? "Hide Advanced Settings" : "Advanced Settings / Manual Override"}
          </button>
          
          {showAdvanced && (
            <label className="method" style={{ marginTop: "12px", display: "flex", flexDirection: "column", gap: "4px", fontSize: "0.9rem" }}>
              <span>Override Steganography Method</span>
              <select value={methodId} onChange={(e) => setMethodId(e.target.value)} style={{ padding: "8px", borderRadius: "4px" }}>
                {methods.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.displayName} · {m.media}
                  </option>
                ))}
              </select>
            </label>
          )}
        </div>
      )}

      {cap !== null && (
        <p className="cap">
          {splitMode ? "Approximate Split Capacity" : decoy ? "Capacity per message" : "Capacity"}: ~{cap.toLocaleString()} bytes
        </p>
      )}
      {cap !== null && !decoy && realOverflow > 0 && (
        <p className="warn">Secret is {realOverflow.toLocaleString()} bytes over capacity.</p>
      )}
      {cap !== null && decoy && realOverflow > 0 && (
        <p className="warn">Real secret is {realOverflow.toLocaleString()} bytes over capacity.</p>
      )}
      {cap !== null && decoy && decoyOverflow > 0 && (
        <p className="warn">Decoy secret is {decoyOverflow.toLocaleString()} bytes over capacity.</p>
      )}

      {!decoy ? (
        <>
          <div className="seg">
            <button className={realMode === "text" ? "on" : ""} onClick={() => setRealMode("text")}>
              Text
            </button>
            <button
              className={realMode === "file" ? "on" : ""}
              onClick={() => setRealMode("file")}
              disabled={covers.length === 0}
            >
              File
            </button>
          </div>

          {realMode === "text" ? (
            <textarea
              placeholder="Secret message…"
              value={realText}
              onChange={(e) => setRealText(e.target.value)}
              rows={4}
            />
          ) : (
            <button className="picker" onClick={pickRealFile}>
              {realFiles.length > 0
                ? `${realFiles.length} file(s) selected (${realFiles.map(f => f.name).join(", ")})`
                : "Choose secret file(s)…"}
            </button>
          )}

          <input
            type="password"
            placeholder="Passphrase"
            value={pass}
            onChange={(e) => setPass(e.target.value)}
          />
        </>
      ) : (
        <>
          <p className="section">Real secret</p>
          <div className="seg">
            <button className={realMode === "text" ? "on" : ""} onClick={() => setRealMode("text")}>
              Text
            </button>
            <button
              className={realMode === "file" ? "on" : ""}
              onClick={() => setRealMode("file")}
              disabled={covers.length === 0}
            >
              File
            </button>
          </div>

          {realMode === "text" ? (
            <textarea
              placeholder="Real message…"
              value={realText}
              onChange={(e) => setRealText(e.target.value)}
              rows={4}
            />
          ) : (
            <button className="picker" onClick={pickRealFile}>
              {realFiles.length > 0
                ? `${realFiles.length} file(s) selected (${realFiles.map(f => f.name).join(", ")})`
                : "Choose real secret file(s)…"}
            </button>
          )}

          <input
            type="password"
            placeholder="Real password"
            value={pass}
            onChange={(e) => setPass(e.target.value)}
          />

          <p className="section">Decoy secret</p>
          <div className="seg">
            <button className={decoyMode === "text" ? "on" : ""} onClick={() => setDecoyMode("text")}>
              Text
            </button>
            <button
              className={decoyMode === "file" ? "on" : ""}
              onClick={() => setDecoyMode("file")}
              disabled={covers.length === 0}
            >
              File
            </button>
          </div>

          {decoyMode === "text" ? (
            <textarea
              placeholder="Decoy message (the fake one)…"
              value={decoyText}
              onChange={(e) => setDecoyText(e.target.value)}
              rows={3}
            />
          ) : (
            <button className="picker" onClick={pickDecoyFile}>
              {decoyFiles.length > 0
                ? `${decoyFiles.length} file(s) selected (${decoyFiles.map(f => f.name).join(", ")})`
                : "Choose decoy file(s)…"}
            </button>
          )}

          <input
            type="password"
            placeholder="Decoy password (must differ from the real one)"
            value={decoyPass}
            onChange={(e) => setDecoyPass(e.target.value)}
          />
        </>
      )}

      <button className="primary" disabled={!canEmbed} onClick={doEmbed}>
        {busy ? "Embedding…" : "Hide & save"}
      </button>

      {msg && <p className="ok">{msg}</p>}
      {err && <p className="err">{err}</p>}
    </div>
  );
}

/**
 * Plain-language verdict using all three metrics:
 *   samplePairRate  — SPA embedding-rate estimate (0=clean, 1=fully embedded)
 *   rsRegularityGap — RS gap (R−S)/(R+S): HIGH gap = clean, LOW/negative = suspicious
 *   chiSquareP      — Chi-square p-value (only fires on heavy sequential LSB replacement)
 *
 * RS gap is the most reliable indicator for real camera photos.
 * SPA rate gives an embedding-rate estimate but over-fires on camera AI processing.
 * Chi-square only triggers on synthetic/cartoon images with sequential lsb_image embedding.
 */
function suspicionVerdict(d: Detection): { text: string; cls: string } {
  const rate = d.samplePairRate;
  const gap  = d.rsRegularityGap;  // high (>0.3) = clean; low/negative = suspicious
  const chi  = d.chiSquareP;

  // Count how many independent tests flag suspicious:
  const spaFlagged  = rate >= 0.20;          // SPA reports ≥20% embedding rate
  const rsFlagged   = gap  <  0.15;          // RS gap collapsed — regularity eroded
  const chiFlagged  = chi  >= 0.85;          // Chi-square p ≥ 85% (rare, only sequential LSB)

  const flagCount = (spaFlagged ? 1 : 0) + (rsFlagged ? 1 : 0) + (chiFlagged ? 1 : 0);

  // Strong consensus: 2+ independent tests agree → very likely steganography.
  if (flagCount >= 2) {
    return { text: "⛔ Likely hiding data — multiple independent tests agree.", cls: "err" };
  }

  // One test flags. Decide if it's credible or likely a false positive.
  if (spaFlagged && !rsFlagged) {
    // SPA alone fired but RS is still healthy → typical AI/HDR camera artefact.
    return { text: "⚠ Inconclusive — SPA detected anomalies, but RS analysis looks clean. Likely camera AI processing.", cls: "warn" };
  }
  if (rsFlagged && !spaFlagged) {
    // RS alone collapsed but SPA is low → unusual, worth noting.
    return { text: "⚠ Possibly hiding data — RS regularity has eroded. Could be lightweight embedding.", cls: "warn" };
  }
  if (chiFlagged) {
    // Chi-square alone → sequential LSB replacement on a near-synthetic image.
    return { text: "⚠ Possibly hiding data — chi-square detects sequential LSB replacement.", cls: "warn" };
  }

  return { text: "✓ Looks clean — no signs of hidden data detected.", cls: "ok" };
}

/** Plain-language verdict for a quality comparison. PSNR is ∞ (serialized as
 * null) when the images are pixel-identical. */
function qualityVerdict(q: Quality): { text: string; cls: string } {
  const psnr = q.psnrDb == null || !isFinite(q.psnrDb) ? Infinity : q.psnrDb;
  if (psnr >= 45 || q.ssim >= 0.999) {
    return { text: "✓ Looks identical to the eye.", cls: "ok" };
  }
  if (psnr >= 35) {
    return { text: "✓ Very similar — changes are hard to spot.", cls: "ok" };
  }
  if (psnr >= 28) {
    return { text: "⚠ Noticeably different on close inspection.", cls: "warn" };
  }
  return { text: "⛔ Clearly different.", cls: "err" };
}

/** PSNR for display: ∞ when images are identical. */
function psnrLabel(psnrDb: number): string {
  return psnrDb == null || !isFinite(psnrDb) ? "∞" : psnrDb.toFixed(1);
}

function AnalyzeTab() {
  const [scan, setScan] = useState<number[] | null>(null);
  const [scanName, setScanName] = useState("");
  const [detection, setDetection] = useState<Detection | null>(null);
  const [orig, setOrig] = useState<number[] | null>(null);
  const [edited, setEdited] = useState<number[] | null>(null);
  const [qual, setQual] = useState<Quality | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function pickFor(setter: (b: number[]) => void, after?: () => void) {
    const path = await open({ multiple: false });
    if (typeof path !== "string") return path;
    setter(await readFile(path));
    setErr(null);
    after?.();
    return path;
  }

  async function doDetect() {
    if (!scan) return;
    setBusy(true);
    setErr(null);
    try {
      setDetection(await detectLsb(scan));
    } catch (e) {
      setErr(String(e));
    }
    setBusy(false);
  }

  async function doQuality() {
    if (!orig || !edited) return;
    setBusy(true);
    setErr(null);
    try {
      setQual(await quality(orig, edited));
    } catch (e) {
      setErr(String(e));
    }
    setBusy(false);
  }

  const sv = detection && suspicionVerdict(detection);
  const qv = qual && qualityVerdict(qual);

  return (
    <div className="panel">
      <h2 className="section">Scan a photo for hidden data</h2>
      <p className="hint">Checks a photo for the most common hiding method (LSB). Works best on PNG photos.</p>
      <button
        className="picker"
        onClick={async () => {
          const p = await pickFor(setScan, () => {
            setDetection(null);
          });
          if (typeof p === "string") setScanName(p.split(/[\\/]/).pop() ?? "image");
        }}
      >
        {scan ? `Image: ${scanName}` : "Choose a photo…"}
      </button>
      <button className="primary" disabled={busy || !scan} onClick={doDetect}>
        {busy ? "Scanning…" : "Scan"}
      </button>
      {sv && (
        <div className="reveal">
          <p className={sv.cls}>{sv.text}</p>
          <p className="hint">
            SPA rate {(detection!.samplePairRate * 100).toFixed(0)}%
            {" · "}
            RS gap {(detection!.rsRegularityGap * 100).toFixed(0)}%
            {" · "}
            Chi-square {(detection!.chiSquareP * 100).toFixed(0)}%
            {" · "}
            ML confidence {(detection!.mlConfidence * 100).toFixed(0)}%
          </p>
        </div>
      )}

      <h2 className="section">Compare two photos</h2>
      <p className="hint">Pick an original and an edited copy to see how much they differ.</p>
      <button className="picker" onClick={() => pickFor(setOrig, () => setQual(null))}>
        {orig ? "Original chosen ✓" : "Choose the original…"}
      </button>
      <button className="picker" onClick={() => pickFor(setEdited, () => setQual(null))}>
        {edited ? "Edited copy chosen ✓" : "Choose the edited copy…"}
      </button>
      <button className="primary" disabled={busy || !orig || !edited} onClick={doQuality}>
        {busy ? "Comparing…" : "Compare"}
      </button>
      {qv && (
        <div className="reveal">
          <p className={qv.cls}>{qv.text}</p>
          <p className="hint">
            PSNR {psnrLabel(qual!.psnrDb)} dB · similarity {(qual!.ssim * 100).toFixed(1)}%
          </p>
        </div>
      )}

      {err && <p className="err">{err}</p>}
    </div>
  );
}

interface ExtractTabProps {
  methodId: string;
  setMethodId: (id: string) => void;
  methods: MethodInfo[];
}

function ExtractTab({ methodId, setMethodId, methods }: ExtractTabProps) {
  const [stegos, setStegos] = useState<{ name: string; bytes: number[] }[]>([]);
  const [splitMode, setSplitMode] = useState(false);
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Revealed | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const currentMethodInfo = methods.find(m => m.id === methodId);

  async function pickStego() {
    const paths = await open({ multiple: splitMode });
    if (!paths) return;
    const pathsArr = Array.isArray(paths) ? paths : [paths];
    const results = await Promise.all(
      pathsArr.map(async (p) => ({
        name: p.split(/[\\/]/).pop() ?? "stego",
        bytes: await readFile(p),
      }))
    );
    setStegos(results);
    setResult(null);
    setErr(null);
    if (results.length > 0) {
      setMethodId(autoSelectMethod(results[0].name));
    }
  }

  async function doExtract() {
    if (stegos.length === 0 || !pass) return;
    setBusy(true);
    setResult(null);
    setErr(null);
    try {
      if (splitMode) {
        setResult(await extractSplit(methodId, stegos.map(s => s.bytes), pass));
      } else {
        setResult(await extract(methodId, stegos[0].bytes, pass));
      }
    } catch (e) {
      setErr(String(e));
    }
    setBusy(false);
  }

  async function saveRevealedFile(name: string, bytes: number[]) {
    const path = await save({ defaultPath: name });
    if (typeof path === "string") await writeFile(path, bytes);
  }

  return (
    <div className="panel">
      <label className="decoy-toggle">
        <input type="checkbox" checked={splitMode} onChange={(e) => { 
          setSplitMode(e.target.checked); 
          setStegos([]); 
          setResult(null); 
        }} />
        Extract from split covers
      </label>

      <button className="picker" onClick={pickStego}>
        {stegos.length > 0 
          ? `Stegos: ${stegos.length} selected (${stegos.map(s => s.name).join(", ")})` 
          : splitMode ? "Choose split stego files…" : "Choose stego file…"}
      </button>

      {stegos.length > 0 && currentMethodInfo && !showAdvanced && (
        <p className="ok" style={{ margin: "4px 0 0 0", fontSize: "0.9rem" }}>
          ✓ Auto-selected method for {currentMethodInfo.media.toUpperCase()} files ({currentMethodInfo.displayName})
        </p>
      )}

      {stegos.length > 0 && (
        <div style={{ marginTop: "8px", marginBottom: "8px" }}>
          <button 
            className="link-button" 
            style={{ fontSize: "0.85rem", padding: 0, background: "none", border: "none", color: "#646cff", cursor: "pointer", textDecoration: "underline" }}
            onClick={() => setShowAdvanced(!showAdvanced)}
          >
            {showAdvanced ? "Hide Advanced Settings" : "Advanced Settings / Manual Override"}
          </button>
          
          {showAdvanced && (
            <label className="method" style={{ marginTop: "12px", display: "flex", flexDirection: "column", gap: "4px", fontSize: "0.9rem" }}>
              <span>Override Steganography Method</span>
              <select value={methodId} onChange={(e) => setMethodId(e.target.value)} style={{ padding: "8px", borderRadius: "4px" }}>
                {methods.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.displayName} · {m.media}
                  </option>
                ))}
              </select>
            </label>
          )}
        </div>
      )}
      <input
        type="password"
        placeholder="Passphrase"
        value={pass}
        onChange={(e) => setPass(e.target.value)}
      />
      <button className="primary" disabled={busy || stegos.length === 0 || !pass} onClick={doExtract}>
        {busy ? "Extracting…" : "Reveal"}
      </button>

      {result?.kind === "none" && <p className="warn">No hidden data found.</p>}
      {result?.kind === "text" && (
        <div className="reveal">
          <span className="label">Hidden message</span>
          <pre>{result.text}</pre>
        </div>
      )}
      {result?.kind === "file" && (
        <div className="reveal">
          <span className="label">Hidden file: {result.name}</span>
          <button className="primary" onClick={() => saveRevealedFile(result.name, result.bytes)}>
            Save file…
          </button>
        </div>
      )}
      {result?.kind === "files" && (
        <div className="reveal">
          <span className="label">Hidden files ({result.files.length})</span>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {result.files.map((f, i) => (
              <button key={i} className="primary" onClick={() => saveRevealedFile(f.name, f.bytes)}>
                Save {f.name} ({f.bytes.length} B)…
              </button>
            ))}
          </div>
        </div>
      )}
      {err && <p className="err">{err}</p>}
    </div>
  );
}
