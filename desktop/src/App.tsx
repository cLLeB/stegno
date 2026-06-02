import { useEffect, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  capacity,
  decoyCapacity,
  detectLsb,
  embedFile,
  embedText,
  embedTextWithDecoy,
  extract,
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

/// Output file extension for a method. Most image methods emit PNG, but a few
/// produce a different container (e.g. jpeg_jsteg emits a real JPEG), so the
/// method id takes precedence over the carrier medium.
function outputExtension(methodId: string, media: string): string {
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
      return "bin";
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

      {tab !== "analyze" && (
        <label className="method">
          <span>Method</span>
          <select value={methodId} onChange={(e) => setMethodId(e.target.value)}>
            {methods.map((m) => (
              <option key={m.id} value={m.id}>
                {m.displayName} · {m.media}
              </option>
            ))}
          </select>
        </label>
      )}

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
      {tab === "hide" && <HideTab methodId={methodId} media={method?.media ?? "File"} />}
      {tab === "extract" && <ExtractTab methodId={methodId} />}
      {tab === "analyze" && <AnalyzeTab />}

      <footer>Argon2id + AES-256-GCM · nothing leaves this device.</footer>
    </div>
  );
}

interface HideTabProps {
  methodId: string;
  media: string;
}

function HideTab({ methodId, media }: HideTabProps) {
  const [cover, setCover] = useState<number[] | null>(null);
  const [coverName, setCoverName] = useState("");
  const [cap, setCap] = useState<number | null>(null);
  const [mode, setMode] = useState<SecretMode>("text");
  const [text, setText] = useState("");
  const [file, setFile] = useState<{ name: string; bytes: number[] } | null>(null);
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // Decoy mode: hide a second "fake" message under a different password.
  const [decoy, setDecoy] = useState(false);
  const [decoyText, setDecoyText] = useState("");
  const [decoyPass, setDecoyPass] = useState("");

  // Recompute capacity whenever the cover, method, or decoy toggle changes.
  // Decoy mode always uses LSB-in-photo and reports per-message capacity.
  useEffect(() => {
    if (!cover) {
      setCap(null);
      return;
    }
    const p = decoy ? decoyCapacity(cover) : capacity(methodId, cover);
    p.then(setCap).catch(() => setCap(null));
  }, [cover, methodId, decoy]);

  async function pickCover() {
    const path = await open({ multiple: false });
    if (typeof path !== "string") return;
    const bytes = await readFile(path);
    setCover(bytes);
    setCoverName(path.split(/[\\/]/).pop() ?? "cover");
    setMsg(null);
    setErr(null);
  }

  async function pickSecretFile() {
    const path = await open({ multiple: false });
    if (typeof path !== "string") return;
    const bytes = await readFile(path);
    setFile({ name: path.split(/[\\/]/).pop() ?? "file", bytes });
  }

  async function doEmbed() {
    if (!cover || !pass) return;
    setBusy(true);
    setMsg(null);
    setErr(null);
    try {
      // Decoy mode always produces a PNG photo (real + decoy via LSB).
      const out = decoy
        ? await embedTextWithDecoy(cover, text, pass, decoyText, decoyPass)
        : mode === "text"
          ? await embedText(methodId, cover, text, pass)
          : await embedFile(methodId, cover, file!.name, file!.bytes, pass);
      const ext = decoy ? "png" : outputExtension(methodId, media);
      const path = await save({
        defaultPath: `stego.${ext}`,
        filters: [{ name: ext.toUpperCase(), extensions: [ext] }],
      });
      if (typeof path === "string") {
        await writeFile(path, out);
        setMsg(`Saved ${out.length.toLocaleString()} bytes → ${path}`);
      }
    } catch (e) {
      setErr(String(e));
    }
    setBusy(false);
  }

  const canEmbed =
    !busy &&
    !!cover &&
    !!pass &&
    (decoy
      ? text.length > 0 && decoyText.length > 0 && decoyPass.length > 0 && decoyPass !== pass
      : mode === "text"
        ? text.length > 0
        : !!file);

  return (
    <div className="panel">
      <button className="picker" onClick={pickCover}>
        {cover ? `Cover: ${coverName}` : "Choose cover file…"}
      </button>
      {cap !== null && (
        <p className="cap">
          {decoy ? "Capacity per message" : "Capacity"}: ~{cap.toLocaleString()} bytes
        </p>
      )}

      <label className="decoy-toggle">
        <input type="checkbox" checked={decoy} onChange={(e) => setDecoy(e.target.checked)} />
        Add a decoy message
      </label>
      {decoy && (
        <p className="hint">
          Hides two messages in one photo. The real password reveals the real message; the
          decoy password reveals a harmless fake — so you can safely hand over the decoy
          password if forced. (Saved as a PNG photo.)
        </p>
      )}

      {!decoy && (
        <div className="seg">
          <button className={mode === "text" ? "on" : ""} onClick={() => setMode("text")}>
            Text
          </button>
          <button className={mode === "file" ? "on" : ""} onClick={() => setMode("file")}>
            File
          </button>
        </div>
      )}

      {decoy || mode === "text" ? (
        <textarea
          placeholder={decoy ? "Real message…" : "Secret message…"}
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={4}
        />
      ) : (
        <button className="picker" onClick={pickSecretFile}>
          {file ? `File: ${file.name} (${file.bytes.length} B)` : "Choose secret file…"}
        </button>
      )}

      <input
        type="password"
        placeholder={decoy ? "Real password" : "Passphrase"}
        value={pass}
        onChange={(e) => setPass(e.target.value)}
      />

      {decoy && (
        <>
          <textarea
            placeholder="Decoy message (the fake one)…"
            value={decoyText}
            onChange={(e) => setDecoyText(e.target.value)}
            rows={3}
          />
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

/** Plain-language verdict for the LSB detector. */
function suspicionVerdict(d: Detection): { text: string; cls: string } {
  const rate = d.samplePairRate;
  if (rate < 0.05 && d.chiSquareP < 0.5) {
    return { text: "✓ Looks clean — no obvious hidden data.", cls: "ok" };
  }
  if (rate < 0.2 && d.chiSquareP < 0.9) {
    return { text: "⚠ Possibly hiding data — some suspicious signs.", cls: "warn" };
  }
  return { text: "⛔ Likely hiding data — strong signs of LSB embedding.", cls: "err" };
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
            Embedding-rate estimate {(detection!.samplePairRate * 100).toFixed(0)}% · chi-square{" "}
            {(detection!.chiSquareP * 100).toFixed(0)}%
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
}

function ExtractTab({ methodId }: ExtractTabProps) {
  const [stego, setStego] = useState<number[] | null>(null);
  const [stegoName, setStegoName] = useState("");
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Revealed | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function pickStego() {
    const path = await open({ multiple: false });
    if (typeof path !== "string") return;
    setStego(await readFile(path));
    setStegoName(path.split(/[\\/]/).pop() ?? "stego");
    setResult(null);
    setErr(null);
  }

  async function doExtract() {
    if (!stego || !pass) return;
    setBusy(true);
    setResult(null);
    setErr(null);
    try {
      setResult(await extract(methodId, stego, pass));
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
      <button className="picker" onClick={pickStego}>
        {stego ? `Stego: ${stegoName}` : "Choose stego file…"}
      </button>
      <input
        type="password"
        placeholder="Passphrase"
        value={pass}
        onChange={(e) => setPass(e.target.value)}
      />
      <button className="primary" disabled={busy || !stego || !pass} onClick={doExtract}>
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
      {err && <p className="err">{err}</p>}
    </div>
  );
}
