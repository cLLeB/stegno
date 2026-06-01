import { useEffect, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  capacity,
  embedFile,
  embedText,
  extract,
  listMethods,
  readFile,
  writeFile,
  type MethodInfo,
  type Revealed,
} from "./api";

type Tab = "hide" | "extract";
type SecretMode = "text" | "file";

/// Output file extension for a method's carrier medium.
function mediaExtension(media: string): string {
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

      <div className="tabs">
        <button className={tab === "hide" ? "on" : ""} onClick={() => setTab("hide")}>
          Hide
        </button>
        <button className={tab === "extract" ? "on" : ""} onClick={() => setTab("extract")}>
          Extract
        </button>
      </div>

      {methods.length === 0 && <p className="warn">Engine not available.</p>}
      {tab === "hide" ? (
        <HideTab methodId={methodId} media={method?.media ?? "File"} />
      ) : (
        <ExtractTab methodId={methodId} />
      )}

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

  // Recompute capacity whenever the cover or method changes.
  useEffect(() => {
    if (!cover) {
      setCap(null);
      return;
    }
    capacity(methodId, cover)
      .then(setCap)
      .catch(() => setCap(null));
  }, [cover, methodId]);

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
      const out =
        mode === "text"
          ? await embedText(methodId, cover, text, pass)
          : await embedFile(methodId, cover, file!.name, file!.bytes, pass);
      const ext = mediaExtension(media);
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
    !busy && !!cover && !!pass && (mode === "text" ? text.length > 0 : !!file);

  return (
    <div className="panel">
      <button className="picker" onClick={pickCover}>
        {cover ? `Cover: ${coverName}` : "Choose cover file…"}
      </button>
      {cap !== null && <p className="cap">Capacity: ~{cap.toLocaleString()} bytes</p>}

      <div className="seg">
        <button className={mode === "text" ? "on" : ""} onClick={() => setMode("text")}>
          Text
        </button>
        <button className={mode === "file" ? "on" : ""} onClick={() => setMode("file")}>
          File
        </button>
      </div>

      {mode === "text" ? (
        <textarea
          placeholder="Secret message…"
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
        placeholder="Passphrase"
        value={pass}
        onChange={(e) => setPass(e.target.value)}
      />

      <button className="primary" disabled={!canEmbed} onClick={doEmbed}>
        {busy ? "Embedding…" : "Hide & save"}
      </button>

      {msg && <p className="ok">{msg}</p>}
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
