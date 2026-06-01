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
  type Revealed,
} from "./api";

const METHOD = "lsb_image";

type Tab = "hide" | "extract";
type SecretMode = "text" | "file";

export default function App() {
  const [tab, setTab] = useState<Tab>("hide");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    listMethods()
      .then((ms) => setReady(ms.some((m) => m.id === METHOD)))
      .catch(() => setReady(false));
  }, []);

  return (
    <div className="app">
      <header>
        <h1>Stegno</h1>
        <p className="sub">Offline steganography · LSB image (PNG)</p>
      </header>

      <div className="tabs">
        <button className={tab === "hide" ? "on" : ""} onClick={() => setTab("hide")}>
          Hide
        </button>
        <button className={tab === "extract" ? "on" : ""} onClick={() => setTab("extract")}>
          Extract
        </button>
      </div>

      {!ready && <p className="warn">Engine not available.</p>}
      {tab === "hide" ? <HideTab /> : <ExtractTab />}

      <footer>Argon2id + AES-256-GCM · nothing leaves this device.</footer>
    </div>
  );
}

function HideTab() {
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

  async function pickCover() {
    const path = await open({
      multiple: false,
      filters: [{ name: "Image", extensions: ["png", "jpg", "jpeg", "bmp", "webp", "gif"] }],
    });
    if (typeof path !== "string") return;
    const bytes = await readFile(path);
    setCover(bytes);
    setCoverName(path.split(/[\\/]/).pop() ?? "image");
    setMsg(null);
    setErr(null);
    try {
      setCap(await capacity(METHOD, bytes));
    } catch {
      setCap(null);
    }
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
          ? await embedText(METHOD, cover, text, pass)
          : await embedFile(METHOD, cover, file!.name, file!.bytes, pass);
      const path = await save({
        defaultPath: "stego.png",
        filters: [{ name: "PNG", extensions: ["png"] }],
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
        {cover ? `Cover: ${coverName}` : "Choose cover image…"}
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
        {busy ? "Embedding…" : "Hide & save PNG"}
      </button>

      {msg && <p className="ok">{msg}</p>}
      {err && <p className="err">{err}</p>}
    </div>
  );
}

function ExtractTab() {
  const [stego, setStego] = useState<number[] | null>(null);
  const [stegoName, setStegoName] = useState("");
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Revealed | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function pickStego() {
    const path = await open({
      multiple: false,
      filters: [{ name: "PNG", extensions: ["png"] }],
    });
    if (typeof path !== "string") return;
    setStego(await readFile(path));
    setStegoName(path.split(/[\\/]/).pop() ?? "image");
    setResult(null);
    setErr(null);
  }

  async function doExtract() {
    if (!stego || !pass) return;
    setBusy(true);
    setResult(null);
    setErr(null);
    try {
      setResult(await extract(METHOD, stego, pass));
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
        {stego ? `Stego: ${stegoName}` : "Choose stego PNG…"}
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
