import { useEffect, useMemo, useState, type ReactNode } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  listMethods,
  capacity,
  embedAdvanced,
  embedMulti,
  extractAuto,
  scanStructure,
  fingerprint,
  sanitize,
  passphraseStrength,
  bitPlane,
  readFile,
  writeFile,
  type MethodInfo,
  type Revealed,
  type PassphraseStrength,
  type RecipientInput,
} from "./api";

/* ---------- theme ---------- */
function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState<string>(() => localStorage.getItem("stegno-theme") || "auto");
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "auto") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
  }, [theme]);
  const effective = () => {
    const t = document.documentElement.getAttribute("data-theme");
    if (t) return t;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  };
  const toggle = () => {
    const next = effective() === "dark" ? "light" : "dark";
    localStorage.setItem("stegno-theme", next);
    setTheme(next);
  };
  return [theme, toggle];
}

/* ---------- helpers ---------- */
type Bytes = number[];
async function pickFile(accept?: string): Promise<{ name: string; bytes: Bytes } | null> {
  const path = await open({ multiple: false, filters: accept ? [{ name: accept, extensions: accept.split(",") }] : undefined });
  if (!path || typeof path !== "string") return null;
  const bytes = await readFile(path);
  const name = path.split(/[\\/]/).pop() || "file";
  return { name, bytes };
}
async function saveBytes(bytes: Bytes, defaultName: string): Promise<boolean> {
  const path = await save({ defaultPath: defaultName });
  if (!path) return false;
  await writeFile(path, bytes);
  return true;
}
function blobUrl(bytes: Bytes, mime: string): string {
  return URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: mime }));
}

type Tab = "hide" | "reveal" | "share" | "inspect" | "clean";

export default function App() {
  const [, toggleTheme] = useTheme();
  const [tab, setTab] = useState<Tab>("hide");
  const [methods, setMethods] = useState<MethodInfo[]>([]);
  const themeIcon = () =>
    (document.documentElement.getAttribute("data-theme") ||
      (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark"
      ? "☀️"
      : "🌙";

  useEffect(() => {
    listMethods().then(setMethods).catch(() => {});
  }, []);

  const tabs: { id: Tab; label: string }[] = [
    { id: "hide", label: "🖼️ Hide" },
    { id: "reveal", label: "🔑 Reveal" },
    { id: "share", label: "👥 Share" },
    { id: "inspect", label: "🔍 Inspect" },
    { id: "clean", label: "🧼 Clean" },
  ];

  return (
    <>
      <div className="hero">
        <div className="hero-inner">
          <div className="badge">🔒</div>
          <div>
            <h1>Stegno</h1>
            <p>Hide encrypted messages inside ordinary photos, text &amp; files.</p>
          </div>
          <div className="hero-actions">
            <button className="theme-toggle" onClick={toggleTheme} title="Switch theme">{themeIcon()}</button>
            <span className="offline">On-device</span>
          </div>
        </div>
      </div>
      <main>
        <nav className="tabs">
          {tabs.map((t) => (
            <button key={t.id} className={tab === t.id ? "active" : ""} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>
        {tab === "hide" && <HideTab methods={methods} />}
        {tab === "reveal" && <RevealTab />}
        {tab === "share" && <ShareTab />}
        {tab === "inspect" && <InspectTab />}
        {tab === "clean" && <CleanTab />}
      </main>
      <footer>Runs entirely on your device — no uploads, no servers. · {methods.length} methods</footer>
    </>
  );
}

/* ---------- Hide ---------- */
function HideTab({ methods }: { methods: MethodInfo[] }) {
  const imageMethods = useMemo(() => methods.filter((m) => m.media === "Image"), [methods]);
  const [cover, setCover] = useState<{ name: string; bytes: Bytes } | null>(null);
  const [text, setText] = useState("");
  const [pass, setPass] = useState("");
  const [method, setMethod] = useState("lsb_seeded");
  const [robust, setRobust] = useState(0);
  const [compress, setCompress] = useState(false);
  const [cap, setCap] = useState<number | null>(null);
  const [strength, setStrength] = useState<PassphraseStrength | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  useEffect(() => {
    if (cover) capacity(method, cover.bytes).then(setCap).catch(() => setCap(null));
  }, [cover, method]);

  async function onPass(v: string) {
    setPass(v);
    setStrength(v ? await passphraseStrength(v) : null);
  }
  async function doHide() {
    if (!cover) return;
    setBusy(true); setResult(null);
    try {
      const stego = await embedAdvanced(method, cover.bytes, { kind: "text", text }, pass, robust as 0 | 1 | 2 | 3, compress);
      const saved = await saveBytes(stego, "stego.png");
      setResult({ ok: true, msg: saved ? `Hidden in a ${(stego.length / 1024).toFixed(0)} KB image — saved.` : "Ready (save cancelled)." });
    } catch (e: unknown) {
      setResult({ ok: false, msg: String((e as Error).message ?? e) });
    } finally { setBusy(false); }
  }

  const strengthColors = ["var(--bad)", "var(--bad)", "var(--warn)", "var(--ok)", "var(--ok)"];
  const strengthLabels = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];

  return (
    <section className="panel active">
      <div className="card">
        <h2>Hide a secret</h2>
        <p className="hint">Pick a cover, write your message, choose a password. Everything stays on your device.</p>

        <label>Cover image</label>
        <Drop label={cover ? cover.name : "Choose a photo (PNG, JPG…)"} icon={cover ? "✅" : "📷"} has={!!cover}
          onClick={async () => setCover(await pickFile("png,jpg,jpeg,bmp,webp,gif"))} />

        <label>Secret message</label>
        <textarea value={text} onChange={(e) => setText(e.target.value)} placeholder="Type the message you want to hide…" />

        <label>Password</label>
        <input type="password" value={pass} onChange={(e) => onPass(e.target.value)} placeholder="A strong passphrase" />
        <div className="meter"><span style={{ width: strength ? `${((strength.score + 1) / 5) * 100}%` : "0", background: strength ? strengthColors[strength.score] : "" }} /></div>
        <div className="small">{strength ? <><b>{strengthLabels[strength.score]}</b> · ~{strength.entropyBits.toFixed(0)} bits · cracks in {strength.crackTimeDisplay}{strength.warning ? <span className="err"> · {strength.warning}</span> : null}</> : "Strength appears as you type."}</div>

        <label>Method</label>
        <select value={method} onChange={(e) => setMethod(e.target.value)}>
          {imageMethods.map((m) => <option key={m.id} value={m.id}>{m.displayName}</option>)}
        </select>
        {cap != null && <div className="small">Room for about {cap.toLocaleString()} bytes.</div>}

        <div className="row">
          <div>
            <label>Toughness</label>
            <select value={robust} onChange={(e) => setRobust(Number(e.target.value))}>
              <option value={0}>Standard</option>
              <option value={1}>Rugged — survives light edits</option>
              <option value={2}>Extra rugged</option>
              <option value={3}>Maximum — survives print/scan</option>
            </select>
          </div>
          <div>
            <label>Squeeze</label>
            <label className="check"><input type="checkbox" checked={compress} onChange={(e) => setCompress(e.target.checked)} /> <span>Compress first <span className="small">fit more in</span></span></label>
          </div>
        </div>

        <button className="primary" disabled={!cover || !text || !pass || busy} onClick={doHide}>{busy ? "Hiding…" : "Hide & save"}</button>
        {result && <div className={`result-banner ${result.ok ? "ok" : "bad"}`} style={{ marginTop: 16 }}>{result.ok ? "✅ " : "⚠️ "}{result.msg}</div>}
      </div>
    </section>
  );
}

/* ---------- Reveal ---------- */
function RevealTab() {
  const [file, setFile] = useState<{ name: string; bytes: Bytes } | null>(null);
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState<{ ok: boolean; node: ReactNode } | null>(null);

  async function doReveal() {
    if (!file) return;
    setBusy(true); setOut(null);
    try {
      const r = await extractAuto(file.bytes, pass);
      const rv: Revealed = r.revealed;
      if (rv.kind === "none") setOut({ ok: false, node: "No hidden data found (or wrong password)." });
      else if (rv.kind === "text") setOut({ ok: true, node: <><div>Revealed via <b>{r.methodId}</b></div><pre>{rv.text}</pre></> });
      else if (rv.kind === "file") { await saveBytes(rv.bytes, rv.name); setOut({ ok: true, node: `Recovered file ${rv.name} — saved.` }); }
      else if (rv.kind === "files") { for (const f of rv.files) await saveBytes(f.bytes, f.name); setOut({ ok: true, node: `Recovered ${rv.files.length} files.` }); }
    } catch (e: unknown) {
      setOut({ ok: false, node: String((e as Error).message ?? e) });
    } finally { setBusy(false); }
  }

  return (
    <section className="panel active">
      <div className="card">
        <h2>Reveal a secret</h2>
        <p className="hint">Choose a stego file and enter the password. We'll figure out the method automatically.</p>
        <label>Stego file</label>
        <Drop label={file ? file.name : "Choose the file"} icon={file ? "✅" : "🗂️"} has={!!file} onClick={async () => setFile(await pickFile())} />
        <label>Password</label>
        <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} placeholder="The password used to hide it" />
        <button className="primary" disabled={!file || busy} onClick={doReveal}>{busy ? "Revealing…" : "Reveal"}</button>
        {out && <div className="out"><div className={`result-banner ${out.ok ? "ok" : "bad"}`}>{out.ok ? "🔓 " : "🔎 "}{out.node}</div></div>}
      </div>
    </section>
  );
}

/* ---------- Share (multi-recipient) ---------- */
function ShareTab() {
  const [cover, setCover] = useState<{ name: string; bytes: Bytes } | null>(null);
  const [rows, setRows] = useState<{ text: string; passphrase: string }[]>([{ text: "", passphrase: "" }, { text: "", passphrase: "" }]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const valid = rows.filter((r) => r.text && r.passphrase);

  async function doShare() {
    if (!cover) return;
    setBusy(true); setResult(null);
    try {
      const recipients: RecipientInput[] = valid.map((r) => ({ secret: { kind: "text", text: r.text }, passphrase: r.passphrase }));
      const stego = await embedMulti(cover.bytes, recipients);
      const saved = await saveBytes(stego, "shared.png");
      setResult({ ok: true, msg: saved ? `Hid ${recipients.length} separate messages in one photo.` : "Ready (save cancelled)." });
    } catch (e: unknown) {
      setResult({ ok: false, msg: String((e as Error).message ?? e) });
    } finally { setBusy(false); }
  }

  return (
    <section className="panel active">
      <div className="card">
        <h2>One photo, many people</h2>
        <p className="hint">Hide a different message for each person. Each opens only their own with their own password.</p>
        <label>Cover image</label>
        <Drop label={cover ? cover.name : "Choose a photo"} icon={cover ? "✅" : "📷"} has={!!cover} onClick={async () => setCover(await pickFile("png,jpg,jpeg,bmp,webp,gif"))} />
        {rows.map((r, i) => (
          <div className="recip" key={i}>
            <div className="row">
              <input type="text" placeholder="Message for this person" value={r.text} onChange={(e) => setRows(rows.map((x, j) => j === i ? { ...x, text: e.target.value } : x))} />
              <input type="password" placeholder="Their password" value={r.passphrase} onChange={(e) => setRows(rows.map((x, j) => j === i ? { ...x, passphrase: e.target.value } : x))} />
              <button className="ghost" onClick={() => setRows(rows.filter((_, j) => j !== i))}>✕</button>
            </div>
          </div>
        ))}
        <button className="ghost" style={{ marginTop: 12 }} disabled={rows.length >= 8} onClick={() => setRows([...rows, { text: "", passphrase: "" }])}>+ Add person</button>
        <button className="primary" disabled={!cover || valid.length < 2 || busy} onClick={doShare}>{busy ? "Hiding…" : "Hide all & save"}</button>
        {result && <div className={`result-banner ${result.ok ? "ok" : "bad"}`} style={{ marginTop: 16 }}>{result.ok ? "✅ " : "⚠️ "}{result.msg}</div>}
      </div>
    </section>
  );
}

/* ---------- Inspect ---------- */
function InspectTab() {
  const [file, setFile] = useState<{ name: string; bytes: Bytes } | null>(null);
  const [out, setOut] = useState<ReactNode>(null);
  const [isImage, setIsImage] = useState(false);
  const [channel, setChannel] = useState(0);
  const [plane, setPlane] = useState(0);
  const [planeSrc, setPlaneSrc] = useState<string | null>(null);

  async function doInspect() {
    if (!file) return;
    try {
      const scan = await scanStructure(file.bytes);
      const guesses = await fingerprint(file.bytes);
      setIsImage(["png", "jpeg", "gif"].includes(scan.format));
      setOut(
        <>
          <div className={`result-banner ${scan.suspicious ? "bad" : "ok"}`}>{scan.suspicious ? "⚠️ Signs of hidden data found" : "✅ Nothing obvious found"}</div>
          <div className="small" style={{ marginTop: 8 }}>Format: <b>{scan.format}</b></div>
          {scan.findings.length > 0 && (
            <table><thead><tr><th>Signal</th><th>Detail</th></tr></thead><tbody>
              {scan.findings.map((f, i) => <tr key={i}><td>{f.kind}{f.severity >= 2 && <span className="tag bad" style={{ marginLeft: 6 }}>strong</span>}</td><td>{f.detail}</td></tr>)}
            </tbody></table>
          )}
          <label>Likely method</label>
          <table><tbody>{guesses.slice(0, 4).map((g, i) => <tr key={i}><td>{(g.confidence * 100).toFixed(0)}%</td><td>{g.label}</td></tr>)}</tbody></table>
        </>
      );
    } catch (e: unknown) {
      setOut(<div className="result-banner bad">⚠️ {String((e as Error).message ?? e)}</div>);
    }
  }
  async function renderPlane() {
    if (!file) return;
    try {
      const png = await bitPlane(file.bytes, channel, plane);
      setPlaneSrc(blobUrl(png, "image/png"));
    } catch { /* ignore */ }
  }

  return (
    <section className="panel active">
      <div className="card">
        <h2>Inspect a file</h2>
        <p className="hint">Check any file for signs of hidden data — and guess how it was hidden.</p>
        <label>File to inspect</label>
        <Drop label={file ? file.name : "Choose a file"} icon={file ? "✅" : "🔍"} has={!!file} onClick={async () => { setFile(await pickFile()); setOut(null); setPlaneSrc(null); }} />
        <button className="primary" disabled={!file} onClick={doInspect}>Inspect</button>
        <div className="out">{out}</div>
      </div>
      {isImage && (
        <div className="card">
          <h2>See the hidden layer</h2>
          <p className="hint">Render a bit-plane — hidden data shows up as noise.</p>
          <div className="row">
            <div><label>Channel</label><select value={channel} onChange={(e) => setChannel(Number(e.target.value))}><option value={0}>Red</option><option value={1}>Green</option><option value={2}>Blue</option></select></div>
            <div><label>Plane</label><select value={plane} onChange={(e) => setPlane(Number(e.target.value))}>{[0, 1, 2, 3, 4, 5, 6, 7].map((p) => <option key={p} value={p}>{p}</option>)}</select></div>
          </div>
          <button className="primary" onClick={renderPlane}>Render</button>
          {planeSrc && <div className="out"><img className="render" src={planeSrc} alt="bit plane" /></div>}
        </div>
      )}
    </section>
  );
}

/* ---------- Clean ---------- */
function CleanTab() {
  const [file, setFile] = useState<{ name: string; bytes: Bytes } | null>(null);
  const [out, setOut] = useState<ReactNode>(null);

  async function doClean() {
    if (!file) return;
    try {
      const r = await sanitize(file.bytes);
      const base = file.name.replace(/\.[^.]+$/, "");
      const ext = r.format === "image" ? ".png" : (file.name.match(/\.[^.]+$/)?.[0] || ".txt");
      await saveBytes(r.cleaned, `${base}-clean${ext}`);
      setOut(
        <>
          <div className="result-banner ok">🧼 {r.changed ? "Cleaned — any hidden payload destroyed." : "Nothing hidden was found; copied as-is."}</div>
          {r.actions.length > 0 && <ul className="small">{r.actions.map((a, i) => <li key={i}>{a}</li>)}</ul>}
        </>
      );
    } catch (e: unknown) {
      setOut(<div className="result-banner bad">⚠️ {String((e as Error).message ?? e)}</div>);
    }
  }

  return (
    <section className="panel active">
      <div className="card">
        <h2>Remove hidden data</h2>
        <p className="hint">Scrub a file so any hidden payload is destroyed — the picture still looks the same.</p>
        <label>File to clean</label>
        <Drop label={file ? file.name : "Choose a file"} icon={file ? "✅" : "🧼"} has={!!file} onClick={async () => { setFile(await pickFile()); setOut(null); }} />
        <button className="primary" disabled={!file} onClick={doClean}>Sanitize & save</button>
        <div className="out">{out}</div>
      </div>
    </section>
  );
}

/* ---------- shared Drop ---------- */
function Drop({ label, icon, has, onClick }: { label: string; icon: string; has: boolean; onClick: () => void }) {
  return (
    <div className={`drop ${has ? "has" : ""}`} onClick={onClick}>
      <span className="big">{icon}</span>{label}
    </div>
  );
}
