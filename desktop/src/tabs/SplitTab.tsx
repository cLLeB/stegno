import { useMemo, useState, type ReactNode } from "react";
import { embedSplit, extractSplit, type MethodInfo, type Revealed } from "../api";
import { Banner, Drop, IMAGE_ACCEPT, Seg, errMsg, pickFiles, saveBytes, type Picked } from "../shared";

type Mode = "hide" | "reveal";

export function SplitTab({ methods }: { methods: MethodInfo[] }) {
  const imageMethods = useMemo(() => methods.filter((m) => m.media === "Image"), [methods]);
  const [mode, setMode] = useState<Mode>("hide");

  return (
    <section className="panel active">
      <div className="card">
        <h2>Split across several photos</h2>
        <p className="hint">Spread one secret over multiple photos — every photo is needed to rebuild it. Losing any one keeps the secret safe.</p>
        <Seg<Mode> options={[{ id: "hide", label: "Hide across" }, { id: "reveal", label: "Reveal from" }]} value={mode} onChange={setMode} />
        {mode === "hide" ? <SplitHide methods={imageMethods} /> : <SplitReveal methods={imageMethods} />}
      </div>
    </section>
  );
}

function SplitHide({ methods }: { methods: MethodInfo[] }) {
  const [covers, setCovers] = useState<Picked[]>([]);
  const [text, setText] = useState("");
  const [pass, setPass] = useState("");
  const [method, setMethod] = useState("lsb_seeded");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  async function doHide() {
    setBusy(true); setResult(null);
    try {
      const parts = await embedSplit(method, covers.map((c) => c.bytes), { kind: "text", text }, pass);
      let saved = 0;
      for (let i = 0; i < parts.length; i++) if (await saveBytes(parts[i], `part${i + 1}.png`)) saved++;
      setResult({ ok: true, msg: `Saved ${saved} of ${parts.length} photos — all are needed to rebuild.` });
    } catch (e) {
      setResult({ ok: false, msg: errMsg(e) });
    } finally { setBusy(false); }
  }

  return (
    <>
      <label>Cover photos <span className="small">pick 2 or more</span></label>
      <Drop label={covers.length ? `${covers.length} photos selected` : "Choose photos"} icon={covers.length ? "✅" : "📷"} has={covers.length > 0} onClick={async () => setCovers(await pickFiles(IMAGE_ACCEPT))} />
      <label>Secret message</label>
      <textarea value={text} onChange={(e) => setText(e.target.value)} placeholder="The message to spread across the photos" />
      <label>Password</label>
      <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} placeholder="A strong passphrase" />
      <label>Method</label>
      <select value={method} onChange={(e) => setMethod(e.target.value)}>{methods.map((m) => <option key={m.id} value={m.id}>{m.displayName}</option>)}</select>
      <button className="primary" disabled={covers.length < 2 || !text || !pass || busy} onClick={doHide}>{busy ? "Splitting…" : "Split & save each"}</button>
      {result && <div style={{ marginTop: 16 }}><Banner ok={result.ok}>{result.msg}</Banner></div>}
    </>
  );
}

function SplitReveal({ methods }: { methods: MethodInfo[] }) {
  const [stegos, setStegos] = useState<Picked[]>([]);
  const [pass, setPass] = useState("");
  const [method, setMethod] = useState("lsb_seeded");
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState<{ ok: boolean; node: ReactNode } | null>(null);

  async function doReveal() {
    setBusy(true); setOut(null);
    try {
      const r: Revealed = await extractSplit(method, stegos.map((s) => s.bytes), pass);
      if (r.kind === "none") setOut({ ok: false, node: "Nothing found (wrong password, method, or missing a photo)." });
      else if (r.kind === "text") setOut({ ok: true, node: <><div>Rebuilt the secret.</div><pre>{r.text}</pre></> });
      else if (r.kind === "file") { await saveBytes(r.bytes, r.name); setOut({ ok: true, node: `Recovered file ${r.name} — saved.` }); }
      else if (r.kind === "files") { for (const f of r.files) await saveBytes(f.bytes, f.name); setOut({ ok: true, node: `Recovered ${r.files.length} files.` }); }
    } catch (e) {
      setOut({ ok: false, node: errMsg(e) });
    } finally { setBusy(false); }
  }

  return (
    <>
      <label>All the photos</label>
      <Drop label={stegos.length ? `${stegos.length} photos selected` : "Choose every photo"} icon={stegos.length ? "✅" : "🗂️"} has={stegos.length > 0} onClick={async () => setStegos(await pickFiles(IMAGE_ACCEPT))} />
      <label>Password</label>
      <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} placeholder="The password used to hide it" />
      <label>Method</label>
      <select value={method} onChange={(e) => setMethod(e.target.value)}>{methods.map((m) => <option key={m.id} value={m.id}>{m.displayName}</option>)}</select>
      <button className="primary" disabled={stegos.length < 2 || !pass || busy} onClick={doReveal}>{busy ? "Rebuilding…" : "Rebuild secret"}</button>
      {out && <div className="out"><div className={`result-banner ${out.ok ? "ok" : "bad"}`}>{out.ok ? "🔓 " : "🔎 "}{out.node}</div></div>}
    </>
  );
}
