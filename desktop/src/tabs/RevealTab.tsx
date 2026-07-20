import { useState, type ReactNode } from "react";
import { extractAuto, type Revealed } from "../api";
import { Drop, errMsg, pickFile, saveBytes, type Picked } from "../shared";

export function RevealTab() {
  const [file, setFile] = useState<Picked | null>(null);
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
      else if (rv.kind === "text") setOut({ ok: true, node: <><div>Revealed via <b>{r.methodId || "auto"}</b></div><pre>{rv.text}</pre></> });
      else if (rv.kind === "file") { await saveBytes(rv.bytes, rv.name); setOut({ ok: true, node: `Recovered file ${rv.name} — saved.` }); }
      else if (rv.kind === "files") { for (const f of rv.files) await saveBytes(f.bytes, f.name); setOut({ ok: true, node: `Recovered ${rv.files.length} files.` }); }
    } catch (e) {
      setOut({ ok: false, node: errMsg(e) });
    } finally { setBusy(false); }
  }

  return (
    <section className="panel active">
      <div className="card">
        <h2>Reveal a secret</h2>
        <p className="hint">Choose a stego file and enter the password. We'll figure out the method automatically — including decoy and multi-recipient photos.</p>
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
