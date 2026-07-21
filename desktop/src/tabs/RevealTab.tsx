import { useState } from "react";
import { extractAuto, extractComposite, type Revealed } from "../api";
import { RevealedOut, saveRevealed, type RevealedView } from "../revealed";
import { Drop, errMsg, pickFiles, type Picked } from "../shared";

export function RevealTab() {
  const [files, setFiles] = useState<Picked[]>([]);
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<RevealedView | null>(null);

  async function doReveal() {
    if (!files.length) return;
    setBusy(true); setView(null);
    try {
      let rv: Revealed = await extractComposite(files.map((f) => f.bytes), pass);
      // A file hidden with a chosen method isn't composite-framed, so fall back
      // to the auto-detecting single-file path before giving up.
      if (rv.kind === "none" && files.length === 1) {
        rv = (await extractAuto(files[0].bytes, pass)).revealed;
      }
      setView(await saveRevealed(rv));
    } catch (e) {
      setView({ ok: false, message: errMsg(e) });
    } finally { setBusy(false); }
  }

  return (
    <section className="panel active">
      <div className="card">
        <h2>Reveal a secret</h2>
        <p className="hint">
          Pick the stego file(s) and a password. The carrier and method are detected automatically.
        </p>
        <label>Stego file(s)</label>
        <Drop
          label={files.length
            ? `${files.length} file(s): ${files.map((f) => f.name).join(", ")}`
            : "Choose the file(s) — any type. If it was split, pick all the parts."}
          icon={files.length ? "✅" : "🗂️"}
          has={files.length > 0}
          onClick={async () => {
            const picked = await pickFiles();
            if (picked.length) { setFiles(picked); setView(null); }
          }}
        />
        <label>Password</label>
        <input
          type="password"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
          placeholder="The password used to hide it"
        />
        <button className="primary" disabled={!files.length || busy} onClick={doReveal}>
          {busy ? "Revealing…" : "Reveal"}
        </button>
        {view && <RevealedOut view={view} />}
      </div>
    </section>
  );
}
