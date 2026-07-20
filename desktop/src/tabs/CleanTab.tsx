import { useState, type ReactNode } from "react";
import { sanitize } from "../api";
import { Drop, errMsg, pickFile, saveBytes, type Picked } from "../shared";

export function CleanTab() {
  const [file, setFile] = useState<Picked | null>(null);
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
          <div className="result-banner ok">🧼 {r.changed ? "Cleaned. Hidden payload destroyed." : "Nothing hidden was found; copied as-is."}</div>
          {r.actions.length > 0 && <ul className="small">{r.actions.map((a, i) => <li key={i}>{a}</li>)}</ul>}
        </>
      );
    } catch (e) {
      setOut(<div className="result-banner bad">⚠️ {errMsg(e)}</div>);
    }
  }

  return (
    <section className="panel active">
      <div className="card">
        <h2>Remove hidden data</h2>
        <p className="hint">Destroys any hidden payload. Photo looks the same.</p>
        <label>File to clean</label>
        <Drop label={file ? file.name : "Choose a file"} icon={file ? "✅" : "🧼"} has={!!file} onClick={async () => { setFile(await pickFile()); setOut(null); }} />
        <button className="primary" disabled={!file} onClick={doClean}>Sanitize & save</button>
        <div className="out">{out}</div>
      </div>
    </section>
  );
}
