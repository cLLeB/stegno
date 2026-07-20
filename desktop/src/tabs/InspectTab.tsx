import { useState, type ReactNode } from "react";
import { detectLsb, fingerprint, scanStructure } from "../api";
import { Drop, StatRow, errMsg, pickFile, type Picked } from "../shared";

export function InspectTab() {
  const [file, setFile] = useState<Picked | null>(null);
  const [out, setOut] = useState<ReactNode>(null);

  async function doInspect() {
    if (!file) return;
    try {
      const scan = await scanStructure(file.bytes);
      const guesses = await fingerprint(file.bytes);
      const detection = await detectLsb(file.bytes).catch(() => null);
      setOut(
        <>
          <div className={`result-banner ${scan.suspicious ? "bad" : "ok"}`}>{scan.suspicious ? "⚠️ Signs of hidden data found" : "✅ Nothing obvious found"}</div>
          <div className="small" style={{ marginTop: 8 }}>Format: <b>{scan.format}</b></div>
          {scan.findings.length > 0 && (
            <table><thead><tr><th>Signal</th><th>Detail</th></tr></thead><tbody>
              {scan.findings.map((f, i) => <tr key={i}><td>{f.kind}{f.severity >= 2 && <span className="tag bad" style={{ marginLeft: 6 }}>strong</span>}</td><td>{f.detail}</td></tr>)}
            </tbody></table>
          )}
          {guesses.length > 0 && (
            <>
              <label>Likely method</label>
              <table><tbody>{guesses.slice(0, 4).map((g, i) => <tr key={i}><td>{(g.confidence * 100).toFixed(0)}%</td><td>{g.label}</td></tr>)}</tbody></table>
            </>
          )}
          {detection && (
            <>
              <label>Statistical LSB analysis</label>
              <div className="small" style={{ marginBottom: 4 }}>Overall likelihood of hidden data: <b>{(detection.mlConfidence * 100).toFixed(0)}%</b></div>
              <StatRow k="Chi-square p" v={detection.chiSquareP.toFixed(3)} />
              <StatRow k="RS regularity gap" v={detection.rsRegularityGap.toFixed(3)} />
              <StatRow k="Sample-pair rate" v={detection.samplePairRate.toFixed(3)} />
              <StatRow k="HoG uniformity" v={detection.hogUniformity.toFixed(3)} />
              <StatRow k="Noise residual energy" v={detection.noiseResidualEnergy.toFixed(3)} />
            </>
          )}
        </>
      );
    } catch (e) {
      setOut(<div className="result-banner bad">⚠️ {errMsg(e)}</div>);
    }
  }

  return (
    <section className="panel active">
      <div className="card">
        <h2>Inspect a file</h2>
        <p className="hint">Structure, statistics, and a method guess.</p>
        <label>File to inspect</label>
        <Drop label={file ? file.name : "Choose a file"} icon={file ? "✅" : "🔍"} has={!!file} onClick={async () => { setFile(await pickFile()); setOut(null); }} />
        <button className="primary" disabled={!file} onClick={doInspect}>Inspect</button>
        <div className="out">{out}</div>
      </div>
    </section>
  );
}
