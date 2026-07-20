import { useState } from "react";
import { sssCombine, sssSplit, type SecretShare } from "../api";
import { Banner, Seg, errMsg } from "../shared";

type Mode = "split" | "combine";

const hex = (arr: number[]): string => arr.map((b) => (b & 0xff).toString(16).padStart(2, "0")).join("");
const encodeShare = (s: SecretShare): string => `${s.x}-${hex(s.y)}`;

function parseShare(line: string): SecretShare | null {
  const t = line.trim();
  const dash = t.indexOf("-");
  if (dash <= 0) return null;
  const x = parseInt(t.slice(0, dash), 10);
  const h = t.slice(dash + 1).trim();
  if (!Number.isInteger(x) || x < 1 || x > 255 || !h || h.length % 2) return null;
  const y: number[] = [];
  for (let i = 0; i < h.length; i += 2) {
    const v = parseInt(h.substr(i, 2), 16);
    if (Number.isNaN(v)) return null;
    y.push(v);
  }
  return { x, y };
}

export function KeysTab() {
  const [mode, setMode] = useState<Mode>("split");
  return (
    <section className="panel active">
      <div className="card">
        <h2>Split a secret into key-shares</h2>
        <p className="hint">Any threshold of shares rebuilds a secret.</p>
        <Seg<Mode> options={[{ id: "split", label: "Split" }, { id: "combine", label: "Combine" }]} value={mode} onChange={setMode} />
        {mode === "split" ? <SplitPane /> : <CombinePane />}
      </div>
    </section>
  );
}

function SplitPane() {
  const [secret, setSecret] = useState("");
  const [threshold, setThreshold] = useState(2);
  const [shares, setShares] = useState(3);
  const [result, setResult] = useState<SecretShare[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(-1);

  async function doSplit() {
    setError(null); setResult(null);
    try {
      const bytes = [...new TextEncoder().encode(secret)];
      setResult(await sssSplit(bytes, threshold, Math.max(shares, threshold)));
    } catch (e) { setError(errMsg(e)); }
  }

  const nums = [2, 3, 4, 5, 6, 7, 8];
  return (
    <>
      <label>Secret</label>
      <textarea value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="The passphrase or note to split" />
      <div className="row">
        <div>
          <label>Threshold <span className="small">needed to rebuild</span></label>
          <select value={threshold} onChange={(e) => { const t = Number(e.target.value); setThreshold(t); if (shares < t) setShares(t); }}>
            {nums.map((n) => <option key={n} value={n}>{n} shares</option>)}
          </select>
        </div>
        <div>
          <label>Total shares</label>
          <select value={shares} onChange={(e) => setShares(Number(e.target.value))}>
            {nums.filter((n) => n >= threshold).map((n) => <option key={n} value={n}>{n} shares</option>)}
          </select>
        </div>
      </div>
      <button className="primary" disabled={!secret} onClick={doSplit}>Split into shares</button>
      {error && <div style={{ marginTop: 16 }}><Banner ok={false}>{error}</Banner></div>}
      {result && (
        <div className="out">
          <div className="small" style={{ marginBottom: 8 }}>Give each person one share. Any {threshold} of {Math.max(shares, threshold)} rebuild the secret.</div>
          {result.map((s, i) => {
            const str = encodeShare(s);
            return (
              <div className="share-line" key={i}>
                <div><span className="small">Share {i + 1}</span><code>{str}</code></div>
                <button className="ghost" onClick={() => { navigator.clipboard?.writeText(str); setCopied(i); setTimeout(() => setCopied(-1), 1200); }}>{copied === i ? "Copied" : "Copy"}</button>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

function CombinePane() {
  const [text, setText] = useState("");
  const [out, setOut] = useState<{ ok: boolean; msg: string } | null>(null);

  async function doCombine() {
    setOut(null);
    const shares = text.split("\n").map(parseShare).filter((s): s is SecretShare => s !== null);
    if (shares.length < 2) { setOut({ ok: false, msg: "Need at least 2 valid shares." }); return; }
    try {
      const bytes = await sssCombine(shares);
      setOut({ ok: true, msg: new TextDecoder().decode(new Uint8Array(bytes)) });
    } catch (e) { setOut({ ok: false, msg: errMsg(e) }); }
  }

  return (
    <>
      <label>Paste shares <span className="small">one per line</span></label>
      <textarea value={text} onChange={(e) => setText(e.target.value)} placeholder={"3-1a2b3c…\n5-9f8e7d…"} />
      <button className="primary" disabled={!text.trim()} onClick={doCombine}>Reconstruct secret</button>
      {out && (out.ok
        ? <div className="out"><div className="result-banner ok">🔓 Reconstructed the secret.</div><pre>{out.msg}</pre></div>
        : <div style={{ marginTop: 16 }}><Banner ok={false}>{out.msg}</Banner></div>)}
    </>
  );
}
