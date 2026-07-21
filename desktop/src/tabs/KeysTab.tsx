import { useState } from "react";
import { sssCombineSecret, sssSplitSecret, type SecretInput, type SecretShare } from "../api";
import { RevealedOut, saveRevealed, type RevealedView } from "../revealed";
import { Banner, Drop, Seg, errMsg, pickFile, type Picked } from "../shared";

type Mode = "split" | "combine";
type SecretType = "text" | "file";

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
        <h2>Key-shares</h2>
        <p className="hint">
          Any threshold of shares rebuilds a secret. A shared file comes back under its own name.
        </p>
        <Seg<Mode>
          options={[{ id: "split", label: "Split" }, { id: "combine", label: "Combine" }]}
          value={mode}
          onChange={setMode}
        />
        {mode === "split" ? <SplitPane /> : <CombinePane />}
      </div>
    </section>
  );
}

const NUMS = [2, 3, 4, 5, 6, 7, 8];

function SplitPane() {
  const [type, setType] = useState<SecretType>("text");
  const [secret, setSecret] = useState("");
  const [file, setFile] = useState<Picked | null>(null);
  const [threshold, setThreshold] = useState(2);
  const [shares, setShares] = useState(3);
  const [result, setResult] = useState<SecretShare[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(-1);

  const total = Math.max(shares, threshold);
  const ready = type === "text" ? !!secret : !!file;

  async function doSplit() {
    setError(null); setResult(null);
    try {
      // Split the *typed* secret so a shared file recombines under its own name
      // rather than as anonymous bytes.
      const input: SecretInput = type === "text"
        ? { kind: "text", text: secret }
        : { kind: "file", name: file!.name, bytes: file!.bytes };
      setResult(await sssSplitSecret(input, threshold, total));
    } catch (e) { setError(errMsg(e)); }
  }

  return (
    <>
      <label>Secret</label>
      <Seg<SecretType>
        options={[{ id: "text", label: "Text" }, { id: "file", label: "File" }]}
        value={type}
        onChange={(t) => { setType(t); setResult(null); }}
      />
      {type === "text" ? (
        <textarea
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          placeholder="The passphrase or note to split"
        />
      ) : (
        <Drop
          mini
          label={file ? file.name : "Choose a file — any type"}
          icon={file ? "✅" : "📎"}
          has={!!file}
          onClick={async () => { const f = await pickFile(); if (f) setFile(f); }}
        />
      )}
      <div className="row">
        <div>
          <label>Threshold <span className="small">needed to rebuild</span></label>
          <select
            value={threshold}
            onChange={(e) => { const t = Number(e.target.value); setThreshold(t); if (shares < t) setShares(t); }}
          >
            {NUMS.map((n) => <option key={n} value={n}>{n} shares</option>)}
          </select>
        </div>
        <div>
          <label>Total shares</label>
          <select value={total} onChange={(e) => setShares(Number(e.target.value))}>
            {NUMS.filter((n) => n >= threshold).map((n) => <option key={n} value={n}>{n} shares</option>)}
          </select>
        </div>
      </div>
      <button className="primary" disabled={!ready} onClick={doSplit}>Split into shares</button>
      {error && <div style={{ marginTop: 16 }}><Banner ok={false}>{error}</Banner></div>}
      {result && (
        <div className="out">
          <div className="small" style={{ marginBottom: 8 }}>
            Give each person one share. Any {threshold} of {total} rebuild the secret.
          </div>
          {result.map((s, i) => {
            const str = encodeShare(s);
            return (
              <div className="share-line" key={i}>
                <div><span className="small">Share {i + 1}</span><code>{str}</code></div>
                <button
                  className="ghost"
                  onClick={() => {
                    navigator.clipboard?.writeText(str);
                    setCopied(i);
                    setTimeout(() => setCopied(-1), 1200);
                  }}
                >
                  {copied === i ? "Copied" : "Copy"}
                </button>
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
  const [view, setView] = useState<RevealedView | null>(null);

  async function doCombine() {
    setView(null);
    const shares = text.split("\n").map(parseShare).filter((s): s is SecretShare => s !== null);
    if (shares.length < 2) { setView({ ok: false, message: "Need at least 2 valid shares." }); return; }
    try {
      // Restores whatever was split — a message, or a file under its own name.
      setView(await saveRevealed(await sssCombineSecret(shares)));
    } catch (e) { setView({ ok: false, message: errMsg(e) }); }
  }

  return (
    <>
      <label>Paste shares <span className="small">one per line</span></label>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={"3-1a2b3c…\n5-9f8e7d…"}
      />
      <button className="primary" disabled={!text.trim()} onClick={doCombine}>Reconstruct secret</button>
      {view && <RevealedOut view={view} />}
    </>
  );
}
