import { useEffect, useMemo, useState } from "react";
import {
  capacity,
  decoyCapacity,
  embedAdvanced,
  embedTextWithDecoy,
  passphraseStrength,
  planEmbedding,
  type MethodInfo,
  type MethodRecommendation,
  type PassphraseStrength,
} from "../api";
import { Banner, Drop, IMAGE_ACCEPT, errMsg, pickFile, saveBytes, type Picked } from "../shared";

const STRENGTH_COLORS = ["var(--bad)", "var(--bad)", "var(--warn)", "var(--ok)", "var(--ok)"];
const STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];

export function HideTab({ methods }: { methods: MethodInfo[] }) {
  const imageMethods = useMemo(() => methods.filter((m) => m.media === "Image"), [methods]);
  const [cover, setCover] = useState<Picked | null>(null);
  const [text, setText] = useState("");
  const [pass, setPass] = useState("");
  const [method, setMethod] = useState("lsb_seeded");
  const [robust, setRobust] = useState(0);
  const [compress, setCompress] = useState(false);
  const [decoy, setDecoy] = useState(false);
  const [decoyText, setDecoyText] = useState("");
  const [decoyPass, setDecoyPass] = useState("");
  const [cap, setCap] = useState<number | null>(null);
  const [strength, setStrength] = useState<PassphraseStrength | null>(null);
  const [recs, setRecs] = useState<MethodRecommendation[]>([]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  useEffect(() => {
    if (!cover) return;
    if (decoy) decoyCapacity(cover.bytes).then(setCap).catch(() => setCap(null));
    else capacity(method, cover.bytes).then(setCap).catch(() => setCap(null));
  }, [cover, method, decoy]);

  async function onPass(v: string) {
    setPass(v);
    setStrength(v ? await passphraseStrength(v) : null);
  }
  async function suggest() {
    if (!cover) return;
    setRecs(await planEmbedding(cover.bytes, new TextEncoder().encode(text).length).catch(() => []));
  }
  async function doHide() {
    if (!cover) return;
    setBusy(true); setResult(null);
    try {
      const stego = decoy
        ? await embedTextWithDecoy(cover.bytes, text, pass, decoyText, decoyPass)
        : await embedAdvanced(method, cover.bytes, { kind: "text", text }, pass, robust as 0 | 1 | 2 | 3, compress);
      const saved = await saveBytes(stego, "stego.png");
      setResult({ ok: true, msg: saved ? `Hidden in a ${(stego.length / 1024).toFixed(0)} KB image saved.` : "Ready (save cancelled)." });
    } catch (e) {
      setResult({ ok: false, msg: errMsg(e) });
    } finally { setBusy(false); }
  }

  const ready = !!cover && !!text && !!pass && (!decoy || (!!decoyText && !!decoyPass));

  return (
    <section className="panel active">
      <div className="card">
        <h2>Hide a secret</h2>
        <p className="hint">Hide a message inside a photo.</p>

        <label>Cover image</label>
        <Drop label={cover ? cover.name : "Choose a photo (PNG, JPG…)"} icon={cover ? "✅" : "📷"} has={!!cover}
          onClick={async () => setCover(await pickFile(IMAGE_ACCEPT))} />

        <label>Secret message</label>
        <textarea value={text} onChange={(e) => setText(e.target.value)} placeholder="Type the message you want to hide…" />

        <label>Password</label>
        <input type="password" value={pass} onChange={(e) => onPass(e.target.value)} placeholder="A strong passphrase" />
        <div className="meter"><span style={{ width: strength ? `${((strength.score + 1) / 5) * 100}%` : "0", background: strength ? STRENGTH_COLORS[strength.score] : "" }} /></div>
        <div className="small">{strength ? <><b>{STRENGTH_LABELS[strength.score]}</b> · ~{strength.entropyBits.toFixed(0)} bits · cracks in {strength.crackTimeDisplay}{strength.warning ? <span className="err"> · {strength.warning}</span> : null}</> : "Strength appears as you type."}</div>

        <label className="check"><input type="checkbox" checked={decoy} onChange={(e) => setDecoy(e.target.checked)} /> <span>Add a decoy message <span className="small">plausible deniability</span></span></label>
        {decoy && (
          <>
            <p className="hint" style={{ marginTop: 12 }}>Hand over the decoy password. The real one stays hidden.</p>
            <label>Decoy message</label>
            <textarea value={decoyText} onChange={(e) => setDecoyText(e.target.value)} placeholder="A believable, harmless message" />
            <label>Decoy password</label>
            <input type="password" value={decoyPass} onChange={(e) => setDecoyPass(e.target.value)} placeholder="The password you'd hand over" />
          </>
        )}

        {!decoy && (
          <>
            <label>Method</label>
            <select value={method} onChange={(e) => setMethod(e.target.value)}>
              {imageMethods.map((m) => <option key={m.id} value={m.id}>{m.displayName}</option>)}
            </select>
            <button className="ghost" style={{ marginTop: 10, width: "100%" }} disabled={!cover} onClick={suggest}>💡 Suggest the best method</button>
            {recs.length > 0 && (
              <div id="planOut">
                {recs.slice(0, 4).map((r) => (
                  <button key={r.methodId} className="rec" onClick={() => { setMethod(r.methodId); setRecs([]); }}>
                    <b>{r.fits ? "✅" : "⚠️"} {r.displayName}</b>
                    <span className={`tag ${r.stealthTier >= 2 ? "ok" : r.stealthTier === 1 ? "warn" : "bad"}`}>stealth {r.stealthTier}/3</span>
                    <span className="small">{r.note}</span>
                  </button>
                ))}
              </div>
            )}
          </>
        )}
        {cap != null && <div className="small">Room for about {cap.toLocaleString()} bytes{decoy ? " per slot" : ""}.</div>}

        {!decoy && (
          <div className="row">
            <div>
              <label>Toughness</label>
              <select value={robust} onChange={(e) => setRobust(Number(e.target.value))}>
                <option value={0}>Standard</option>
                <option value={1}>Rugged</option>
                <option value={2}>Extra rugged</option>
                <option value={3}>Maximum</option>
              </select>
            </div>
            <div>
              <label>Squeeze</label>
              <label className="check"><input type="checkbox" checked={compress} onChange={(e) => setCompress(e.target.checked)} /> <span>Compress first <span className="small">fit more in</span></span></label>
            </div>
          </div>
        )}

        <button className="primary" disabled={!ready || busy} onClick={doHide}>{busy ? "Hiding…" : "Hide & save"}</button>
        {result && <div style={{ marginTop: 16 }}><Banner ok={result.ok}>{result.msg}</Banner></div>}
      </div>
    </section>
  );
}
