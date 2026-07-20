import { useState } from "react";
import { embedMulti, type RecipientInput } from "../api";
import { Banner, Drop, IMAGE_ACCEPT, errMsg, pickFile, saveBytes, type Picked } from "../shared";

export function ShareTab() {
  const [cover, setCover] = useState<Picked | null>(null);
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
    } catch (e) {
      setResult({ ok: false, msg: errMsg(e) });
    } finally { setBusy(false); }
  }

  return (
    <section className="panel active">
      <div className="card">
        <h2>One photo, many people</h2>
        <p className="hint">A different message for each person.</p>
        <label>Cover image</label>
        <Drop label={cover ? cover.name : "Choose a photo"} icon={cover ? "✅" : "📷"} has={!!cover} onClick={async () => setCover(await pickFile(IMAGE_ACCEPT))} />
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
        {result && <div style={{ marginTop: 16 }}><Banner ok={result.ok}>{result.msg}</Banner></div>}
      </div>
    </section>
  );
}
