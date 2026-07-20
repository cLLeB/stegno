import { useMemo, useState } from "react";
import {
  benchmarkKdf,
  bitPlane,
  changeMap,
  changeRate,
  detectability,
  quality,
  selfTest,
  type Detectability,
  type KdfBenchmark,
  type MethodInfo,
  type Quality,
  type SelfTestResult,
} from "../api";
import { Banner, Drop, IMAGE_ACCEPT, StatRow, blobUrl, errMsg, pickFile, type Picked } from "../shared";

export function LabTab({ methods }: { methods: MethodInfo[] }) {
  const imageMethods = useMemo(() => methods.filter((m) => m.media === "Image"), [methods]);
  return (
    <section className="panel active">
      <BitPlaneCard />
      <CompareCard />
      <DetectabilityCard methods={imageMethods} />
      <DiagnosticsCard />
    </section>
  );
}

function BitPlaneCard() {
  const [img, setImg] = useState<Picked | null>(null);
  const [channel, setChannel] = useState(0);
  const [plane, setPlane] = useState(0);
  const [src, setSrc] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function render() {
    if (!img) return;
    setError(null);
    try { setSrc(blobUrl(await bitPlane(img.bytes, channel, plane), "image/png")); }
    catch (e) { setError(errMsg(e)); }
  }

  return (
    <div className="card">
      <h2>Bit-plane viewer</h2>
      <p className="hint">See a single bit layer of a photo — hidden LSB data shows up as visible noise.</p>
      <Drop label={img ? img.name : "Choose a photo"} icon={img ? "✅" : "📷"} has={!!img} onClick={async () => { setImg(await pickFile(IMAGE_ACCEPT)); setSrc(null); }} />
      <div className="row">
        <div><label>Channel</label><select value={channel} onChange={(e) => setChannel(Number(e.target.value))}><option value={0}>Red</option><option value={1}>Green</option><option value={2}>Blue</option></select></div>
        <div><label>Plane</label><select value={plane} onChange={(e) => setPlane(Number(e.target.value))}>{[0, 1, 2, 3, 4, 5, 6, 7].map((p) => <option key={p} value={p}>{p}</option>)}</select></div>
      </div>
      <button className="primary" disabled={!img} onClick={render}>Render bit plane</button>
      {error && <div style={{ marginTop: 16 }}><Banner ok={false}>{error}</Banner></div>}
      {src && <div className="out"><img className="render" src={src} alt="bit plane" /></div>}
    </div>
  );
}

function CompareCard() {
  const [cover, setCover] = useState<Picked | null>(null);
  const [stego, setStego] = useState<Picked | null>(null);
  const [busy, setBusy] = useState(false);
  const [rate, setRate] = useState<number | null>(null);
  const [q, setQ] = useState<Quality | null>(null);
  const [map, setMap] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function compare() {
    if (!cover || !stego) return;
    setBusy(true); setError(null); setMap(null);
    try {
      setRate(await changeRate(cover.bytes, stego.bytes));
      setQ(await quality(cover.bytes, stego.bytes));
      setMap(blobUrl(await changeMap(cover.bytes, stego.bytes), "image/png"));
    } catch (e) { setError(errMsg(e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="card">
      <h2>Compare original vs stego</h2>
      <p className="hint">Measure how much a photo changed after hiding — quality scores and a change map.</p>
      <div className="row">
        <div><label>Original photo</label><Drop mini label={cover ? cover.name : "Original"} icon={cover ? "✅" : "📷"} has={!!cover} onClick={async () => setCover(await pickFile(IMAGE_ACCEPT))} /></div>
        <div><label>Stego photo</label><Drop mini label={stego ? stego.name : "Stego"} icon={stego ? "✅" : "🖼️"} has={!!stego} onClick={async () => setStego(await pickFile(IMAGE_ACCEPT))} /></div>
      </div>
      <button className="primary" disabled={!cover || !stego || busy} onClick={compare}>{busy ? "Comparing…" : "Compare"}</button>
      {error && <div style={{ marginTop: 16 }}><Banner ok={false}>{error}</Banner></div>}
      {rate != null && <div className="out">
        <StatRow k="Pixels changed" v={`${(rate * 100).toFixed(2)}%`} />
        {q && <><StatRow k="PSNR" v={`${q.psnrDb.toFixed(1)} dB`} /><StatRow k="SSIM" v={q.ssim.toFixed(4)} /><StatRow k="MSE" v={q.mse.toFixed(3)} /></>}
        {map && <><label>Change map</label><img className="render" src={map} alt="change map" /></>}
      </div>}
    </div>
  );
}

function DetectabilityCard({ methods }: { methods: MethodInfo[] }) {
  const [cover, setCover] = useState<Picked | null>(null);
  const [method, setMethod] = useState("lsb_seeded");
  const [payload, setPayload] = useState(1024);
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<Detectability | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function estimate() {
    if (!cover) return;
    setBusy(true); setError(null);
    try { setReport(await detectability(method, cover.bytes, payload)); }
    catch (e) { setError(errMsg(e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="card">
      <h2>Will it be detectable?</h2>
      <p className="hint">Estimate how much hiding a payload of a given size would raise a detector's suspicion.</p>
      <Drop mini label={cover ? cover.name : "Choose a cover"} icon={cover ? "✅" : "📷"} has={!!cover} onClick={async () => setCover(await pickFile(IMAGE_ACCEPT))} />
      <div className="row">
        <div><label>Method</label><select value={method} onChange={(e) => setMethod(e.target.value)}>{methods.map((m) => <option key={m.id} value={m.id}>{m.displayName}</option>)}</select></div>
        <div><label>Payload size <span className="small">bytes</span></label><input type="number" min={1} value={payload} onChange={(e) => setPayload(Number(e.target.value))} /></div>
      </div>
      <button className="primary" disabled={!cover || busy} onClick={estimate}>{busy ? "Estimating…" : "Estimate"}</button>
      {error && <div style={{ marginTop: 16 }}><Banner ok={false}>{error}</Banner></div>}
      {report && <div className="out">
        <div className={`result-banner ${report.delta < 0.15 ? "ok" : "bad"}`}>{report.verdict}</div>
        <StatRow k="Suspicion (clean)" v={`${(report.cleanConfidence * 100).toFixed(0)}%`} />
        <StatRow k="Suspicion (with payload)" v={`${(report.stegoConfidence * 100).toFixed(0)}%`} />
        <StatRow k="Increase" v={`${(report.delta * 100).toFixed(0)}%`} />
        <StatRow k="PSNR" v={`${report.psnrDb.toFixed(1)} dB`} />
      </div>}
    </div>
  );
}

function DiagnosticsCard() {
  const [busy, setBusy] = useState("");
  const [tests, setTests] = useState<SelfTestResult[] | null>(null);
  const [bench, setBench] = useState<KdfBenchmark | null>(null);

  async function runTests() {
    setBusy("test"); setBench(null);
    try { setTests(await selfTest()); } finally { setBusy(""); }
  }
  async function runBench() {
    setBusy("bench"); setTests(null);
    try { setBench(await benchmarkKdf()); } finally { setBusy(""); }
  }

  const passed = tests ? tests.filter((t) => t.ok).length : 0;
  return (
    <div className="card">
      <h2>Engine self-test &amp; benchmark</h2>
      <p className="hint">Round-trip every method to confirm the engine is healthy, and time the password hashing on this device.</p>
      <div className="row">
        <button className="ghost" style={{ flex: 1 }} disabled={!!busy} onClick={runTests}>{busy === "test" ? "Testing…" : "🩺 Run self-test"}</button>
        <button className="ghost" style={{ flex: 1 }} disabled={!!busy} onClick={runBench}>{busy === "bench" ? "Benchmarking…" : "⏱️ Benchmark hashing"}</button>
      </div>
      {tests && <div className="out">
        <div className={`result-banner ${passed === tests.length ? "ok" : "bad"}`}>{passed} of {tests.length} methods passed</div>
        <table><tbody>{tests.map((t, i) => <tr key={i}><td>{t.ok ? "✅" : "❌"} {t.methodId}</td><td className="small">{t.detail}</td></tr>)}</tbody></table>
      </div>}
      {bench && <div className="out">
        <div className="result-banner ok">{bench.verdict}</div>
        <StatRow k="Time" v={`${bench.millis.toFixed(0)} ms`} />
        <StatRow k="Memory" v={`${(bench.memoryKib / 1024).toFixed(0)} MiB`} />
        <StatRow k="Iterations" v={String(bench.iterations)} />
      </div>}
    </div>
  );
}
