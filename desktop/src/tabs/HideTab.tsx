// Unified composer: any number of covers of any type, any number of secrets.
// One secret + one cover is a plain hide; more of either layers decoys,
// recipients and splits on top of the same primitive.
import { useEffect, useState } from "react";
import {
  capacity,
  compositeCapacity,
  coverInfo,
  embedAdvanced,
  embedComposite,
  ffmpegStatus,
  looksLikeVideo,
  planEmbedding,
  videoToY4m,
  y4mToVideo,
  type CoverInfo,
  type FfmpegStatus,
  type MethodInfo,
  type MethodRecommendation,
} from "../api";
import { kindLabel, stemOf, stegoNameFor } from "../carrier";
import { Banner, Drop, errMsg, pickFiles, savePath, saveBytes, type Picked } from "../shared";
import {
  MAX_ENTRIES,
  SecretEntry,
  entryPayloadLen,
  entryReady,
  entrySecret,
  newEntry,
  type Entry,
} from "./SecretEntry";

interface CoverFile extends Picked {
  /** Null when the engine could not classify it; embedding still reports why. */
  info: CoverInfo | null;
}

/**
 * A cover as it will actually be handed to the engine. Compressed video is
 * decoded to lossless y4m first when frame-level embedding is on, so the bytes
 * here can differ from the bytes that were picked.
 */
interface PreparedCover {
  cover: CoverFile;
  bytes: number[];
  /** True when this came from a compressed video and must be re-encoded after. */
  transcoded: boolean;
}

/** Plain-language summary of what the current cover/secret counts will do. */
function describeScheme(covers: number, secrets: number, single: boolean): string {
  const parts =
    secrets === 1
      ? ["one secret"]
      : [`${secrets} secrets, each with its own password (hand one over as a decoy)`];
  parts.push(
    covers === 1
      ? "in one cover"
      : `split across ${covers} covers — all of them are needed to rebuild`
  );
  const scheme = single ? "Chosen method." : "Layered region scheme (method is chosen for you).";
  return `${scheme} ${parts.join(", ")}.`;
}

async function describeCovers(picked: Picked[]): Promise<CoverFile[]> {
  return Promise.all(
    picked.map(async (c) => ({
      ...c,
      info: await coverInfo(c.bytes).catch(() => null),
    }))
  );
}

export function HideTab({ methods }: { methods: MethodInfo[] }) {
  const [covers, setCovers] = useState<CoverFile[]>([]);
  const [entries, setEntries] = useState<Entry[]>(() => [newEntry()]);
  const [method, setMethod] = useState("lsb_seeded");
  const [robust, setRobust] = useState(0);
  const [compress, setCompress] = useState(false);
  const [cap, setCap] = useState<number | null>(null);
  const [recs, setRecs] = useState<MethodRecommendation[]>([]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [ffmpeg, setFfmpeg] = useState<FfmpegStatus | null>(null);
  const [frameLevel, setFrameLevel] = useState(false);
  /** False once you pick a method yourself; a new cover hands control back. */
  const [methodIsAuto, setMethodIsAuto] = useState(true);
  const [autoNote, setAutoNote] = useState("");

  const hasVideo = covers.some((c) => looksLikeVideo(c.name));
  // Offered only when there is something to transcode and a tool to do it with.
  const canFrameLevel = hasVideo && ffmpeg?.available === true;
  const useFrameLevel = canFrameLevel && frameLevel;
  // Transcoded covers are carried by the video carrier, which the composite
  // path drives — a registry method has no way to read raw y4m.
  const single = entries.length === 1 && covers.length === 1 && !useFrameLevel;

  useEffect(() => { ffmpegStatus().then(setFfmpeg).catch(() => setFfmpeg(null)); }, []);

  useEffect(() => {
    // With frame-level on, the picked bytes are the *compressed* file; its real
    // capacity is only known once ffmpeg has decoded it, which is far too slow
    // to run on every keystroke. Report nothing rather than a wrong number.
    if (!covers.length || useFrameLevel) { setCap(null); return; }
    let live = true;
    const bytes = covers.map((c) => c.bytes);
    const pending = single
      ? capacity(method, bytes[0])
      : compositeCapacity(bytes, Math.max(entries.length, 1));
    pending
      .then((n) => { if (live) setCap(n); })
      .catch(() => { if (live) setCap(null); });
    return () => { live = false; };
  }, [covers, entries.length, method, single, useFrameLevel]);

  // The method picker only governs a single-secret hide; a mix is placed by the
  // layered region scheme. Clear stale suggestions rather than leave them
  // looking like they still apply.
  useEffect(() => { if (!single) setRecs([]); }, [single]);

  // Pick the best method automatically, and keep re-picking as the cover or the
  // secret changes — until you override it, after which your choice stands.
  //
  // Debounced because planning asks every method for its capacity and the image
  // methods each decode the cover: about 1.8s on a 6-megapixel photo. Running
  // that per keystroke would make typing unusable.
  const payloadLen = entryPayloadLen(entries[0]);
  useEffect(() => {
    if (!methodIsAuto || !single || !covers.length) {
      setAutoNote(methodIsAuto ? "" : "Method chosen by you.");
      return;
    }
    let live = true;
    setAutoNote("Choosing the best method…");
    const t = setTimeout(() => {
      planEmbedding(covers[0].bytes, payloadLen)
        .then((recs) => {
          if (!live) return;
          const best = recs.find((r) => r.fits);
          if (!best) {
            setAutoNote("No method fits this secret in this cover.");
            return;
          }
          setMethod(best.methodId);
          setAutoNote(`Chosen for you: ${best.displayName} — ${best.note}`);
        })
        .catch(() => { if (live) setAutoNote(""); });
    }, 400);
    return () => { live = false; clearTimeout(t); };
  }, [covers, single, payloadLen, methodIsAuto]);

  function updateEntry(i: number, next: Entry) {
    setEntries((prev) => prev.map((e, j) => (j === i ? next : e)));
  }
  function removeEntry(i: number) {
    setEntries((prev) => prev.filter((_, j) => j !== i));
  }
  function addEntry() {
    setEntries((prev) => (prev.length < MAX_ENTRIES ? [...prev, newEntry()] : prev));
  }

  async function chooseCovers() {
    const picked = await pickFiles();
    if (!picked.length) return;
    // A new cover is a new situation, so resume choosing automatically.
    setMethodIsAuto(true);
    setCovers(await describeCovers(picked));
  }

  async function suggest() {
    if (!covers.length) return;
    setRecs(await planEmbedding(covers[0].bytes, entryPayloadLen(entries[0])).catch(() => []));
  }

  async function hideSingle(): Promise<string> {
    const cover = covers[0];
    const stego = await embedAdvanced(
      method, cover.bytes, entrySecret(entries[0]), entries[0].pass,
      robust as 0 | 1 | 2 | 3, compress
    );
    // A chosen method may re-encode (image methods emit PNG), so trust the
    // engine's view of the result over the cover's.
    const info = await coverInfo(stego).catch(() => cover.info);
    const saved = await saveBytes(stego, stegoNameFor(cover.name, info, "stego"));
    return saved ? "Hid your secret." : "Ready (save cancelled).";
  }

  /** Decode compressed video to y4m when frame-level embedding is on. */
  async function prepareCovers(): Promise<PreparedCover[]> {
    return Promise.all(
      covers.map(async (cover) => {
        if (useFrameLevel && looksLikeVideo(cover.name)) {
          return { cover, bytes: await videoToY4m(cover.path), transcoded: true };
        }
        return { cover, bytes: cover.bytes, transcoded: false };
      })
    );
  }

  /**
   * Save one stego part. A transcoded clip is handed back to ffmpeg for a
   * *lossless* FFV1 re-encode — anything lossy would discard the payload.
   */
  async function savePart(part: number[], p: PreparedCover, fallbackStem: string): Promise<void> {
    if (p.transcoded) {
      const out = await savePath(`${stemOf(p.cover.name)}-hidden.mkv`);
      if (out) await y4mToVideo(part, p.cover.path, out);
      return;
    }
    await saveBytes(part, stegoNameFor(p.cover?.name ?? null, p.cover?.info ?? null, fallbackStem));
  }

  async function hideComposite(prepared: PreparedCover[]): Promise<string> {
    const parts = await embedComposite(
      prepared.map((p) => p.bytes),
      entries.map((e) => ({ secret: entrySecret(e), passphrase: e.pass })),
      robust as 0 | 1 | 2 | 3,
      compress
    );
    for (let i = 0; i < parts.length; i++) {
      await savePart(parts[i], prepared[i], `part${i + 1}`);
    }
    const note = prepared.some((p) => p.transcoded)
      ? " Re-encoded losslessly — a lossy re-encode would destroy it."
      : "";
    return (
      (parts.length > 1
        ? `Hid ${entries.length} secret(s) across ${parts.length} covers (all needed to rebuild).`
        : `Hid ${entries.length} secret(s) in one cover.`) + note
    );
  }

  async function doHide() {
    if (!covers.length) return;
    setBusy(true); setResult(null);
    try {
      const msg = single ? await hideSingle() : await hideComposite(await prepareCovers());
      setResult({ ok: true, msg });
    } catch (e) {
      setResult({ ok: false, msg: errMsg(e) });
    } finally { setBusy(false); }
  }

  // A picked .mp4 classifies as an appended-region cover until it is decoded,
  // so name what it will actually be carried as once frame-level is on.
  const carriers = [
    ...new Set(
      covers.map((c) =>
        useFrameLevel && looksLikeVideo(c.name) ? kindLabel("video") : kindLabel(c.info?.kind)
      )
    ),
  ].join(", ");
  const ready = covers.length >= 1 && entries.length >= 1 && entries.every(entryReady);

  return (
    <section className="panel active">
      <div className="card">
        <h2>Hide</h2>
        <p className="hint">Add cover files and one or more secrets. Mix freely.</p>

        <label>Cover file(s)</label>
        <Drop
          label={covers.length
            ? `${covers.length} cover(s): ${covers.map((c) => c.name).join(", ")}`
            : "Choose one or more covers — photo, audio, text, document, video, any file"}
          icon={covers.length ? "✅" : "📎"}
          has={covers.length > 0}
          onClick={chooseCovers}
        />

        <label>Secrets</label>
        {entries.map((e, i) => (
          <SecretEntry
            key={e.id}
            entry={e}
            index={i}
            canRemove={entries.length > 1}
            onChange={(next) => updateEntry(i, next)}
            onRemove={() => removeEntry(i)}
          />
        ))}
        <button
          className="ghost"
          style={{ marginTop: 10 }}
          disabled={entries.length >= MAX_ENTRIES}
          onClick={addEntry}
        >
          + Add another secret
        </button>

        <div className={single ? "" : "inactive"}>
          <label>Method</label>
          {/* Showing the last single-hide method while it is disabled reads as
              "your PDF will be hidden with Photo" — wrong, and unchangeable.
              A mix has no method, so say that instead of naming one. */}
          <select
            value={single ? method : "__mix"}
            disabled={!single}
            onChange={(e) => { setMethodIsAuto(false); setMethod(e.target.value); }}
          >
            {!single && (
              <option value="__mix">Not used — the layered scheme places the data</option>
            )}
            {methods.map((m) => (
              <option key={m.id} value={m.id}>{m.displayName} · {m.media.toLowerCase()}</option>
            ))}
          </select>
          {single && autoNote && <div className="small">{autoNote}</div>}
          <button
            className="ghost"
            style={{ marginTop: 10, width: "100%" }}
            disabled={!single}
            onClick={suggest}
          >
            💡 Show other methods
          </button>
          {recs.length > 0 && (
            <div id="planOut">
              {recs.slice(0, 4).map((r) => (
                <button key={r.methodId} className="rec" onClick={() => { setMethodIsAuto(false); setMethod(r.methodId); setRecs([]); }}>
                  <b>{r.fits ? "✅" : "⚠️"} {r.displayName}</b>
                  <span className={`tag ${r.stealthTier >= 2 ? "ok" : r.stealthTier === 1 ? "warn" : "bad"}`}>
                    stealth {r.stealthTier}/3
                  </span>
                  <span className="small">{r.note}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {hasVideo && (
          <div className="small" style={{ marginTop: 12 }}>
            <label className="check">
              <input
                type="checkbox"
                checked={useFrameLevel}
                disabled={!canFrameLevel}
                onChange={(e) => setFrameLevel(e.target.checked)}
              />
              <span>
                Hide inside the video frames{" "}
                <span className="small">spreads the secret across every frame</span>
              </span>
            </label>
            {canFrameLevel ? (
              <div style={{ marginTop: 4 }}>
                The clip is decoded and re-encoded <b>losslessly</b> (FFV1 in .mkv), so the
                output is much larger than the original — and a later lossy re-encode, or
                uploading to a site that re-compresses, destroys the secret. Leave this off to
                tuck the data past the end of the file instead: the clip stays byte-identical
                and plays anywhere, but the data is easier to spot.
              </div>
            ) : (
              <div style={{ marginTop: 4 }}>
                Needs ffmpeg on your PATH — {ffmpeg?.detail ?? "checking…"}. Without it the
                secret is appended past the end of the clip, which still plays normally.
              </div>
            )}
          </div>
        )}

        {covers.length > 0 && (
          <div className="small" style={{ marginTop: 10 }}>
            <b>{describeScheme(covers.length, entries.length, single)}</b>
          </div>
        )}
        {covers.length > 0 && (
          <div className="small">
            Carrier: {carriers}.{" "}
            {cap != null
              ? `Room for about ${cap.toLocaleString()} bytes${single ? "" : " per secret"}.`
              : useFrameLevel
                ? "Room is worked out when the clip is decoded — a video holds far more than a still."
                : ""}
          </div>
        )}

        <div className="row" style={{ marginTop: 14 }}>
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
            <label className="check">
              <input type="checkbox" checked={compress} onChange={(e) => setCompress(e.target.checked)} />
              <span>Compress first <span className="small">fit more in</span></span>
            </label>
          </div>
        </div>

        <button className="primary" disabled={!ready || busy} onClick={doHide}>
          {busy ? "Hiding…" : "Hide & save"}
        </button>
        {result && <div style={{ marginTop: 16 }}><Banner ok={result.ok}>{result.msg}</Banner></div>}

        <p className="small" style={{ marginTop: 12 }}>
          One secret is a simple hide. Two or more each open with their own password (give one away
          as a decoy). Two or more covers split the data across them, all needed to rebuild. Combine
          any of it — a photo and a video and a PDF can carry one secret between them. Photos come
          back as PNG; everything else keeps its own format.
        </p>
      </div>
    </section>
  );
}
