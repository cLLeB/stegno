// Shared presentation for anything the engine hands back — used by Reveal and
// by rebuilding a secret from key-shares, so both behave identically.
import type { Revealed } from "./api";
import { saveBytes } from "./shared";

export interface RevealedView {
  ok: boolean;
  message: string;
  /** Present only for a recovered text secret. */
  text?: string;
}

/**
 * Write out any recovered files (prompting once per file) and describe the
 * outcome. Files are saved here rather than in the caller so every screen
 * recovers a named file the same way.
 */
export async function saveRevealed(rv: Revealed): Promise<RevealedView> {
  switch (rv.kind) {
    case "none":
      return { ok: false, message: "No hidden data found (or wrong password)." };
    case "text":
      return { ok: true, message: "Revealed the hidden message.", text: rv.text };
    case "file": {
      const saved = await saveBytes(rv.bytes, rv.name);
      return {
        ok: true,
        message: saved
          ? `Recovered file ${rv.name} - saved.`
          : `Recovered file ${rv.name} (save cancelled).`,
      };
    }
    case "files": {
      let saved = 0;
      for (const f of rv.files) if (await saveBytes(f.bytes, f.name)) saved += 1;
      return {
        ok: true,
        message: `Recovered ${rv.files.length} file(s); saved ${saved}.`,
      };
    }
  }
}

export function RevealedOut({ view }: { view: RevealedView }) {
  return (
    <div className="out">
      <div className={`result-banner ${view.ok ? "ok" : "bad"}`}>
        {view.ok ? "🔓 " : "🔎 "}
        {view.message}
      </div>
      {view.text !== undefined && <pre>{view.text}</pre>}
    </div>
  );
}
