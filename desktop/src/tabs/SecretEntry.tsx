// One secret in the composer: text or file(s), plus the password that opens it.
import { useEffect, useState } from "react";
import { passphraseStrength, type PassphraseStrength, type SecretInput } from "../api";
import { Drop, Seg, pickFiles, type Picked } from "../shared";

export type EntryType = "text" | "file";

export interface Entry {
  /** Stable across reorders so React keeps each row's own state with its row. */
  id: string;
  type: EntryType;
  text: string;
  files: Picked[];
  pass: string;
}

let nextEntryId = 0;

export function newEntry(): Entry {
  nextEntryId += 1;
  return { id: `e${nextEntryId}`, type: "text", text: "", files: [], pass: "" };
}

/** Longest a composer list may get — matches the engine's entry ceiling. */
export const MAX_ENTRIES = 8;

export function entrySecret(e: Entry): SecretInput {
  if (e.type === "text") return { kind: "text", text: e.text };
  return { kind: "files", files: e.files.map((f) => ({ name: f.name, bytes: f.bytes })) };
}

export function entryPayloadLen(e: Entry): number {
  if (e.type === "text") return new TextEncoder().encode(e.text).length;
  return e.files.reduce((n, f) => n + f.bytes.length, 0);
}

export function entryReady(e: Entry): boolean {
  return !!e.pass && (e.type === "text" ? !!e.text : e.files.length > 0);
}

const STRENGTH_COLORS = ["var(--bad)", "var(--bad)", "var(--warn)", "var(--ok)", "var(--ok)"];
const STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];

interface SecretEntryProps {
  entry: Entry;
  index: number;
  canRemove: boolean;
  onChange: (next: Entry) => void;
  onRemove: () => void;
}

export function SecretEntry({ entry, index, canRemove, onChange, onRemove }: SecretEntryProps) {
  const [strength, setStrength] = useState<PassphraseStrength | null>(null);

  useEffect(() => {
    let live = true;
    if (!entry.pass) {
      setStrength(null);
      return;
    }
    passphraseStrength(entry.pass)
      .then((s) => { if (live) setStrength(s); })
      .catch(() => { if (live) setStrength(null); });
    return () => { live = false; };
  }, [entry.pass]);

  const fileLabel = entry.files.length
    ? `${entry.files.length} file(s) selected`
    : "Choose file(s) — any type";

  return (
    <div className="recip">
      <div className="entry-head">
        <Seg<EntryType>
          options={[{ id: "text", label: "Text" }, { id: "file", label: "File(s)" }]}
          value={entry.type}
          onChange={(type) => onChange({ ...entry, type })}
        />
        {canRemove && (
          <button className="entry-del" title="Remove this secret" onClick={onRemove}>✕</button>
        )}
      </div>

      {entry.type === "text" ? (
        <textarea
          value={entry.text}
          placeholder={`Secret message ${index + 1}`}
          onChange={(e) => onChange({ ...entry, text: e.target.value })}
        />
      ) : (
        <Drop
          mini
          label={fileLabel}
          icon={entry.files.length ? "✅" : "📎"}
          has={entry.files.length > 0}
          onClick={async () => {
            const files = await pickFiles();
            if (files.length) onChange({ ...entry, files });
          }}
        />
      )}

      <input
        type="password"
        style={{ marginTop: 8 }}
        value={entry.pass}
        placeholder="Password for this secret"
        onChange={(e) => onChange({ ...entry, pass: e.target.value })}
      />
      <div className="meter">
        <span
          style={{
            width: strength ? `${((strength.score + 1) / 5) * 100}%` : 0,
            background: strength ? STRENGTH_COLORS[strength.score] : undefined,
          }}
        />
      </div>
      <div className="small">
        {strength ? (
          <>
            <b>{STRENGTH_LABELS[strength.score]}</b> · ~{strength.entropyBits.toFixed(0)} bits ·
            cracks in {strength.crackTimeDisplay}
            {strength.warning ? <span className="err"> · {strength.warning}</span> : null}
          </>
        ) : (
          "Strength shows as you type."
        )}
      </div>
    </div>
  );
}
