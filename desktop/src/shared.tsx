// Shared helpers and small presentational components used across every tab.
import type { ReactNode } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { readFile, writeFile } from "./api";

export type Bytes = number[];
export interface Picked {
  name: string;
  bytes: Bytes;
}

const IMAGE_ACCEPT = "png,jpg,jpeg,bmp,webp,gif";
export { IMAGE_ACCEPT };

export async function pickFile(accept?: string): Promise<Picked | null> {
  const path = await open({
    multiple: false,
    filters: accept ? [{ name: accept, extensions: accept.split(",") }] : undefined,
  });
  if (!path || typeof path !== "string") return null;
  const bytes = await readFile(path);
  return { name: path.split(/[\\/]/).pop() || "file", bytes };
}

export async function pickFiles(accept?: string): Promise<Picked[]> {
  const paths = await open({
    multiple: true,
    filters: accept ? [{ name: accept, extensions: accept.split(",") }] : undefined,
  });
  if (!paths) return [];
  const arr = Array.isArray(paths) ? paths : [paths];
  return Promise.all(
    arr.map(async (p) => ({ name: p.split(/[\\/]/).pop() || "file", bytes: await readFile(p) }))
  );
}

export async function saveBytes(bytes: Bytes, defaultName: string): Promise<boolean> {
  const path = await save({ defaultPath: defaultName });
  if (!path) return false;
  await writeFile(path, bytes);
  return true;
}

export function blobUrl(bytes: Bytes, mime: string): string {
  return URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: mime }));
}

export function errMsg(e: unknown): string {
  return String((e as Error)?.message ?? e);
}

/* ---------- presentational ---------- */

interface DropProps {
  label: string;
  icon: string;
  has: boolean;
  mini?: boolean;
  onClick: () => void;
}
export function Drop({ label, icon, has, mini, onClick }: DropProps) {
  return (
    <div className={`drop ${has ? "has" : ""} ${mini ? "mini" : ""}`} onClick={onClick}>
      <span className="big">{icon}</span>
      {label}
    </div>
  );
}

interface SegProps<T extends string> {
  options: { id: T; label: string }[];
  value: T;
  onChange: (id: T) => void;
}
export function Seg<T extends string>({ options, value, onChange }: SegProps<T>) {
  return (
    <div className="seg">
      {options.map((o) => (
        <button key={o.id} className={value === o.id ? "active" : ""} onClick={() => onChange(o.id)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function StatRow({ k, v }: { k: string; v: string }) {
  return (
    <div className="stat">
      <span>{k}</span>
      <b>{v}</b>
    </div>
  );
}

export function Banner({ ok, children }: { ok: boolean; children: ReactNode }) {
  return <div className={`result-banner ${ok ? "ok" : "bad"}`}>{ok ? "✅ " : "⚠️ "}{children}</div>;
}
