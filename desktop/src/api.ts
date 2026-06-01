// Thin typed wrapper over the Tauri commands exposed by the Rust backend.
import { invoke } from "@tauri-apps/api/core";

export type MethodInfo = { id: string; displayName: string; media: string };

export type Revealed =
  | { kind: "none" }
  | { kind: "text"; text: string }
  | { kind: "file"; name: string; bytes: number[] };

export async function listMethods(): Promise<MethodInfo[]> {
  const raw = await invoke<[string, string, string][]>("list_methods");
  return raw.map(([id, displayName, media]) => ({ id, displayName, media }));
}

export function capacity(methodId: string, cover: number[]): Promise<number> {
  return invoke<number>("capacity", { methodId, cover });
}

export function embedText(
  methodId: string,
  cover: number[],
  text: string,
  passphrase: string
): Promise<number[]> {
  return invoke<number[]>("embed_text", { methodId, cover, text, passphrase });
}

export function embedFile(
  methodId: string,
  cover: number[],
  name: string,
  bytes: number[],
  passphrase: string
): Promise<number[]> {
  return invoke<number[]>("embed_file", {
    methodId,
    cover,
    name,
    bytes,
    passphrase,
  });
}

export function extract(
  methodId: string,
  stego: number[],
  passphrase: string
): Promise<Revealed> {
  return invoke<Revealed>("extract", { methodId, stego, passphrase });
}

export function readFile(path: string): Promise<number[]> {
  return invoke<number[]>("read_file", { path });
}

export function writeFile(path: string, bytes: number[]): Promise<void> {
  return invoke<void>("write_file", { path, bytes });
}
