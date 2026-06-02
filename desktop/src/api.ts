// Thin typed wrapper over the Tauri commands exposed by the Rust backend.
import { invoke } from "@tauri-apps/api/core";

export type MethodInfo = { id: string; displayName: string; media: string };

export type Revealed =
  | { kind: "none" }
  | { kind: "text"; text: string }
  | { kind: "file"; name: string; bytes: number[] }
  | { kind: "files"; files: { name: string; bytes: number[] }[] };

export type SecretInput =
  | { kind: "text"; text: string }
  | { kind: "file"; name: string; bytes: number[] }
  | { kind: "files"; files: { name: string; bytes: number[] }[] };

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

export function embedSecret(
  methodId: string,
  cover: number[],
  secret: SecretInput,
  passphrase: string
): Promise<number[]> {
  return invoke<number[]>("embed", {
    methodId,
    cover,
    secret,
    passphrase,
  });
}

/** Usable bytes per slot when hiding a real + decoy message (≈ half the image each). */
export function decoyCapacity(cover: number[]): Promise<number> {
  return invoke<number>("decoy_capacity", { cover });
}

/**
 * Hide a real message and a decoy message in one photo, each under its own
 * password. Revealing later: the real password shows the real message, the
 * decoy password shows the decoy. Always outputs a PNG photo.
 */
export function embedTextWithDecoy(
  cover: number[],
  realText: string,
  realPassphrase: string,
  decoyText: string,
  decoyPassphrase: string
): Promise<number[]> {
  return embedWithDecoy(
    cover,
    { kind: "text", text: realText },
    realPassphrase,
    { kind: "text", text: decoyText },
    decoyPassphrase
  );
}

export function embedWithDecoy(
  cover: number[],
  real: SecretInput,
  realPassphrase: string,
  decoy: SecretInput,
  decoyPassphrase: string
): Promise<number[]> {
  return invoke<number[]>("embed_with_decoy", {
    cover,
    real,
    realPassphrase,
    decoy,
    decoyPassphrase,
  });
}

export function extract(
  methodId: string,
  stego: number[],
  passphrase: string
): Promise<Revealed> {
  return invoke<Revealed>("extract", { methodId, stego, passphrase });
}

export function embedSplit(
  methodId: string,
  covers: number[][],
  secret: SecretInput,
  passphrase: string
): Promise<number[][]> {
  return invoke<number[][]>("embed_split", {
    methodId,
    covers,
    secret,
    passphrase,
  });
}

export function extractSplit(
  methodId: string,
  stegos: number[][],
  passphrase: string
): Promise<Revealed> {
  return invoke<Revealed>("extract_split", { methodId, stegos, passphrase });
}

export type Detection = {
  chiSquareP: number;
  rsRegularityGap: number;
  samplePairRate: number;
};

/** Scan a photo for signs of hidden LSB data. */
export function detectLsb(image: number[]): Promise<Detection> {
  return invoke<Detection>("detect_lsb", { image });
}

export type Quality = { mse: number; psnrDb: number; ssim: number };

/** Compare an original photo with a modified one. */
export function quality(cover: number[], stego: number[]): Promise<Quality> {
  return invoke<Quality>("quality", { cover, stego });
}

export function readFile(path: string): Promise<number[]> {
  return invoke<number[]>("read_file", { path });
}

export function writeFile(path: string, bytes: number[]): Promise<void> {
  return invoke<void>("write_file", { path, bytes });
}
