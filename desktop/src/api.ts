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

export interface MethodRecommendation {
  methodId: string;
  displayName: string;
  media: string;
  usableBytes: number;
  fits: boolean;
  fillRatio: number;
  stealthTier: 0 | 1 | 2;
  note: string;
}

/**
 * Rank the methods that can hide `payloadLen` bytes in `cover`, best-first
 * (fitting methods before non-fitting; stealthier methods before detectable
 * ones; lower fill ratio before higher).
 */
export function planEmbedding(
  cover: number[],
  payloadLen: number
): Promise<MethodRecommendation[]> {
  return invoke<MethodRecommendation[]>("plan_embedding", {
    cover,
    payloadLen,
  });
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

/**
 * Hide a secret with Reed–Solomon error correction so it survives bounded
 * carrier damage (light recompression, a resize, a scanned print). `robustness`
 * ranges 1 (smallest overhead) to 3 (most resilient). Recovered with the plain
 * `extract` — the recipient only needs the passphrase.
 */
export function embedRobust(
  methodId: string,
  cover: number[],
  secret: SecretInput,
  passphrase: string,
  robustness: 1 | 2 | 3
): Promise<number[]> {
  return invoke<number[]>("embed_robust", {
    methodId,
    cover,
    secret,
    passphrase,
    robustness,
  });
}

/**
 * Full hide pipeline: optional Reed–Solomon FEC (`robustness` 0 = off, 1–3) and
 * an optional compression pre-pass (`compress`). Both are recorded in the frame,
 * so a plain `extract` reverses them — the recipient only needs the passphrase.
 */
export function embedAdvanced(
  methodId: string,
  cover: number[],
  secret: SecretInput,
  passphrase: string,
  robustness: 0 | 1 | 2 | 3,
  compress: boolean
): Promise<number[]> {
  return invoke<number[]>("embed_advanced", {
    methodId,
    cover,
    secret,
    passphrase,
    robustness,
    compress,
  });
}

export interface PassphraseStrength {
  score: 0 | 1 | 2 | 3 | 4;
  entropyBits: number;
  crackTimeDisplay: string;
  warning: string;
  suggestions: string[];
}

/** Offline passphrase-strength estimate — no dictionary download, no network. */
export function passphraseStrength(
  passphrase: string
): Promise<PassphraseStrength> {
  return invoke<PassphraseStrength>("passphrase_strength", { passphrase });
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

export interface AutoRevealed {
  methodId: string;
  revealed: Revealed;
}

/**
 * Reveal a hidden payload without knowing which method hid it. Returns the
 * matching method id (empty if nothing found) alongside the revealed data.
 */
export function extractAuto(
  stego: number[],
  passphrase: string
): Promise<AutoRevealed> {
  return invoke<AutoRevealed>("extract_auto", { stego, passphrase });
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
  hogUniformity: number;
  noiseResidualEnergy: number;
  mlConfidence: number;
  isStenographic: boolean;
};

/** Scan a photo for signs of hidden LSB data. */
export function detectLsb(image: number[]): Promise<Detection> {
  return invoke<Detection>("detect_lsb", { image });
}

export interface StructuralFinding {
  kind: string;
  detail: string;
  severity: 0 | 1 | 2;
}

export interface StructuralReport {
  format: string;
  findings: StructuralFinding[];
  suspicious: boolean;
}

/**
 * Scan a file's container structure for signs of hidden data — appended data,
 * PNG/ZIP polyglots, private metadata chunks, or zero-width text. Complements
 * `detectLsb` (which looks at pixel statistics) with format-level checks.
 */
export function scanStructure(data: number[]): Promise<StructuralReport> {
  return invoke<StructuralReport>("scan_structure", { data });
}

export type Quality = { mse: number; psnrDb: number; ssim: number };

/** Compare an original photo with a modified one. */
export function quality(cover: number[], stego: number[]): Promise<Quality> {
  return invoke<Quality>("quality", { cover, stego });
}

export interface SecretShare {
  x: number;
  y: number[];
}

/**
 * Split a secret into `shares` pieces, any `threshold` of which reconstruct it
 * (Shamir Secret Sharing). Fewer than `threshold` reveal nothing.
 */
export function sssSplit(
  secret: number[],
  threshold: number,
  shares: number
): Promise<SecretShare[]> {
  return invoke<SecretShare[]>("sss_split", { secret, threshold, shares });
}

/** Reconstruct a secret from a set of Shamir shares. */
export function sssCombine(shares: SecretShare[]): Promise<number[]> {
  return invoke<number[]>("sss_combine", { shares });
}

export function readFile(path: string): Promise<number[]> {
  return invoke<number[]>("read_file", { path });
}

export function writeFile(path: string, bytes: number[]): Promise<void> {
  return invoke<void>("write_file", { path, bytes });
}
