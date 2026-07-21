// Carrier-aware naming and labelling for stego output files.
import type { CoverInfo } from "./api";

/** Base name without its extension. */
export function stemOf(name: string): string {
  return name.replace(/\.[^.]+$/, "");
}

/** Original extension including the dot, or "" when there isn't one. */
export function extOf(name: string): string {
  return name.match(/\.[^.]+$/)?.[0] ?? "";
}

/**
 * What a stego file made from a cover should be called. Photos are re-encoded to
 * PNG (lossless is mandatory for LSB survival) so they take the engine's own
 * extension; every other carrier keeps its container, so a .pdf cover stays a
 * .pdf and a clip stays playable under its original extension.
 */
export function stegoNameFor(
  coverName: string | null,
  info: CoverInfo | null,
  fallbackStem: string
): string {
  const stem = coverName ? stemOf(coverName) : fallbackStem;
  if (info?.preservesContainer && coverName) return `${stem}-hidden${extOf(coverName)}`;
  return `${stem}-hidden.${info?.extension || "png"}`;
}

/** Human label for a carrier kind, for the capacity readout. */
const KIND_LABEL: Record<string, string> = {
  image: "photo",
  audio: "audio",
  text: "text",
  video: "video (frame-level)",
  bytes: "file (appended)",
};

export function kindLabel(kind: string | undefined): string {
  return (kind && KIND_LABEL[kind]) || "file";
}
