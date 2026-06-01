# Stegno — Design Specification

**Date:** 2026-06-01
**Status:** Approved — implementation in progress
**Scope of this spec:** Phase 0 (Foundation + LSB image) in full detail, plus the
phased roadmap for every later technique.

---

## 1. Vision

Stegno is a **standalone, offline, server-less steganography toolkit**. It hides
data *and* (later) detects it, across many media and methods. It is tied to no
other project on the machine: its own git repo, its own dependencies.

Two primary deliverables:

1. **Tauri desktop app** — Rust backend + bundled web (React) UI.
2. **Native Android app** — Kotlin + Jetpack Compose UI.

A future browser build is a possible add-on but is **not** in scope now.

### Non-negotiable properties

- **Offline.** No network calls for any core function. Nothing is uploaded.
- **Server-less.** All embedding, extraction, encryption, and detection run
  on-device.
- **Securely built.** One audited engine. Memory-safe. Modern crypto.
- **Interoperable.** A stego image produced on desktop must extract byte-for-byte
  identically on Android, and vice-versa — guaranteed by sharing *one* engine.

---

## 2. Architecture decision

The engine — pixel/byte math, DSP, and crypto — is the part that must be correct.
Duplicating it in TypeScript (desktop) and Kotlin (Android) would risk silent
divergence that breaks interop or weakens crypto. Therefore:

> **The engine lives once, in a Rust crate (`stegno-core`), and is consumed by
> both platform shells via UniFFI.**

| Concern | Decision |
|---|---|
| Engine | `stegno-core` Rust crate. No UI, no platform deps. |
| Desktop | **Tauri** app. Rust backend depends on `stegno-core` directly (in-process). React UI bundled offline. |
| Android | **Fully native** Kotlin + Jetpack Compose. Calls `stegno-core` via UniFFI-generated Kotlin bindings (`.so` over JNI). No webview. |
| Bindings | **UniFFI** generates the Kotlin FFI. Tauri uses the crate as a normal Rust dependency. |
| Browser | Out of scope (future: compile core to WASM). |

### Why Rust core + native Android (rejected alternatives)

- **Webview everywhere (Tauri + Capacitor, TS engine):** simplest and most reuse,
  but Android ships a webview (extra attack surface) and the engine is JS (weaker
  perf for later DCT/DSP phases). Rejected for the "securely built" priority.
- **Fully native both (Compose + native desktop):** most native, but drops Tauri
  and all web reuse; heaviest lift for no security gain over the chosen option.
  Rejected.

All options are equally offline/server-less, so security/auditability decided it.

---

## 3. Phase 0 scope (this build)

Ship the **foundation** plus **one method working end-to-end** on both platforms:

- `stegno-core` crate with a pluggable `Method` trait and a `MethodRegistry`.
- One method: **`lsb_image`** — sequential least-significant-bit embedding in PNG.
- Crypto layer: **Argon2id** key derivation + **AES-256-GCM**.
- Versioned **payload framing** that already reserves room for the Phase 1 decoy
  slot.
- UniFFI surface: `list_methods`, `capacity`, `embed`, `extract`.
- **Tauri desktop** app: pick cover → hide/extract → save PNG.
- **Native Android** app: same flow via Compose + SAF file pickers.
- Tests: Rust unit + property tests, golden vectors for cross-platform parity.

Explicitly **deferred** (designed-for, not built here):

- Decoy / plausible-deniability slot → Phase 1.
- Key-seeded randomized embedding (detection resistance) → Phase 1.

---

## 4. Core engine design (`stegno-core`)

### 4.1 Crate layout

```
core/
├─ Cargo.toml
├─ src/
│  ├─ lib.rs            # UniFFI scaffolding, public API, error enum
│  ├─ crypto.rs         # Argon2id KDF + AES-256-GCM seal/open
│  ├─ payload.rs        # frame/unframe; Secret (text|file) <-> bytes
│  ├─ capacity.rs       # capacity math per method
│  ├─ registry.rs       # MethodRegistry, list_methods
│  ├─ method.rs         # Method trait + shared types
│  ├─ image_io.rs       # decode any -> RGBA8; encode -> PNG
│  └─ methods/
│     └─ lsb_image.rs   # LsbImage method
└─ tests/
   ├─ roundtrip.rs      # property tests
   └─ golden.rs         # fixed vectors for cross-platform parity
```

### 4.2 The `Method` trait

```rust
pub trait Method {
    fn id(&self) -> &'static str;          // "lsb_image"
    fn display_name(&self) -> &'static str;
    fn media(&self) -> Media;              // Image | Audio | Text | File
    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError>;
    fn embed(&self, cover: &[u8], payload: &[u8], opts: &EmbedOpts)
        -> Result<Vec<u8>, StegnoError>;
    fn extract(&self, stego: &[u8]) -> Result<Option<Vec<u8>>, StegnoError>;
}
```

The trait operates on **already-encrypted, already-framed bytes** (`payload`).
Encryption and framing happen one layer up (in the public API), so every method
inherits identical crypto for free. `Capacity` reports usable payload bytes after
subtracting frame + crypto overhead.

### 4.3 Crypto layer (`crypto.rs`)

- KDF: **Argon2id** (`argon2` crate), parameters chosen for a ~250 ms target on a
  mid-range phone (documented constants: m=19456 KiB, t=2, p=1 as a starting
  point; tuned during implementation). 16-byte random salt.
- Cipher: **AES-256-GCM** (`aes-gcm` crate). 12-byte random nonce. 16-byte tag.
- `seal(plaintext, passphrase) -> [salt(16) | nonce(12) | ciphertext+tag]`
- `open(blob, passphrase) -> Result<plaintext, AuthFailed>` — GCM tag failure maps
  to `StegnoError::AuthFailed` (this is the "wrong passphrase" signal).
- All randomness from `getrandom`/`OsRng`.

### 4.4 Payload framing (`payload.rs`)

A `Secret` is either text or a named file:

```
Secret::Text(String)
Secret::File { name: String, bytes: Vec<u8> }
```

Serialized inner plaintext (before encryption):

```
type(1)  0x00 = text, 0x01 = file
if file: name_len(u16, BE) · name(utf8) ...
body bytes
```

Outer frame written into the cover (after encryption):

```
MAGIC(4) = "STG0"   version(1)=1   flags(1)   slot_type(1)   len(u32, BE)
└─ followed by len bytes of sealed blob (salt·nonce·ciphertext·tag)
```

`flags` reserves bits for future use (e.g. decoy present). `slot_type`
distinguishes primary vs. (future) decoy slot. `len` lets the reader know exactly
how many bytes to pull out of the LSB stream.

### 4.5 `lsb_image` method

- **Input:** any image the `image` crate decodes (PNG/JPEG/BMP/WebP/GIF). Always
  normalized to RGBA8.
- **Output:** **PNG** (lossless — mandatory for LSB survival).
- **Embedding:** write frame bits into the LSB of the R, G, B channels in pixel
  order (alpha left untouched to avoid premultiplied-alpha surprises). 3 bits per
  pixel.
- **Capacity:** `floor(width * height * 3 / 8) - frame_overhead - crypto_overhead`.
- **Extraction:** read MAGIC + header from the LSB stream; if MAGIC mismatches,
  return `Ok(None)` (no hidden data); otherwise read `len` bytes and hand the
  sealed blob up for decryption.
- Phase 0 is **sequential**; Phase 1 swaps in a key-seeded permutation of pixel
  indices without changing the frame format.

### 4.6 Public API (UniFFI surface, `lib.rs`)

```rust
pub fn list_methods() -> Vec<MethodInfo>;

pub fn capacity(method_id: String, cover: Vec<u8>)
    -> Result<Capacity, StegnoError>;

pub fn embed(
    method_id: String,
    cover: Vec<u8>,
    secret: Secret,         // text or file
    passphrase: String,
) -> Result<Vec<u8>, StegnoError>;   // returns stego PNG bytes

pub fn extract(
    method_id: String,
    stego: Vec<u8>,
    passphrase: String,
) -> Result<Revealed, StegnoError>;  // Revealed = Text | File | None
```

`embed` orchestrates: serialize `Secret` → `crypto::seal` → `payload::frame` →
`method.embed`. `extract` reverses it. The shells never touch crypto directly.

### 4.7 Error model (`StegnoError`, exposed via UniFFI)

| Variant | Meaning | UI message |
|---|---|---|
| `CoverTooSmall` | payload exceeds capacity | "Image too small for this message." |
| `UnsupportedFormat` | cover failed to decode | "Unsupported or corrupt image." |
| `AuthFailed` | GCM tag mismatch | "Wrong passphrase, or no hidden data." |
| `NoHiddenData` | MAGIC not found | "No hidden data found." |
| `CorruptPayload` | header/frame inconsistent | "Hidden data is corrupted." |
| `Internal(String)` | unexpected | generic failure message |

---

## 5. Desktop shell (Tauri)

- `desktop/src-tauri` (Rust) depends on `stegno-core`; exposes Tauri commands
  `list_methods`, `capacity`, `embed`, `extract` that thin-wrap the core.
- `desktop/src` React UI (Vite), bundled offline — **no** network permitted in the
  Tauri allowlist beyond what's needed to load local assets.
- UI: Hide tab (pick cover, text/file secret, passphrase, capacity meter, embed,
  save/share PNG) and Extract tab (pick stego, passphrase, reveal text/file).
  Visually echoes the parent's clean modal but is original code.

---

## 6. Android shell (native)

- `android/` Gradle project, Kotlin + Jetpack Compose, min SDK 26.
- `stegno-core` built for `aarch64`, `armv7`, `x86_64` Android targets; UniFFI
  generates Kotlin bindings packaged as a library module.
- Storage Access Framework for picking the cover/stego and writing the result;
  no broad storage permissions.
- Same two-screen flow as desktop, native Compose components.
- All processing on-device; no `INTERNET` permission required.

---

## 7. Data flow

**Hide:** pick cover → enter secret (text/file) + passphrase → `embed` → receive
PNG bytes → save / share.

**Reveal:** pick stego PNG → enter passphrase → `extract` → show text or offer the
recovered file for download.

---

## 8. Testing strategy

- **Crypto:** seal/open roundtrip; wrong passphrase ⇒ `AuthFailed`; tampered
  ciphertext ⇒ `AuthFailed`.
- **Framing:** frame/unframe roundtrip; truncated/garbage ⇒ `NoHiddenData` /
  `CorruptPayload`.
- **LSB:** embed→extract identity (property test over random payloads sized within
  capacity and random image dimensions). Capacity boundary: payload == capacity
  succeeds, +1 byte fails with `CoverTooSmall`.
- **Format:** JPEG/BMP/WebP covers normalize to RGBA8 and produce valid PNG.
- **Golden vectors:** fixed (image, secret, passphrase) → fixed stego PNG checked
  in, so any future change that breaks cross-platform parity fails CI.
- **Shells:** desktop e2e (hide then reveal) and an Android instrumentation smoke
  test land with each shell.
- Coverage target: 80%+ on `stegno-core`.

---

## 9. Phased roadmap (beyond Phase 0)

Each phase is its own spec → plan → build, and every method plugs into the
`Method` trait without changing the engine.

| Phase | Theme | Methods |
|---|---|---|
| **0** | Foundation + LSB image | `lsb_image`, crypto, framing, both shells |
| **1** | Spatial image suite + decoy | LSB-matching, PVD, edge-adaptive, **key-seeded randomized embedding**, **plausible-deniability decoy slot** |
| **2** | Text & file-structure | zero-width Unicode, whitespace, append-after-EOF, polyglot, EXIF/PNG-tEXt metadata |
| **3** | Audio | WAV LSB, echo hiding, spread-spectrum |
| **4** | Transform-domain image | JPEG DCT (JSteg / F5 / OutGuess-style), DWT |
| **5** | Detection / steganalysis | chi-square, RS analysis, sample-pair, histogram; PSNR/SSIM quality metrics |
| **6** | Adaptive & ML (research) | HUGO / WOW / S-UNIWARD + STC; StegaStamp-style deep hiding; generative LLM linguistic stego |

### Explicitly out of scope (platform-incompatible)

- **Network covert channels** (DNS/TCP/ICMP/timing) — raw sockets are unavailable
  in the Android sandbox and undesirable for an offline tool.
- **Full video steganography** — codec-heavy; revisit only if a clear need appears.

---

## 10. Security notes

- Passphrase strength is the user's responsibility; the app uses Argon2id to make
  brute-force expensive but cannot rescue a weak passphrase.
- LSB (Phase 0) is **detectable** by statistical steganalysis; detection
  resistance arrives with key-seeded embedding and adaptive methods in later
  phases. The UI should not over-promise secrecy at Phase 0.
- No telemetry, no analytics, no crash reporting that leaves the device.
- This is best-effort software provided without warranty.
