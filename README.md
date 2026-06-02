# Stegno

A standalone, **offline**, server-less steganography toolkit. Hide encrypted
data inside ordinary files, and (in later phases) detect it.

- **One engine.** All crypto and byte-handling lives in a single audited Rust
  crate, `stegno-core`. Memory-safe, no duplication across platforms.
- **Two apps share that engine.** A **Tauri** desktop app (Rust backend + web UI)
  and a **fully native Android** app (Kotlin + Jetpack Compose) call the same core
  via [UniFFI](https://mozilla.github.io/uniffi-rs/).
- **Nothing leaves your device.** No network, no telemetry, no server.

> Standalone project. It borrows ideas from a sibling project's LSB module but
> shares no code or dependency with it.

## Status — Phases 0–6

| Component | State |
|---|---|
| `stegno-core` engine | ✅ Argon2id + AES-256-GCM, versioned framing, pluggable `Method` trait |
| Image methods | ✅ `lsb_image`, `lsb_seeded`, `lsb_matching`, `edge_adaptive`, `pvd` |
| Transform-domain | ✅ `dwt_haar` (reversible integer Haar detail-coefficient LSB), `jpeg_jsteg` + `jpeg_f5` (baseline-JPEG DCT) |
| Content-adaptive | ✅ `adaptive_cost` (UNIWARD-flavored directional-residual cost) |
| Text / file methods | ✅ `zero_width`, `whitespace`, `append_eof`, `png_text` |
| Generative text | ✅ `mimic_words` (offline wordlist mimicry) |
| Audio methods | ✅ `wav_lsb` (bit-exact, key-seeded) |
| Steganalysis / quality | ✅ `quality` (MSE/PSNR/SSIM), `detect_lsb` (chi-square + RS + sample-pair) |
| Key-seeded embedding | ✅ deterministic xoshiro256++ permutation keyed by passphrase |
| Plausible-deniability decoy slot | ✅ `embed_with_decoy` — real + decoy in disjoint keyed regions |
| Tests | ✅ 166 (unit + property + parity + deniability + text/file + audio + analysis + JPEG codec) |
| Tauri desktop | ✅ Hide/Extract UI with method selector (all methods) |
| Native Android | ✅ Compose UI with method selector + UniFFI bindings + per-ABI `.so` |

### Methods

| id | media | technique | notes |
|---|---|---|---|
| `lsb_image` | image | sequential LSB replacement | Phase-0 baseline, max capacity, detectable |
| `lsb_seeded` | image | key-seeded LSB replacement | payload scattered by a passphrase-keyed permutation |
| `lsb_matching` | image | ±1 LSB matching | removes the pairs-of-values / chi-square signature |
| `edge_adaptive` | image | edge-first LSB | fills busy/edge pixels first (order invariant under LSB) |
| `pvd` | image | pixel-value differencing | variable bits/pair by local difference; reversible |
| `zero_width` | text | zero-width Unicode | invisible U+200B/U+200C carry bits inside normal text |
| `whitespace` | text | trailing whitespace | space=0 / tab=1 run after the text (SNOW-style) |
| `append_eof` | file | append after EOF | data after the file's end marker; any cover, still opens |
| `png_text` | image | PNG metadata chunk | frame stored in a private `stEg` chunk; pixels untouched |
| `polyglot` | image | PNG/ZIP polyglot | output is valid as both a PNG and a ZIP archive holding the secret |
| `wav_lsb` | audio | WAV/PCM LSB | key-seeded LSB in sample low-bytes; 8/16/24/32-bit + float |
| `dwt_haar` | image | Haar wavelet detail LSB | reversible integer S-transform; embeds in detail band; overflow-safe |
| `jpeg_jsteg` | image | JPEG DCT (JSteg) | LSB of non-{0,1} quantized AC coefficients; emits a real baseline JPEG; bit-exact |
| `jpeg_f5` | image | JPEG DCT (F5) | parity by decrement-toward-zero (no JSteg histogram artefact); shrinkage-aware; key-seeded straddling; bit-exact |
| `adaptive_cost` | image | content-adaptive cost | directional 2nd-order residual cost; fills cheapest (textured) first |
| `mimic_words` | text | generative wordlist mimicry | emits word-salad encoding the payload; cover ignored |

### How it works

1. The secret (text or a file) is serialized and encrypted with AES-256-GCM
   under a key derived from your passphrase via Argon2id.
2. The ciphertext is wrapped in a versioned frame (`STG0` magic + length).
3. `lsb_image` writes that frame bit-by-bit into the least-significant bits of
   the R/G/B channels of a PNG (3 bits/pixel). Output is always lossless PNG.
4. Extraction reverses the process; a wrong passphrase fails the GCM auth tag.

## Repository layout

```
core/      stegno-core — the shared Rust engine (+ UniFFI surface)
desktop/   Tauri app (React UI in src/, Rust backend in src-tauri/)
android/   native Kotlin + Jetpack Compose app (UniFFI bindings + jniLibs)
docs/superpowers/  design spec and implementation plan
```

## Building

### Core

```bash
cargo test -p stegno-core
```

### Desktop (Tauri)

```bash
cd desktop
npm install
npm run tauri dev      # or: npm run tauri build
```

### Android

Regenerate bindings and native libs when the core changes:

```bash
# Kotlin bindings (library mode)
cargo build -p stegno-core
cargo run -p stegno-core --features cli --bin uniffi-bindgen -- \
  generate --library target/debug/stegno_core.dll \
  --language kotlin --out-dir android/app/src/main/java

# Per-ABI .so
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.1.12297006"
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o android/app/src/main/jniLibs build --release -p stegno-core

# APK
cd android && ./gradlew assembleDebug
```

## Roadmap

| Phase | Theme |
|---|---|
| **0** ✅ | Foundation + LSB image |
| **1** ✅ | Spatial image suite (LSB-matching, PVD, edge-adaptive, key-seeded embedding) + plausible-deniability decoy slot |
| **2** ✅ | Text & file-structure (zero-width Unicode, whitespace, append-after-EOF, PNG metadata, PNG/ZIP polyglot) |
| **3** ◑ | Audio — WAV LSB ✅. Echo hiding & spread-spectrum deferred (see note) |
| **4** ◑ | Transform-domain — reversible Haar-DWT ✅ + JPEG DCT JSteg ✅ + F5 ✅. OutGuess deferred (see note) |
| **5** ✅ | Detection / steganalysis — chi-square, RS, sample-pair, PSNR/SSIM/MSE |
| **6** ◑ | Adaptive `adaptive_cost` ✅ + generative `mimic_words` ✅. STC matrix coding, deep-learning, and LLM text deferred (see note) |

**Out of scope** (platform-incompatible): network covert channels (no raw
sockets in the Android sandbox); full video steganography (codec-heavy).

**Deferred — incompatible with authenticated encryption:** echo hiding and
spread-spectrum audio are designed to survive *lossy* channels and do not
guarantee bit-exact blind recovery. Because every payload is sealed with
AES-256-GCM (all-or-nothing authentication), a single recovered-bit error fails
decryption outright, so these lossy techniques can't carry our payload reliably.
They'd require either dropping authentication or adding heavy error-correcting
codes — revisited only if a concrete need appears. `wav_lsb` is bit-exact and
covers the practical audio case.

**JPEG DCT — implemented (`jpeg_jsteg`):** the engine ships its own minimal
baseline-JPEG coefficient codec (forward DCT, standard Annex-K quant/Huffman
tables, entropy coder, and a JFIF container reader/writer). `jpeg_jsteg` applies
the classic JSteg rule — overwrite the LSB of every quantized AC coefficient that
isn't `0` or `1` — and re-emits a real baseline JPEG. Because that usable set is
invariant under an LSB flip and encoder/decoder share fixed tables, extraction is
bit-exact with no side information, so it carries the AES-GCM payload reliably.

**F5 — implemented (`jpeg_f5`):** F5 flips coefficient parity by *decrementing the
magnitude toward zero* instead of overwriting the LSB, so it avoids JSteg's
pairs-of-values histogram signature; it handles shrinkage (a `±1` that decrements
to `0` re-embeds its bit in the next coefficient, and the decoder skips zeros on
both sides) and scatters the payload with a passphrase-keyed permutation. It
remains bit-exact for the AES-GCM payload. The classic `(1,2ᵏ−1,k)` matrix-coding
optimisation (fewer coefficient changes per bit) is a future efficiency add-on.

**Deferred — OutGuess:** OutGuess's statistics-preserving correction pass (it
restores the global DCT histogram after embedding) builds on the same coefficient
codec and can slot in as a further `Method`; JSteg and F5 cover the core JPEG-DCT
case for now.

**Deferred — research-grade:** full HUGO/WOW/S-UNIWARD use syndrome-trellis
codes (STC) to minimise *total* distortion for a payload; `adaptive_cost`
implements the cost model and cost-ordered embedding but not STC matrix coding.
Deep-learning hiding (StegaStamp) and LLM-driven generative text need bundled
neural models and are out of scope for an offline, dependency-light crate;
`mimic_words` provides the classic model-free generative alternative.

## Security notes

- Argon2id makes brute force expensive but can't rescue a weak passphrase.
- `lsb_image` (sequential) is statistically **detectable**. `lsb_seeded`,
  `lsb_matching`, and `edge_adaptive` raise the bar (no sequential structure, no
  pairs-of-values artefact, embedding biased into texture) but are **not**
  provably undetectable — adaptive/transform-domain methods come in later phases.
- The decoy slot gives plausible deniability *only if you actually embed a
  decoy*: the real slot is then indistinguishable from unused LSB noise without
  the real passphrase.
- Best-effort software, no warranty.

## License

MIT
