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

## Status — Phase 0 (Foundation + LSB image)

| Component | State |
|---|---|
| `stegno-core` engine | ✅ Argon2id + AES-256-GCM, versioned framing, pluggable `Method` trait, `lsb_image` |
| Tests | ✅ 25 (unit + property + parity) |
| Tauri desktop | ✅ Hide/Extract UI wired to the core |
| Native Android | ✅ Compose UI + UniFFI bindings + per-ABI `.so` |

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
| 1 | Spatial image suite (LSB-matching, PVD, edge-adaptive, key-seeded embedding) + plausible-deniability decoy slot |
| 2 | Text & file-structure (zero-width Unicode, whitespace, append/polyglot, EXIF/tEXt) |
| 3 | Audio (WAV LSB, echo hiding, spread-spectrum) |
| 4 | Transform-domain image (JPEG DCT: JSteg/F5/OutGuess, DWT) |
| 5 | Detection / steganalysis (chi-square, RS, sample-pair, PSNR/SSIM) |
| 6 | Adaptive (HUGO/WOW/S-UNIWARD) + deep-learning + generative LLM text |

**Out of scope** (platform-incompatible): network covert channels (no raw
sockets in the Android sandbox); full video steganography (codec-heavy).

## Security notes

- Argon2id makes brute force expensive but can't rescue a weak passphrase.
- Phase-0 LSB is statistically **detectable**; detection resistance arrives with
  key-seeded and adaptive methods in later phases.
- Best-effort software, no warranty.

## License

MIT
