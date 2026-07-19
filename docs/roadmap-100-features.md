# Stegno — 100-Feature Roadmap

**Date:** 2026-07-19
**Status:** Ideation catalog — a prioritized backlog, not a commitment
**Baseline:** Phases 0–6 complete. `stegno-core` ships 18 methods, Argon2id +
AES-256-GCM crypto, versioned framing, key-seeded permutation, decoy slot,
steganalysis (`chi-square`/RS/sample-pair) and quality metrics, plus a Tauri
desktop app and a native Android (Compose + UniFFI) app.

This document catalogs **100 intermediate-to-advanced features** tailored to the
existing architecture. Each entry is genuinely weeks-to-months of work. Nothing
here is built yet — this is the map we pick batches from, each of which then gets
its own `spec → plan → TDD build` cycle.

---

## How to read this

**Difficulty** (engineering depth, not just line count):
`◆` intermediate · `◆◆` advanced · `◆◆◆` hard/research-adjacent · `◆◆◆◆` research-grade

**Effort** is a rough single-developer estimate (calendar time at a normal pace).

**Touches** names the concrete code the feature lands in, so scope is unambiguous.

### Category index

| # | Category | Count | Theme |
|---|---|---|---|
| A | Advanced embedding methods | 12 | New `Method`s: spatial, transform, adaptive |
| B | Audio & video steganography | 8 | Beyond `wav_lsb` |
| C | Robustness & error correction | 9 | Survive resize / recompress / print-scan |
| D | Steganalysis, detection & ML | 10 | Extend `analysis.rs` into a real lab |
| E | Crypto, key management & deniability | 10 | Harden and extend `crypto.rs` + decoy |
| F | Capacity, payload & containers | 8 | Framing, chunking, multi-cover |
| G | Desktop app (Tauri) UX | 9 | Workflow, batch, visualization |
| H | Android & mobile | 9 | Camera, SAF, share-sheet, background |
| I | Cross-platform, WASM & distribution | 8 | Browser core, CLI packaging, reproducible builds |
| J | Developer tooling, CLI & testing | 9 | Fuzzing, benchmarking, golden vectors |
| K | Covert channels & transport | 4 | Experimental, sandbox-aware |
| L | Research / novel / AI-assisted | 4 | Frontier bets |
| **Σ** | | **100** | |

---

## A. Advanced embedding methods (12)

New implementations of the `Method` trait in `core/src/methods/`. Each inherits
crypto + framing for free and must ship property + golden tests.

1. **HUGO cost model** — Highly Undetectable steGO spatial distortion function
   (weighted directional pixel co-occurrence residuals). A sibling to the existing
   `adaptive_cost`, giving users a second, differently-characterized adaptive
   spatial method. `◆◆◆` · ~3–4wk · *Touches:* `methods/hugo.rs`, `registry.rs`.

2. **WOW (Wavelet Obtained Weights)** — directional wavelet-filter-bank residual
   costs; the canonical modern spatial adaptive scheme. Reuses the Haar machinery
   from `dwt_haar` for the filter bank. `◆◆◆` · ~4wk · *Touches:* `methods/wow.rs`,
   `dwt_haar.rs` (shared transforms).

3. **S-UNIWARD (true)** — the full spatial UNIWARD cost (three directional
   wavelet filters, per-pixel aggregated cost) as a rigorous upgrade of the current
   "UNIWARD-flavored" `adaptive_cost`. `◆◆◆◆` · ~4–6wk · *Touches:* `methods/uniward.rs`.

4. **J-UNIWARD (JPEG-domain)** — UNIWARD costs computed in the DCT domain and
   embedded via the existing JPEG codec, the state-of-the-art JPEG scheme. Ties
   into `methods/jpeg/`. `◆◆◆◆` · ~5–6wk · *Touches:* `methods/jpeg/juniward.rs`.

5. **UERD (Uniform Embedding Revisited Distortion)** — a lighter JPEG adaptive
   cost, faster than J-UNIWARD, good default for mobile. `◆◆◆` · ~3wk ·
   *Touches:* `methods/jpeg/uerd.rs`.

6. **Syndrome-Trellis Codes (STC)** — near-optimal practical coding that embeds a
   payload while *minimizing total distortion* under any cost model above. This is
   the piece that turns cost functions into real security; pairs with A1–A5.
   `◆◆◆◆` · ~5–6wk · *Touches:* `methods/stc.rs`, consumed by all adaptive methods.

7. **BPCS (Bit-Plane Complexity Segmentation)** — replaces "noisy" bit-plane
   blocks with payload, high capacity with low visual distortion; a classic not yet
   present. `◆◆` · ~2–3wk · *Touches:* `methods/bpcs.rs`.

8. **Palette / GIF embedding** — order/parity of palette entries and indexed
   pixels for indexed-color covers (GIF, indexed PNG), a distinct cover class.
   `◆◆` · ~2–3wk · *Touches:* `methods/palette.rs`, `image_io.rs` (palette path).

9. **Reversible Data Hiding (histogram-shifting / difference-expansion)** — cover
   is recovered *bit-exactly* after extraction; important for medical/forensic use
   where the carrier must not be altered permanently. `◆◆◆` · ~3–4wk ·
   *Touches:* `methods/rdh.rs`.

10. **CMYK / 16-bit / HDR channel embedding** — extend beyond RGBA8 to high-bit-depth
    and CMYK images, more LSB headroom and print-workflow relevance. `◆◆` · ~2wk ·
    *Touches:* `image_io.rs`, `methods/lsb_common.rs`.

11. **Alpha-channel & premultiplied-aware embedding** — deliberately use the alpha
    channel (currently skipped) with correct premultiplication handling as an
    optional high-capacity mode. `◆◆` · ~2wk · *Touches:* `methods/lsb_common.rs`.

12. **QIM / Dither-modulation** — quantization-index-modulation embedding with
    distortion-compensated dithering, a robustness-oriented method distinct from
    LSB. Foundation for watermarking (category C). `◆◆◆` · ~3wk · *Touches:*
    `methods/qim.rs`.

---

## B. Audio & video steganography (8)

13. **FLAC / lossless-audio LSB** — extend `wav_lsb` to decode FLAC to PCM, embed,
    re-encode losslessly; broadens audio covers without touching bit-exactness.
    `◆◆` · ~2–3wk · *Touches:* `methods/flac_lsb.rs`, new `flac` decode path.

14. **Echo-hiding (audio)** — embed bits as imperceptible echoes at key-selected
    delays; robust to some transcoding (explicitly deferred in the original spec,
    revisited here as an *optional, non-bit-exact* method with FEC from category C).
    `◆◆◆` · ~4wk · *Touches:* `methods/echo_hide.rs`.

15. **Spread-spectrum audio** — payload spread across the spectrum under a keyed
    PN sequence; survives light lossy compression. Needs the FEC layer (C21).
    `◆◆◆` · ~4wk · *Touches:* `methods/ss_audio.rs`.

16. **Phase-coding audio** — encode data in phase relationships of segmented audio;
    inaudible, moderately robust. `◆◆◆` · ~3wk · *Touches:* `methods/phase_audio.rs`.

17. **APNG / animated-image frame spreading** — split payload across frames of an
    animated PNG (or GIF), each frame carrying a keyed share. `◆◆` · ~3wk ·
    *Touches:* `methods/apng_spread.rs`, `image_io.rs`.

18. **Lossless video (FFV1 / raw) LSB** — per-frame LSB across a lossless video
    container; the bit-exact entry point into video without codec heaviness.
    `◆◆◆` · ~4–5wk · *Touches:* `methods/video_lossless.rs`.

19. **H.264/H.265 motion-vector steganography** — embed in inter-frame motion
    vector choices during encode; survives lossy video. Research-grade, needs a
    codec integration. `◆◆◆◆` · ~6–8wk · *Touches:* `methods/mv_stego.rs`, codec dep.

20. **DCT-domain video (per-frame JPEG-style)** — reuse the in-house DCT codec on
    intra-coded frames for lossy-tolerant video hiding. `◆◆◆◆` · ~6wk ·
    *Touches:* `methods/video_dct.rs`, `methods/jpeg/`.

---

## C. Robustness & error correction (9)

Make payloads survive the real world (resize, recompress, screenshot, print-scan).

21. **Reed–Solomon FEC layer** — optional forward-error-correction wrapped around
    the sealed blob *before* framing, so a fraction of corrupted carrier bits still
    recovers. The keystone for every lossy method (B14–B20, watermarking). `◆◆◆` ·
    ~3wk · *Touches:* `payload.rs` (frame flags), new `fec.rs`.

22. **LDPC / fountain (RaptorQ) codes** — rateless erasure coding so a payload
    spread over many carriers (or frames) recovers from *any sufficient subset*.
    Pairs with multi-cover (F). `◆◆◆◆` · ~4wk · *Touches:* `fec.rs`, `methods/` spread paths.

23. **Print-scan resistant watermarking** — embed a payload that survives being
    printed and photographed (geometric + tonal distortion), building on QIM (A12).
    `◆◆◆◆` · ~6wk · *Touches:* `methods/watermark_ps.rs`, sync-template code.

24. **JPEG-recompression-resistant embedding** — choose DCT coefficients whose LSBs
    survive a subsequent re-JPEG at typical quality factors. `◆◆◆` · ~4wk ·
    *Touches:* `methods/jpeg/robust.rs`.

25. **Resize / rescale synchronization** — embedded registration template lets the
    extractor re-align a resized or cropped stego image before reading. `◆◆◆` ·
    ~4wk · *Touches:* `methods/sync_template.rs`, `analysis.rs`.

26. **Rotation/affine-invariant embedding** — log-polar / Fourier-Mellin domain
    embedding that survives rotation and modest affine distortion. `◆◆◆◆` · ~5wk ·
    *Touches:* `methods/fmt_domain.rs`.

27. **Interleaving + scrambling layer** — spread FEC symbols so burst errors (a
    corrupted region) become correctable scattered errors. `◆◆` · ~1–2wk ·
    *Touches:* `fec.rs`.

28. **Redundant/replicated embedding mode** — write N copies of the payload in
    disjoint keyed regions and majority-vote on extract; cheap robustness knob.
    `◆◆` · ~2wk · *Touches:* `lib.rs` (embed orchestration), `payload.rs`.

29. **Capacity-vs-robustness tuning API** — a single "robustness level 0–3" option
    that auto-selects FEC rate, redundancy, and coefficient conservatism per method.
    `◆◆` · ~2wk · *Touches:* `method.rs` (`EmbedOpts`), UI in G/H.

---

## D. Steganalysis, detection & ML (10)

Grow `analysis.rs` from three classic tests into a genuine detection lab.

30. **SPAM / SRM feature extractor** — Subtractive Pixel Adjacency / Spatial Rich
    Model feature vectors, the standard input to modern detectors. `◆◆◆` · ~4wk ·
    *Touches:* `analysis/features.rs`.

31. **Ensemble-classifier detector** — an on-device FLD ensemble trained on SRM
    features distinguishing cover from stego; ships with pre-trained weights, no
    network. `◆◆◆◆` · ~5–6wk · *Touches:* `analysis/ensemble.rs`, bundled model.

32. **CNN steganalysis (SRNet-style, quantized)** — a small quantized neural
    detector runnable on-device (ONNX/`tract`), the ML frontier of detection.
    `◆◆◆◆` · ~6–8wk · *Touches:* `analysis/cnn.rs`, model asset.

33. **Calibration attack (JPEG)** — crop-and-recompress calibration for improved
    JPEG steganalysis, the classic feature-boost. `◆◆◆` · ~3wk · *Touches:*
    `analysis/calibration.rs`.

34. **Payload-length estimation (quantitative steganalysis)** — estimate *how much*
    is hidden, not just yes/no, via WS (weighted-stego) estimation. `◆◆◆` · ~3wk ·
    *Touches:* `analysis/quantitative.rs`.

35. **Automatic method-fingerprinting** — given a suspect file, rank *which* Stegno
    method (if any) most likely produced it. Great demo + red-team tool. `◆◆◆` ·
    ~4wk · *Touches:* `analysis/fingerprint.rs`.

36. **Batch steganalysis report** — scan a folder, output per-file risk scores and
    an aggregate HTML/JSON report. `◆◆` · ~2wk · *Touches:* `analysis/report.rs`,
    CLI (J).

37. **Structural / container scanner** — detect appended-EOF, polyglot, and rogue
    PNG/EXIF chunks (i.e. detectors for Stegno's own file-structure methods).
    `◆◆` · ~2wk · *Touches:* `analysis/structural.rs`.

38. **Histogram & bit-plane visualizer (data)** — produce the numeric series
    (per-plane, per-channel histograms, chi-square heatmap) that the apps render in
    G/H. `◆◆` · ~2wk · *Touches:* `analysis/visualize.rs`.

39. **Detector benchmark harness** — ROC/AUC evaluation of every detector against
    every embedder at set payload rates; publishes a comparison matrix. `◆◆◆` ·
    ~3wk · *Touches:* `analysis/bench.rs`, `docs/`.

---

## E. Crypto, key management & deniability (10)

Harden `crypto.rs`, framing, and the decoy slot.

40. **Post-quantum key wrapping (ML-KEM/Kyber)** — hybrid X25519 + ML-KEM to derive
    the content key, future-proofing recipients' keys. `◆◆◆` · ~3–4wk · *Touches:*
    `crypto.rs`, `payload.rs` (key-wrap header).

41. **Asymmetric (public-key) recipients** — encrypt to a recipient's public key
    (X25519 sealed box) instead of a shared passphrase; enables true one-way
    sending. `◆◆◆` · ~3wk · *Touches:* `crypto.rs`, key-management UI (G/H).

42. **XChaCha20-Poly1305 cipher option** — an alternative AEAD with a larger nonce,
    selectable in the frame's crypto-suite byte. `◆◆` · ~1–2wk · *Touches:*
    `crypto.rs`, frame `flags`.

43. **Argon2 auto-calibration** — benchmark the device at first run and pick
    Argon2id parameters hitting a target time, stored per-device. `◆◆` · ~2wk ·
    *Touches:* `crypto.rs`, settings (G/H).

44. **Multi-recipient / group payloads** — one stego file that N different keys can
    each open to *their own* slot; extends the decoy machinery to N slots. `◆◆◆` ·
    ~4wk · *Touches:* `payload.rs`, `lib.rs` (`embed_with_decoy` → N-slot).

45. **Shamir secret-sharing of the passphrase** — split the key into k-of-n shares
    (e.g. across several carriers), reconstruct only with a quorum. `◆◆◆` · ~3wk ·
    *Touches:* `crypto/sss.rs`.

46. **Deniable N-layer nesting** — recursively embed a decoy-within-decoy so escrow
    of one passphrase reveals only a plausible inner layer. `◆◆◆` · ~3wk ·
    *Touches:* `payload.rs`, decoy logic.

47. **Duress / panic passphrase** — a second passphrase that returns a benign decoy
    *and* (optionally) wipes the real slot region. `◆◆` · ~2wk · *Touches:*
    `lib.rs`, decoy logic.

48. **Keyfile + hardware-token support** — combine passphrase with a keyfile or a
    FIDO2/PIV token as a second factor for the KDF. `◆◆◆` · ~3–4wk · *Touches:*
    `crypto.rs`, platform integration (G/H).

49. **Password-strength meter + wordlist checks** — offline zxcvbn-style estimation
    and breach-wordlist check at embed time, surfaced in both apps. `◆◆` · ~2wk ·
    *Touches:* new `passphrase.rs`, UI (G/H).

---

## F. Capacity, payload & containers (8)

50. **Multi-cover / split-across-carriers** — shard one payload across several cover
    files with a keyed layout and per-shard headers; pairs with fountain codes (C22).
    `◆◆◆` · ~4wk · *Touches:* `payload.rs`, `lib.rs`, both UIs.

51. **Streaming embed/extract for large files** — chunked processing so multi-GB
    payloads/covers don't load fully into memory (critical on Android). `◆◆◆` · ~3wk ·
    *Touches:* `lib.rs` API (streaming variant), UniFFI surface.

52. **Compression pre-pass (zstd/brotli)** — optional compress-then-encrypt to raise
    effective capacity, with a frame flag so extract auto-inflates. `◆◆` · ~1–2wk ·
    *Touches:* `payload.rs`.

53. **Directory / archive payloads** — embed a whole folder (tar-in-memory) as a
    single secret, restored on extract. `◆◆` · ~2wk · *Touches:* `payload.rs`
    (`Secret::Archive`).

54. **Capacity auto-planner** — given a payload and a set of covers, recommend the
    method + cover(s) that fit with the best security margin. `◆◆◆` · ~3wk ·
    *Touches:* `capacity.rs`, `analysis.rs`, UI.

55. **Frame format v2 (extensible TLV header)** — migrate the fixed `STG0` header to
    a versioned TLV so future features (FEC, suite, slots) don't need format breaks;
    keep a v1 reader for back-compat. `◆◆◆` · ~3wk · *Touches:* `payload.rs`.

56. **Self-describing / auto-detect extract** — try all plausible methods and report
    which yields a valid frame, so users needn't remember the method used. `◆◆` ·
    ~2wk · *Touches:* `lib.rs`, `registry.rs`.

57. **Payload integrity manifest** — embed a signed manifest (sizes, hashes, method,
    timestamp) so the recipient can verify completeness after multi-cover reassembly.
    `◆◆` · ~2wk · *Touches:* `payload.rs`, `crypto.rs`.

---

## G. Desktop app — Tauri (9)

`desktop/src` (React) + `src-tauri` commands.

58. **Batch hide/extract queue** — drag in many files, apply one config, process
    with a progress list and per-item results. `◆◆` · ~3wk · *Touches:* `App.tsx`,
    `api.ts`, new Tauri commands.

59. **Live capacity + security preview** — as the user picks cover/method/payload,
    show capacity, estimated detectability (from D), and PSNR/SSIM in real time.
    `◆◆` · ~2–3wk · *Touches:* `App.tsx`, `api.ts`.

60. **Bit-plane / difference visualizer** — render the numeric series from D38 as
    interactive heatmaps and before/after diffs. `◆◆` · ~3wk · *Touches:* new React
    viz components, `api.ts`.

61. **Method comparison workbench** — embed the same payload with several methods,
    show a side-by-side capacity/quality/detectability table. `◆◆` · ~3wk ·
    *Touches:* `App.tsx`.

62. **Project / session files** — save an embed configuration (method, options,
    recipients) as a reusable `.stegproj`. `◆◆` · ~2wk · *Touches:* `src-tauri`, `App.tsx`.

63. **In-app steganalysis lab** — a full tab wrapping category D: load a file, run
    detectors, view the risk report. `◆◆◆` · ~4wk · *Touches:* `App.tsx`, `api.ts`.

64. **Key & recipient manager** — manage keyfiles, public keys (E41), and hardware
    tokens (E48) with an address-book UX. `◆◆◆` · ~3wk · *Touches:* `src-tauri`, `App.tsx`.

65. **Accessibility & i18n pass** — full keyboard nav, screen-reader labeling, and a
    string-externalized translation system. `◆◆` · ~2–3wk · *Touches:* all of
    `desktop/src`.

66. **Auto-update + signature verification** — Tauri updater with signed releases and
    an in-app changelog, without weakening the offline stance (opt-in check only).
    `◆◆` · ~2wk · *Touches:* `src-tauri`, CI (I/J).

---

## H. Android & mobile (9)

`android/` Kotlin + Compose + UniFFI.

67. **Share-sheet target** — accept images/files shared from other apps directly
    into a hide/extract flow. `◆◆` · ~2wk · *Touches:* `MainActivity.kt`, manifest,
    Compose nav.

68. **In-app camera capture** — shoot a fresh photo as the cover (fresh sensor noise
    is ideal for LSB), with CameraX. `◆◆` · ~3wk · *Touches:* new camera screen.

69. **Quick-tile / assist shortcuts** — a launcher/quick-settings shortcut to extract
    from the last screenshot or shared image. `◆◆` · ~2wk · *Touches:* Android
    services, manifest.

70. **Background batch worker** — WorkManager job to process a queue without keeping
    the app foregrounded; mirrors G58. `◆◆◆` · ~3wk · *Touches:* new worker, UniFFI
    streaming (F51).

71. **Biometric-gated key vault** — store recipient keys/keyfiles in the Android
    Keystore behind biometric unlock. `◆◆◆` · ~3wk · *Touches:* `MainActivity.kt`,
    Keystore integration.

72. **On-device steganalysis screen** — the D-category detectors surfaced in Compose,
    including the quantized CNN (D32) via `tract`/NNAPI. `◆◆◆◆` · ~4–5wk ·
    *Touches:* new screen, native model loading.

73. **Compose visualization screen** — bit-plane/histogram viz (D38) rendered with
    Compose Canvas. `◆◆` · ~3wk · *Touches:* new screen.

74. **Offline-first onboarding & method guide** — an in-app, illustrated explainer of
    each method and its tradeoffs for non-technical users. `◆◆` · ~2wk · *Touches:*
    Compose UI, content.

75. **iOS app (SwiftUI + UniFFI Swift bindings)** — a third native shell reusing the
    exact same `stegno-core` via UniFFI's Swift target; largest single mobile bet.
    `◆◆◆◆` · ~8–12wk · *Touches:* new `ios/` project, UniFFI Swift export.

---

## I. Cross-platform, WASM & distribution (8)

76. **WASM build of `stegno-core`** — compile the engine to WebAssembly (the design's
    stated future add-on) so a browser/PWA can run everything offline. `◆◆◆` · ~4wk ·
    *Touches:* `core` wasm target, JS glue.

77. **Browser PWA shell** — an installable, fully-offline web app over the WASM core,
    reusing desktop React components. `◆◆◆` · ~4–5wk · *Touches:* new `web/` app.

78. **Browser extension** — right-click "hide in / extract from this image" using the
    WASM core, no server. `◆◆◆` · ~4wk · *Touches:* new extension package.

79. **Reproducible builds + SLSA provenance** — deterministic core builds and signed
    provenance so users can verify binaries match source. `◆◆◆` · ~3wk · *Touches:*
    CI, build scripts.

80. **F-Droid + reproducible Android release** — package the Android app for F-Droid
    with a reproducible build (a strong trust signal for a privacy tool). `◆◆` ·
    ~2–3wk · *Touches:* Gradle, CI, metadata.

81. **Homebrew / winget / Flatpak packaging** — first-class installers for the desktop
    app and CLI across macOS/Windows/Linux. `◆◆` · ~2–3wk · *Touches:* packaging,
    CI.

82. **UniFFI bindings for Python & Node** — expose the engine to scripting ecosystems
    for automation and research. `◆◆` · ~2–3wk · *Touches:* UniFFI foreign targets.

83. **Signed, verifiable release pipeline** — end-to-end CI that builds all shells,
    runs golden-vector parity across platforms, and signs artifacts. `◆◆◆` · ~4wk ·
    *Touches:* CI, `tests/golden`.

---

## J. Developer tooling, CLI & testing (9)

84. **First-class `stegno` CLI** — grow `core/src/bin` into a full command-line tool
    (hide/extract/analyze/capacity/batch) with man pages and shell completions.
    `◆◆` · ~3wk · *Touches:* `core/src/bin`, docs.

85. **Coverage-guided fuzzing (`cargo-fuzz`)** — fuzz every decoder and extractor
    (image_io, jpeg codec, framing) against malformed input; wire into CI. `◆◆◆` ·
    ~3wk · *Touches:* `fuzz/`, CI.

86. **Differential / cross-implementation testing** — auto-generate stego files in
    Rust and verify a second reference reader (WASM/Python bindings) agrees, guarding
    interop. `◆◆◆` · ~3wk · *Touches:* `tests/`, bindings (I82).

87. **Property-test expansion + shrinking corpora** — exhaustive proptest coverage of
    every method across image sizes, formats, and payload boundaries. `◆◆` · ~2wk ·
    *Touches:* `tests/`.

88. **Benchmark suite (`criterion`)** — track embed/extract/analysis throughput per
    method over time to catch regressions. `◆◆` · ~2wk · *Touches:* `benches/`.

89. **Golden-vector expansion + CI gate** — a golden file per method × platform so any
    parity break fails CI (extends the Phase-0 golden idea to all 18+ methods). `◆◆` ·
    ~2wk · *Touches:* `tests/golden`.

90. **Method-authoring SDK + template** — a documented scaffold, checklist, and macro
    so new `Method`s (and their tests) can be added with minimal boilerplate. `◆◆` ·
    ~2wk · *Touches:* `method.rs`, `docs/`, a codegen macro.

91. **Constant-time / side-channel audit harness** — verify crypto and key-seeded
    paths don't leak via timing; add `dudect`-style tests. `◆◆◆` · ~3wk · *Touches:*
    `crypto.rs`, `prng.rs`, tests.

92. **Security-scanning CI (`cargo-audit`, `deny`, SAST)** — automated dependency and
    supply-chain scanning gating every merge. `◆◆` · ~1–2wk · *Touches:* CI.

---

## K. Covert channels & transport (4)

Experimental; the original spec marks network channels out-of-scope for the
sandboxed on-device tool, so these are explicitly opt-in / desktop-only research.

93. **Filesystem timestamp channel** — encode bits in file mtime nanoseconds across a
    directory; a covert channel needing no network. `◆◆◆` · ~2–3wk · *Touches:* new
    `methods/fs_timestamp.rs` (desktop/CLI only).

94. **PDF / OOXML document embedding** — hide in structural slack of PDF objects and
    DOCX/XLSX zip parts (a huge everyday cover class). `◆◆◆` · ~4wk · *Touches:*
    `methods/pdf.rs`, `methods/ooxml.rs`.

95. **QR-with-hidden-layer** — generate a scannable QR whose module-level noise
    carries a second keyed payload. `◆◆◆` · ~3wk · *Touches:* `methods/qr_stego.rs`.

96. **Font / glyph-substitution text stego** — homoglyph and OpenType-feature
    substitution as a richer text channel than zero-width. `◆◆◆` · ~3wk · *Touches:*
    `methods/glyph_sub.rs`.

---

## L. Research / novel / AI-assisted (4)

97. **Neural cover synthesis (on-device, quantized GAN)** — generate a *fresh* cover
    image conditioned to carry the payload with minimal distortion; frontier work,
    needs a small bundled generator. `◆◆◆◆` · ~8–12wk · *Touches:* `methods/gan_cover.rs`,
    model asset.

98. **LLM linguistic steganography (local model)** — drive a small local language
    model's token sampling to encode bits in fluent text (a rigorous successor to
    `mimic_words`), using arithmetic-coding-based distribution steganography. `◆◆◆◆` ·
    ~8wk · *Touches:* `methods/llm_stego.rs`, local model runtime.

99. **Provably-secure distribution-matching stego** — implement a minimum-entropy /
    iMEC-style coupling so the stego distribution provably matches the cover
    distribution for generative channels. `◆◆◆◆` · ~6–8wk · *Touches:* `methods/mec.rs`.

100. **Adversarial-robust embedding** — perturb embeddings to evade the very CNN
     detectors from D32 (a min-max game against the on-device steganalyzer), and
     document the arms-race tradeoffs. `◆◆◆◆` · ~6wk · *Touches:* `methods/adversarial.rs`,
     `analysis/cnn.rs`.

---

## Suggested first batches

Pick by dependency and leverage, not just novelty:

- **Batch 1 — Reliability foundation (unlocks the most):** C21 Reed–Solomon FEC,
  F55 frame format v2, F56 auto-detect extract, C28 redundant mode. These are the
  substrate half the catalog depends on.
- **Batch 2 — Security credibility:** A6 STC + A3/A4 a true UNIWARD, D30 SRM
  features, D31 ensemble detector. Turns "raises the bar" into measurable security.
- **Batch 3 — Reach:** I76 WASM core + I77 PWA, then H75 iOS. Same engine,
  three new surfaces.
- **Batch 4 — Everyday covers:** B13 FLAC, K94 PDF/OOXML, A8 palette/GIF.

Each batch enters the normal `brainstorm → spec → plan → TDD build` cycle.
