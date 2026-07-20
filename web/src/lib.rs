//! WebAssembly bindings for `stegno-core`.
//!
//! Thin `wasm-bindgen` wrappers over the same audited engine the desktop and
//! Android apps use, so a browser PWA can hide, reveal, analyze, and sanitize
//! entirely on-device — no network, no server. Binary data crosses the boundary
//! as `Uint8Array` (`Vec<u8>`); structured results come back as plain JS objects
//! via `serde_wasm_bindgen`.

use serde::Serialize;
use stegno_core::payload::{FileRecord, Revealed, Secret};
use stegno_core::{Recipient, StegnoError};
use wasm_bindgen::prelude::*;

fn err(e: StegnoError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(|e| JsValue::from_str(&e.to_string()))
}

// --- serializable mirrors of the core result types -------------------------

#[derive(Serialize)]
struct MethodInfoJs {
    id: String,
    #[serde(rename = "displayName")]
    display_name: String,
    media: String,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum RevealedJs {
    None,
    Text { text: String },
    File { name: String, bytes: Vec<u8> },
    Files { files: Vec<FileJs> },
}

#[derive(Serialize)]
struct FileJs {
    name: String,
    bytes: Vec<u8>,
}

impl From<Revealed> for RevealedJs {
    fn from(r: Revealed) -> Self {
        match r {
            Revealed::None => RevealedJs::None,
            Revealed::Text { text } => RevealedJs::Text { text },
            Revealed::File { name, bytes } => RevealedJs::File { name, bytes },
            Revealed::Files { files } => RevealedJs::Files {
                files: files
                    .into_iter()
                    .map(|f| FileJs { name: f.name, bytes: f.bytes })
                    .collect(),
            },
        }
    }
}

// --- info / capacity -------------------------------------------------------

#[wasm_bindgen(js_name = listMethods)]
pub fn list_methods() -> Result<JsValue, JsValue> {
    let v: Vec<MethodInfoJs> = stegno_core::list_methods()
        .into_iter()
        .map(|m| MethodInfoJs {
            id: m.id,
            display_name: m.display_name,
            media: m.media,
        })
        .collect();
    to_js(&v)
}

#[wasm_bindgen(js_name = capacity)]
pub fn capacity(method_id: String, cover: Vec<u8>) -> Result<f64, JsValue> {
    stegno_core::capacity(method_id, cover)
        .map(|c| c as f64)
        .map_err(err)
}

// --- hide ------------------------------------------------------------------

#[wasm_bindgen(js_name = embedText)]
pub fn embed_text(
    method_id: String,
    cover: Vec<u8>,
    text: String,
    passphrase: String,
) -> Result<Vec<u8>, JsValue> {
    stegno_core::embed(method_id, cover, Secret::Text { text }, passphrase).map_err(err)
}

#[wasm_bindgen(js_name = embedFile)]
pub fn embed_file(
    method_id: String,
    cover: Vec<u8>,
    name: String,
    bytes: Vec<u8>,
    passphrase: String,
) -> Result<Vec<u8>, JsValue> {
    stegno_core::embed(method_id, cover, Secret::File { name, bytes }, passphrase).map_err(err)
}

/// Advanced hide with FEC robustness (0=off, 1..3) and optional compression.
#[wasm_bindgen(js_name = embedAdvancedText)]
pub fn embed_advanced_text(
    method_id: String,
    cover: Vec<u8>,
    text: String,
    passphrase: String,
    robustness: u8,
    compress: bool,
) -> Result<Vec<u8>, JsValue> {
    stegno_core::embed_advanced(
        method_id,
        cover,
        Secret::Text { text },
        passphrase,
        robustness,
        compress,
    )
    .map_err(err)
}

/// Hide up to 8 messages for 8 recipients in one image. `recipients` is a JS
/// array of `{ text, passphrase }`.
#[wasm_bindgen(js_name = embedMultiText)]
pub fn embed_multi_text(cover: Vec<u8>, recipients: JsValue) -> Result<Vec<u8>, JsValue> {
    #[derive(serde::Deserialize)]
    struct Rec {
        text: String,
        passphrase: String,
    }
    let recs: Vec<Rec> = serde_wasm_bindgen::from_value(recipients)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let core: Vec<Recipient> = recs
        .into_iter()
        .map(|r| Recipient {
            secret: Secret::Text { text: r.text },
            passphrase: r.passphrase,
        })
        .collect();
    stegno_core::embed_multi(cover, core).map_err(err)
}

// --- reveal ----------------------------------------------------------------

#[wasm_bindgen(js_name = extract)]
pub fn extract(method_id: String, stego: Vec<u8>, passphrase: String) -> Result<JsValue, JsValue> {
    let r = stegno_core::extract(method_id, stego, passphrase).map_err(err)?;
    to_js(&RevealedJs::from(r))
}

/// Reveal without knowing the method. Returns `{ methodId, revealed }`.
#[wasm_bindgen(js_name = extractAuto)]
pub fn extract_auto(stego: Vec<u8>, passphrase: String) -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    struct AutoJs {
        #[serde(rename = "methodId")]
        method_id: String,
        revealed: RevealedJs,
    }
    let found = stegno_core::extract_auto(stego, passphrase).map_err(err)?;
    to_js(&AutoJs {
        method_id: found.method_id,
        revealed: found.revealed.into(),
    })
}

// --- analysis --------------------------------------------------------------

#[wasm_bindgen(js_name = detectLsb)]
pub fn detect_lsb(image: Vec<u8>) -> Result<JsValue, JsValue> {
    let d = stegno_core::detect_lsb(image).map_err(err)?;
    #[derive(Serialize)]
    struct D {
        #[serde(rename = "chiSquareP")]
        chi_square_p: f64,
        #[serde(rename = "rsRegularityGap")]
        rs_regularity_gap: f64,
        #[serde(rename = "samplePairRate")]
        sample_pair_rate: f64,
        #[serde(rename = "mlConfidence")]
        ml_confidence: f64,
    }
    to_js(&D {
        chi_square_p: d.chi_square_p,
        rs_regularity_gap: d.rs_regularity_gap,
        sample_pair_rate: d.sample_pair_rate,
        ml_confidence: d.ml_confidence,
    })
}

#[wasm_bindgen(js_name = scanStructure)]
pub fn scan_structure(data: Vec<u8>) -> Result<JsValue, JsValue> {
    let r = stegno_core::structural::scan_structure(data);
    #[derive(Serialize)]
    struct FindingJs {
        kind: String,
        detail: String,
        severity: u8,
    }
    #[derive(Serialize)]
    struct ReportJs {
        format: String,
        findings: Vec<FindingJs>,
        suspicious: bool,
    }
    to_js(&ReportJs {
        format: r.format,
        findings: r
            .findings
            .into_iter()
            .map(|f| FindingJs {
                kind: f.kind,
                detail: f.detail,
                severity: f.severity,
            })
            .collect(),
        suspicious: r.suspicious,
    })
}

#[wasm_bindgen(js_name = fingerprint)]
pub fn fingerprint(data: Vec<u8>) -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    struct GuessJs {
        label: String,
        confidence: f64,
        reason: String,
    }
    let v: Vec<GuessJs> = stegno_core::fingerprint::fingerprint(data)
        .into_iter()
        .map(|g| GuessJs {
            label: g.label,
            confidence: g.confidence,
            reason: g.reason,
        })
        .collect();
    to_js(&v)
}

#[wasm_bindgen(js_name = planEmbedding)]
pub fn plan_embedding(cover: Vec<u8>, payload_len: f64) -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    struct RecJs {
        #[serde(rename = "methodId")]
        method_id: String,
        #[serde(rename = "usableBytes")]
        usable_bytes: f64,
        fits: bool,
        #[serde(rename = "fillRatio")]
        fill_ratio: f64,
        #[serde(rename = "stealthTier")]
        stealth_tier: u8,
        note: String,
    }
    let v: Vec<RecJs> = stegno_core::planner::plan_embedding(cover, payload_len as u64)
        .into_iter()
        .map(|r| RecJs {
            method_id: r.method_id,
            usable_bytes: r.usable_bytes as f64,
            fits: r.fits,
            fill_ratio: r.fill_ratio,
            stealth_tier: r.stealth_tier,
            note: r.note,
        })
        .collect();
    to_js(&v)
}

// --- defense & keys --------------------------------------------------------

/// Strip any hidden payload from a file. Returns `{ cleaned, format, actions, changed }`.
#[wasm_bindgen(js_name = sanitize)]
pub fn sanitize(data: Vec<u8>) -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    struct SanJs {
        cleaned: Vec<u8>,
        format: String,
        actions: Vec<String>,
        changed: bool,
    }
    let r = stegno_core::sanitize::sanitize(data);
    to_js(&SanJs {
        cleaned: r.cleaned,
        format: r.format,
        actions: r.actions,
        changed: r.changed,
    })
}

#[wasm_bindgen(js_name = passphraseStrength)]
pub fn passphrase_strength(passphrase: String) -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    struct StrJs {
        score: u8,
        #[serde(rename = "entropyBits")]
        entropy_bits: f64,
        #[serde(rename = "crackTimeDisplay")]
        crack_time_display: String,
        warning: String,
        suggestions: Vec<String>,
    }
    let s = stegno_core::passphrase::estimate_passphrase_strength(passphrase);
    to_js(&StrJs {
        score: s.score,
        entropy_bits: s.entropy_bits,
        crack_time_display: s.crack_time_display,
        warning: s.warning,
        suggestions: s.suggestions,
    })
}

// --- visualization ---------------------------------------------------------

#[wasm_bindgen(js_name = bitPlane)]
pub fn bit_plane(image: Vec<u8>, channel: u8, plane: u8) -> Result<Vec<u8>, JsValue> {
    stegno_core::visualize::bit_plane(image, channel, plane).map_err(err)
}

#[wasm_bindgen(js_name = changeMap)]
pub fn change_map(cover: Vec<u8>, stego: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    stegno_core::visualize::change_map(cover, stego).map_err(err)
}

// --- decoy (plausible deniability) -----------------------------------------

/// Usable bytes per slot when hiding a real + decoy message (≈ half the image).
#[wasm_bindgen(js_name = decoyCapacity)]
pub fn decoy_capacity(cover: Vec<u8>) -> Result<f64, JsValue> {
    stegno_core::decoy_capacity(cover).map(|c| c as f64).map_err(err)
}

/// Hide a real message and a decoy message in one image, each under its own
/// passphrase. Revealing with the decoy passphrase shows only the decoy.
#[wasm_bindgen(js_name = embedWithDecoyText)]
pub fn embed_with_decoy_text(
    cover: Vec<u8>,
    real_text: String,
    real_passphrase: String,
    decoy_text: String,
    decoy_passphrase: String,
) -> Result<Vec<u8>, JsValue> {
    stegno_core::embed_with_decoy(
        cover,
        Secret::Text { text: real_text },
        real_passphrase,
        Secret::Text { text: decoy_text },
        decoy_passphrase,
    )
    .map_err(err)
}

// --- split across covers ---------------------------------------------------

/// Deserialize a JS array of `Uint8Array` (or byte arrays) into `Vec<Vec<u8>>`.
fn from_js_bufs(v: JsValue) -> Result<Vec<Vec<u8>>, JsValue> {
    serde_wasm_bindgen::from_value(v).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Spread one secret across N covers; every resulting stego is required to
/// rebuild it. Returns a JS array of byte arrays (one per cover).
#[wasm_bindgen(js_name = embedSplitText)]
pub fn embed_split_text(
    method_id: String,
    covers: JsValue,
    text: String,
    passphrase: String,
) -> Result<JsValue, JsValue> {
    let chunks: Vec<stegno_core::ByteChunk> = from_js_bufs(covers)?
        .into_iter()
        .map(|bytes| stegno_core::ByteChunk { bytes })
        .collect();
    let out = stegno_core::embed_split(method_id, chunks, Secret::Text { text }, passphrase)
        .map_err(err)?;
    let bytes: Vec<Vec<u8>> = out.into_iter().map(|c| c.bytes).collect();
    to_js(&bytes)
}

/// Rebuild a secret from all its split-cover stego files. `stegos` is a JS array
/// of byte arrays. Returns `{ kind, ... }` like [`extract`].
#[wasm_bindgen(js_name = extractSplit)]
pub fn extract_split(
    method_id: String,
    stegos: JsValue,
    passphrase: String,
) -> Result<JsValue, JsValue> {
    let chunks: Vec<stegno_core::ByteChunk> = from_js_bufs(stegos)?
        .into_iter()
        .map(|bytes| stegno_core::ByteChunk { bytes })
        .collect();
    let r = stegno_core::extract_split(method_id, chunks, passphrase).map_err(err)?;
    to_js(&RevealedJs::from(r))
}

// --- Shamir secret sharing -------------------------------------------------

#[derive(Serialize, serde::Deserialize)]
struct ShareJs {
    x: u8,
    y: Vec<u8>,
}

/// Split `secret` bytes into `shares` pieces; any `threshold` reconstruct it,
/// fewer reveal nothing. Returns a JS array of `{ x, y }`.
#[wasm_bindgen(js_name = sssSplit)]
pub fn sss_split(secret: Vec<u8>, threshold: u8, shares: u8) -> Result<JsValue, JsValue> {
    let v: Vec<ShareJs> = stegno_core::sss::sss_split(secret, threshold, shares)
        .map_err(err)?
        .into_iter()
        .map(|s| ShareJs { x: s.x, y: s.y })
        .collect();
    to_js(&v)
}

/// Reconstruct a secret from a JS array of `{ x, y }` shares.
#[wasm_bindgen(js_name = sssCombine)]
pub fn sss_combine(shares: JsValue) -> Result<Vec<u8>, JsValue> {
    let ins: Vec<ShareJs> = serde_wasm_bindgen::from_value(shares)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let core: Vec<stegno_core::sss::SecretShare> = ins
        .into_iter()
        .map(|s| stegno_core::sss::SecretShare { x: s.x, y: s.y })
        .collect();
    stegno_core::sss::sss_combine(core).map_err(err)
}

// --- more analysis ---------------------------------------------------------

/// Fraction of pixels that differ between an original and a stego image.
#[wasm_bindgen(js_name = changeRate)]
pub fn change_rate(cover: Vec<u8>, stego: Vec<u8>) -> Result<f64, JsValue> {
    stegno_core::visualize::change_rate(cover, stego).map_err(err)
}

/// Image-quality comparison. Returns `{ mse, psnrDb, ssim }`.
#[wasm_bindgen(js_name = quality)]
pub fn quality(cover: Vec<u8>, stego: Vec<u8>) -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    struct Q {
        mse: f64,
        #[serde(rename = "psnrDb")]
        psnr_db: f64,
        ssim: f64,
    }
    let q = stegno_core::quality(cover, stego).map_err(err)?;
    to_js(&Q {
        mse: q.mse,
        psnr_db: q.psnr_db,
        ssim: q.ssim,
    })
}

/// Estimate how detectable hiding a payload of `payloadLen` bytes would be.
/// Returns `{ methodId, cleanConfidence, stegoConfidence, delta, psnrDb, verdict }`.
#[wasm_bindgen(js_name = detectability)]
pub fn detectability(
    method_id: String,
    cover: Vec<u8>,
    payload_len: f64,
) -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    struct D {
        #[serde(rename = "methodId")]
        method_id: String,
        #[serde(rename = "cleanConfidence")]
        clean_confidence: f64,
        #[serde(rename = "stegoConfidence")]
        stego_confidence: f64,
        delta: f64,
        #[serde(rename = "psnrDb")]
        psnr_db: f64,
        verdict: String,
    }
    let d = stegno_core::benchmark::detectability(method_id, cover, payload_len as u64)
        .map_err(err)?;
    to_js(&D {
        method_id: d.method_id,
        clean_confidence: d.clean_confidence,
        stego_confidence: d.stego_confidence,
        delta: d.delta,
        psnr_db: d.psnr_db,
        verdict: d.verdict,
    })
}

// --- diagnostics -----------------------------------------------------------

/// Round-trip every method through hide→reveal. Returns an array of
/// `{ methodId, media, ok, usableBytes, detail }`.
#[wasm_bindgen(js_name = runSelfTest)]
pub fn run_self_test() -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    struct T {
        #[serde(rename = "methodId")]
        method_id: String,
        media: String,
        ok: bool,
        #[serde(rename = "usableBytes")]
        usable_bytes: f64,
        detail: String,
    }
    let v: Vec<T> = stegno_core::doctor::run_self_test()
        .into_iter()
        .map(|r| T {
            method_id: r.method_id,
            media: r.media,
            ok: r.ok,
            usable_bytes: r.usable_bytes as f64,
            detail: r.detail,
        })
        .collect();
    to_js(&v)
}

/// Time Argon2id key derivation on this device. Returns
/// `{ millis, memoryKib, iterations, verdict }`.
#[wasm_bindgen(js_name = benchmarkKdf)]
pub fn benchmark_kdf() -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    struct B {
        millis: f64,
        #[serde(rename = "memoryKib")]
        memory_kib: u32,
        iterations: u32,
        verdict: String,
    }
    let b = stegno_core::crypto::benchmark_kdf();
    to_js(&B {
        millis: b.millis,
        memory_kib: b.memory_kib,
        iterations: b.iterations,
        verdict: b.verdict,
    })
}

// A convenient re-export so the FileRecord type participates in the build even
// when no method returns Files (keeps the API stable).
#[allow(dead_code)]
fn _touch(_f: FileRecord) {}
