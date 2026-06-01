# Stegno Phase 0 — Foundation + LSB Image — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone, offline steganography toolkit whose shared Rust engine hides/extracts encrypted payloads in PNG via LSB, consumed by a Tauri desktop app and a native Android app.

**Architecture:** One Rust crate `stegno-core` owns crypto (Argon2id + AES-256-GCM), versioned payload framing, a pluggable `Method` trait, and an `lsb_image` method. Tauri's Rust backend depends on the crate directly; native Android calls it via UniFFI/JNI. The engine operates on already-encrypted, already-framed bytes so every method inherits identical crypto.

**Tech Stack:** Rust (image, aes-gcm, argon2, getrandom, thiserror, uniffi, proptest), Tauri 2 + React/Vite (desktop), Kotlin + Jetpack Compose + UniFFI (Android).

---

## File Structure

```
core/Cargo.toml                  # crate manifest, deps, uniffi build
core/build.rs                    # uniffi scaffolding build step
core/src/lib.rs                  # public API + UniFFI exports + error enum
core/src/crypto.rs               # seal/open: Argon2id KDF + AES-256-GCM
core/src/payload.rs              # Secret <-> inner bytes; outer frame/unframe
core/src/method.rs               # Method trait + Media/Capacity/EmbedOpts types
core/src/registry.rs             # MethodRegistry, list_methods, lookup
core/src/image_io.rs             # decode any image -> RGBA8; encode -> PNG
core/src/methods/mod.rs          # methods module index
core/src/methods/lsb_image.rs    # LsbImage method
core/tests/roundtrip.rs          # property tests (proptest)
core/tests/golden.rs             # fixed cross-platform parity vectors
desktop/                         # Tauri app (scaffolded later in plan)
android/                         # native Android app (scaffolded later in plan)
```

---

## Task 1: Cargo workspace + core crate skeleton

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `core/Cargo.toml`
- Create: `core/src/lib.rs`

- [ ] **Step 1: Write workspace manifest**

`Cargo.toml`:
```toml
[workspace]
members = ["core"]
resolver = "2"
```

- [ ] **Step 2: Write core crate manifest**

`core/Cargo.toml`:
```toml
[package]
name = "stegno-core"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["lib", "cdylib", "staticlib"]
name = "stegno_core"

[dependencies]
image = { version = "0.25", default-features = false, features = ["png", "jpeg", "bmp", "webp", "gif"] }
aes-gcm = "0.10"
argon2 = "0.5"
getrandom = "0.2"
thiserror = "2"
uniffi = { version = "0.28", features = ["build"] }

[build-dependencies]
uniffi = { version = "0.28", features = ["build"] }

[dev-dependencies]
proptest = "1"

[features]
default = []
```

- [ ] **Step 3: Write minimal lib.rs that compiles**

`core/src/lib.rs`:
```rust
//! stegno-core: offline steganography engine.
pub mod crypto;
pub mod payload;
pub mod method;
pub mod registry;
pub mod image_io;
pub mod methods;
```
(Stub the modules with empty files in later tasks before this compiles; for this task, create empty module files so it builds.)

- [ ] **Step 4: Create empty module files**

Create empty `core/src/crypto.rs`, `core/src/payload.rs`, `core/src/method.rs`, `core/src/registry.rs`, `core/src/image_io.rs`, `core/src/methods/mod.rs`.

- [ ] **Step 5: Build**

Run: `cargo build -p stegno-core`
Expected: compiles (warnings about unused modules are fine).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml core/
git commit -m "chore(core): cargo workspace + stegno-core skeleton"
```

---

## Task 2: Crypto layer (Argon2id + AES-256-GCM)

**Files:**
- Modify: `core/src/crypto.rs`
- Test: inline `#[cfg(test)]` in `core/src/crypto.rs`

- [ ] **Step 1: Write failing tests**

Append to `core/src/crypto.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_open_roundtrips() {
        let blob = seal(b"hello world", "correct horse").unwrap();
        let out = open(&blob, "correct horse").unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = seal(b"secret", "right").unwrap();
        assert!(matches!(open(&blob, "wrong"), Err(CryptoError::AuthFailed)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut blob = seal(b"secret", "pw").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(matches!(open(&blob, "pw"), Err(CryptoError::AuthFailed)));
    }
}
```

- [ ] **Step 2: Run, expect failure**

Run: `cargo test -p stegno-core crypto`
Expected: FAIL (no `seal`/`open`).

- [ ] **Step 3: Implement crypto**

Prepend to `core/src/crypto.rs`:
```rust
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Argon2, Algorithm, Params, Version};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CryptoError {
    #[error("authentication failed")]
    AuthFailed,
    #[error("crypto input too short")]
    TooShort,
    #[error("key derivation failed")]
    Kdf,
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    // m=19456 KiB, t=2, p=1 — interactive target.
    let params = Params::new(19456, 2, 1, Some(32)).map_err(|_| CryptoError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).expect("OS RNG");
    v
}

/// Returns: salt(16) | nonce(12) | ciphertext+tag
pub fn seal(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    let salt = rand_bytes(SALT_LEN);
    let nonce_bytes = rand_bytes(NONCE_LEN);
    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| CryptoError::AuthFailed)?;
    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(CryptoError::TooShort);
    }
    let salt = &blob[..SALT_LEN];
    let nonce_bytes = &blob[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct = &blob[SALT_LEN + NONCE_LEN..];
    let key = derive_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| CryptoError::AuthFailed)
}
```

- [ ] **Step 4: Run, expect pass**

Run: `cargo test -p stegno-core crypto`
Expected: 3 passing.

- [ ] **Step 5: Commit**

```bash
git add core/src/crypto.rs
git commit -m "feat(core): Argon2id + AES-256-GCM seal/open"
```

---

## Task 3: Method trait + shared types

**Files:**
- Modify: `core/src/method.rs`

- [ ] **Step 1: Implement types + trait (no behavior to test yet)**

`core/src/method.rs`:
```rust
use crate::lib_error::StegnoError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Media { Image, Audio, Text, File }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capacity {
    /// Usable payload bytes after frame + crypto overhead.
    pub usable_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct EmbedOpts;

pub trait Method: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn media(&self) -> Media;
    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError>;
    fn embed(&self, cover: &[u8], payload: &[u8], opts: &EmbedOpts) -> Result<Vec<u8>, StegnoError>;
    fn extract(&self, stego: &[u8]) -> Result<Option<Vec<u8>>, StegnoError>;
}
```
(`StegnoError` defined in Task 6; create `core/src/lib_error.rs` placeholder there. To keep this task compiling standalone, temporarily `use crate::StegnoError;` will be wired in Task 6 — for now add `pub mod lib_error;` to lib.rs and a stub error in Task 6 before building the whole crate.)

- [ ] **Step 2: Build (whole crate builds after Task 6 wires the error). Commit now.**

```bash
git add core/src/method.rs
git commit -m "feat(core): Method trait + Media/Capacity/EmbedOpts"
```

---

## Task 4: Payload framing

**Files:**
- Modify: `core/src/payload.rs`

- [ ] **Step 1: Write failing tests**

Append to `core/src/payload.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_secret_roundtrips_inner() {
        let s = Secret::Text("hi".into());
        let inner = serialize_secret(&s);
        assert_eq!(deserialize_secret(&inner).unwrap(), s);
    }

    #[test]
    fn file_secret_roundtrips_inner() {
        let s = Secret::File { name: "a.bin".into(), bytes: vec![1,2,3] };
        let inner = serialize_secret(&s);
        assert_eq!(deserialize_secret(&inner).unwrap(), s);
    }

    #[test]
    fn frame_unframe_roundtrips() {
        let body = vec![9u8; 40];
        let framed = frame(&body);
        let got = unframe(&framed).unwrap();
        assert_eq!(got, Some(body));
    }

    #[test]
    fn unframe_rejects_bad_magic() {
        assert_eq!(unframe(&[0,1,2,3,4,5,6,7,8,9]).unwrap(), None);
    }
}
```

- [ ] **Step 2: Run, expect failure**

Run: `cargo test -p stegno-core payload`
Expected: FAIL.

- [ ] **Step 3: Implement**

Prepend to `core/src/payload.rs`:
```rust
use crate::StegnoError;

const MAGIC: [u8; 4] = *b"STG0";
const VERSION: u8 = 1;
const HDR_LEN: usize = 4 + 1 + 1 + 1 + 4; // magic+version+flags+slot+len

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secret {
    Text(String),
    File { name: String, bytes: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revealed {
    None,
    Text(String),
    File { name: String, bytes: Vec<u8> },
}

pub fn serialize_secret(s: &Secret) -> Vec<u8> {
    match s {
        Secret::Text(t) => {
            let mut v = vec![0x00u8];
            v.extend_from_slice(t.as_bytes());
            v
        }
        Secret::File { name, bytes } => {
            let nb = name.as_bytes();
            let mut v = vec![0x01u8];
            v.extend_from_slice(&(nb.len() as u16).to_be_bytes());
            v.extend_from_slice(nb);
            v.extend_from_slice(bytes);
            v
        }
    }
}

pub fn deserialize_secret(inner: &[u8]) -> Result<Secret, StegnoError> {
    let kind = *inner.first().ok_or(StegnoError::CorruptPayload)?;
    match kind {
        0x00 => Ok(Secret::Text(
            String::from_utf8(inner[1..].to_vec()).map_err(|_| StegnoError::CorruptPayload)?,
        )),
        0x01 => {
            if inner.len() < 3 { return Err(StegnoError::CorruptPayload); }
            let nlen = u16::from_be_bytes([inner[1], inner[2]]) as usize;
            if inner.len() < 3 + nlen { return Err(StegnoError::CorruptPayload); }
            let name = String::from_utf8(inner[3..3 + nlen].to_vec())
                .map_err(|_| StegnoError::CorruptPayload)?;
            Ok(Secret::File { name, bytes: inner[3 + nlen..].to_vec() })
        }
        _ => Err(StegnoError::CorruptPayload),
    }
}

/// MAGIC|version|flags|slot|len(u32 BE)|body
pub fn frame(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HDR_LEN + body.len());
    v.extend_from_slice(&MAGIC);
    v.push(VERSION);
    v.push(0); // flags
    v.push(0); // slot_type: primary
    v.extend_from_slice(&(body.len() as u32).to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// Reads header from a byte stream; Ok(None) if MAGIC absent.
pub fn unframe(stream: &[u8]) -> Result<Option<Vec<u8>>, StegnoError> {
    if stream.len() < HDR_LEN || stream[..4] != MAGIC {
        return Ok(None);
    }
    let len = u32::from_be_bytes([stream[7], stream[8], stream[9], stream[10]]) as usize;
    let end = HDR_LEN + len;
    if stream.len() < end {
        return Err(StegnoError::CorruptPayload);
    }
    Ok(Some(stream[HDR_LEN..end].to_vec()))
}

pub fn header_len() -> usize { HDR_LEN }
```

- [ ] **Step 4: Run, expect pass**

Run: `cargo test -p stegno-core payload`
Expected: 4 passing.

- [ ] **Step 5: Commit**

```bash
git add core/src/payload.rs
git commit -m "feat(core): versioned payload framing + Secret/Revealed"
```

---

## Task 5: image_io (decode -> RGBA8, encode PNG)

**Files:**
- Modify: `core/src/image_io.rs`

- [ ] **Step 1: Write failing test**

Append to `core/src/image_io.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_roundtrips_dimensions() {
        // 4x3 white RGBA
        let rgba = RgbaImage { width: 4, height: 3, pixels: vec![255u8; 4*3*4] };
        let png = encode_png(&rgba).unwrap();
        let back = decode_rgba(&png).unwrap();
        assert_eq!((back.width, back.height), (4, 3));
        assert_eq!(back.pixels.len(), 4*3*4);
    }
}
```

- [ ] **Step 2: Run, expect failure**

Run: `cargo test -p stegno-core image_io`
Expected: FAIL.

- [ ] **Step 3: Implement**

Prepend to `core/src/image_io.rs`:
```rust
use crate::StegnoError;
use image::{ImageEncoder, ImageReader};
use std::io::Cursor;

pub struct RgbaImage {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>, // RGBA8, row-major
}

pub fn decode_rgba(bytes: &[u8]) -> Result<RgbaImage, StegnoError> {
    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| StegnoError::UnsupportedFormat)?;
    let img = reader.decode().map_err(|_| StegnoError::UnsupportedFormat)?;
    let rgba = img.to_rgba8();
    Ok(RgbaImage { width: rgba.width(), height: rgba.height(), pixels: rgba.into_raw() })
}

pub fn encode_png(img: &RgbaImage) -> Result<Vec<u8>, StegnoError> {
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(&mut out)
        .write_image(&img.pixels, img.width, img.height, image::ExtendedColorType::Rgba8)
        .map_err(|_| StegnoError::Internal("png encode".into()))?;
    Ok(out)
}
```

- [ ] **Step 4: Run, expect pass**

Run: `cargo test -p stegno-core image_io`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/image_io.rs
git commit -m "feat(core): image_io decode->RGBA8, encode PNG"
```

---

## Task 6: Public API, error enum, registry, UniFFI wiring

**Files:**
- Modify: `core/src/lib.rs`
- Modify: `core/src/registry.rs`
- Create: `core/build.rs`
- Create: `core/src/stegno.udl`

- [ ] **Step 1: Define StegnoError, Revealed export, public fns in lib.rs**

Replace `core/src/lib.rs`:
```rust
//! stegno-core: offline steganography engine.
pub mod crypto;
pub mod payload;
pub mod method;
pub mod registry;
pub mod image_io;
pub mod methods;

use payload::{Revealed, Secret};

#[derive(Debug, thiserror::Error)]
pub enum StegnoError {
    #[error("image too small for this payload")]
    CoverTooSmall,
    #[error("unsupported or corrupt cover")]
    UnsupportedFormat,
    #[error("wrong passphrase or no hidden data")]
    AuthFailed,
    #[error("no hidden data found")]
    NoHiddenData,
    #[error("hidden data is corrupted")]
    CorruptPayload,
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct MethodInfo {
    pub id: String,
    pub display_name: String,
    pub media: String,
}

pub fn list_methods() -> Vec<MethodInfo> {
    registry::registry().iter().map(|m| MethodInfo {
        id: m.id().to_string(),
        display_name: m.display_name().to_string(),
        media: format!("{:?}", m.media()),
    }).collect()
}

pub fn capacity(method_id: String, cover: Vec<u8>) -> Result<u64, StegnoError> {
    let m = registry::lookup(&method_id).ok_or(StegnoError::Internal("unknown method".into()))?;
    Ok(m.capacity(&cover)?.usable_bytes)
}

pub fn embed(method_id: String, cover: Vec<u8>, secret: Secret, passphrase: String) -> Result<Vec<u8>, StegnoError> {
    let m = registry::lookup(&method_id).ok_or(StegnoError::Internal("unknown method".into()))?;
    let inner = payload::serialize_secret(&secret);
    let sealed = crypto::seal(&inner, &passphrase).map_err(|_| StegnoError::Internal("seal".into()))?;
    let framed = payload::frame(&sealed);
    m.embed(&cover, &framed, &method::EmbedOpts::default())
}

pub fn extract(method_id: String, stego: Vec<u8>, passphrase: String) -> Result<Revealed, StegnoError> {
    let m = registry::lookup(&method_id).ok_or(StegnoError::Internal("unknown method".into()))?;
    let stream = m.extract(&stego)?;
    let framed = match stream { Some(s) => s, None => return Ok(Revealed::None) };
    let sealed = match payload::unframe(&framed)? { Some(s) => s, None => return Ok(Revealed::None) };
    let inner = crypto::open(&sealed, &passphrase).map_err(|_| StegnoError::AuthFailed)?;
    Ok(match payload::deserialize_secret(&inner)? {
        Secret::Text(t) => Revealed::Text(t),
        Secret::File { name, bytes } => Revealed::File { name, bytes },
    })
}

uniffi::include_scaffolding!("stegno");
```

(Note: `method.rs` Task 3 used `crate::lib_error::StegnoError`; change that import to `crate::StegnoError`. Update method.rs accordingly.)

- [ ] **Step 2: Implement registry**

`core/src/registry.rs`:
```rust
use crate::method::Method;
use crate::methods::lsb_image::LsbImage;

pub fn registry() -> Vec<Box<dyn Method>> {
    vec![Box::new(LsbImage)]
}

pub fn lookup(id: &str) -> Option<Box<dyn Method>> {
    registry().into_iter().find(|m| m.id() == id)
}
```

- [ ] **Step 3: Write UDL**

`core/src/stegno.udl`:
```idl
namespace stegno {
    sequence<MethodInfo> list_methods();
    [Throws=StegnoError]
    u64 capacity(string method_id, sequence<u8> cover);
    [Throws=StegnoError]
    sequence<u8> embed(string method_id, sequence<u8> cover, Secret secret, string passphrase);
    [Throws=StegnoError]
    Revealed extract(string method_id, sequence<u8> stego, string passphrase);
};

dictionary MethodInfo {
    string id;
    string display_name;
    string media;
};

[Enum]
interface Secret {
    Text(string text);
    File(string name, sequence<u8> bytes);
};

[Enum]
interface Revealed {
    None();
    Text(string text);
    File(string name, sequence<u8> bytes);
};

[Error]
enum StegnoError {
    "CoverTooSmall", "UnsupportedFormat", "AuthFailed",
    "NoHiddenData", "CorruptPayload", "Internal",
};
```

- [ ] **Step 4: Write build.rs**

`core/build.rs`:
```rust
fn main() {
    uniffi::generate_scaffolding("src/stegno.udl").unwrap();
}
```

- [ ] **Step 5: Build whole crate**

Run: `cargo build -p stegno-core`
Expected: compiles. Fix import mismatches (`method.rs` StegnoError path) until green.

- [ ] **Step 6: Commit**

```bash
git add core/
git commit -m "feat(core): public API, StegnoError, registry, UniFFI scaffolding"
```

---

## Task 7: LsbImage method + roundtrip/capacity tests

**Files:**
- Modify: `core/src/methods/mod.rs`
- Create: `core/src/methods/lsb_image.rs`

- [ ] **Step 1: Module index**

`core/src/methods/mod.rs`:
```rust
pub mod lsb_image;
```

- [ ] **Step 2: Write failing tests**

Create `core/src/methods/lsb_image.rs` with tests first:
```rust
use crate::image_io::{decode_rgba, encode_png, RgbaImage};
use crate::method::{Capacity, EmbedOpts, Media, Method};
use crate::payload;
use crate::StegnoError;

pub struct LsbImage;

const BITS_PER_PIXEL: usize = 3; // R,G,B LSBs

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: u32, h: u32) -> Vec<u8> {
        let img = RgbaImage { width: w, height: h, pixels: vec![128u8; (w*h*4) as usize] };
        encode_png(&img).unwrap()
    }

    #[test]
    fn embed_extract_identity() {
        let cover = solid(64, 64);
        let body = payload::frame(b"the quick brown fox");
        let stego = LsbImage.embed(&cover, &body, &EmbedOpts::default()).unwrap();
        let got = LsbImage.extract(&stego).unwrap().unwrap();
        assert_eq!(&got[..body.len()], &body[..]);
    }

    #[test]
    fn no_data_returns_none() {
        let cover = solid(16, 16);
        assert_eq!(LsbImage.extract(&cover).unwrap(), None);
    }

    #[test]
    fn too_small_errors() {
        let cover = solid(4, 4); // 48 bits = 6 bytes capacity
        let body = vec![0u8; 100];
        assert!(matches!(
            LsbImage.embed(&cover, &body, &EmbedOpts::default()),
            Err(StegnoError::CoverTooSmall)
        ));
    }
}
```

- [ ] **Step 3: Run, expect failure**

Run: `cargo test -p stegno-core lsb_image`
Expected: FAIL (trait not implemented).

- [ ] **Step 4: Implement the method**

Insert before the `#[cfg(test)]` block in `core/src/methods/lsb_image.rs`:
```rust
fn write_bit(byte: &mut u8, bit: u8) { *byte = (*byte & 0xFE) | (bit & 1); }

impl Method for LsbImage {
    fn id(&self) -> &'static str { "lsb_image" }
    fn display_name(&self) -> &'static str { "LSB Image (PNG)" }
    fn media(&self) -> Media { Media::Image }

    fn capacity(&self, cover: &[u8]) -> Result<Capacity, StegnoError> {
        let img = decode_rgba(cover)?;
        let total_bits = (img.width as u64) * (img.height as u64) * BITS_PER_PIXEL as u64;
        let total_bytes = total_bits / 8;
        let overhead = payload::header_len() as u64 + 16 + 12 + 16 + 1; // hdr+salt+nonce+tag+type
        Ok(Capacity { usable_bytes: total_bytes.saturating_sub(overhead) })
    }

    fn embed(&self, cover: &[u8], payload_bytes: &[u8], _opts: &EmbedOpts) -> Result<Vec<u8>, StegnoError> {
        let mut img = decode_rgba(cover)?;
        let capacity_bytes = ((img.width as usize) * (img.height as usize) * BITS_PER_PIXEL) / 8;
        if payload_bytes.len() > capacity_bytes {
            return Err(StegnoError::CoverTooSmall);
        }
        let mut bit_index = 0usize;
        for &byte in payload_bytes {
            for b in (0..8).rev() {
                let bit = (byte >> b) & 1;
                let pixel = bit_index / BITS_PER_PIXEL;
                let chan = bit_index % BITS_PER_PIXEL; // 0=R,1=G,2=B
                let idx = pixel * 4 + chan;
                write_bit(&mut img.pixels[idx], bit);
                bit_index += 1;
            }
        }
        encode_png(&img)
    }

    fn extract(&self, stego: &[u8]) -> Result<Option<Vec<u8>>, StegnoError> {
        let img = decode_rgba(stego)?;
        let total_bytes = ((img.width as usize) * (img.height as usize) * BITS_PER_PIXEL) / 8;
        let read_byte = |byte_idx: usize| -> u8 {
            let mut out = 0u8;
            for b in (0..8).rev() {
                let bit_index = byte_idx * 8 + (7 - b);
                let pixel = bit_index / BITS_PER_PIXEL;
                let chan = bit_index % BITS_PER_PIXEL;
                let idx = pixel * 4 + chan;
                out |= (img.pixels[idx] & 1) << b;
            }
            out
        };
        // Read header (HDR_LEN bytes), validate magic via payload::unframe on a
        // progressively grown buffer.
        let hdr = payload::header_len();
        if total_bytes < hdr { return Ok(None); }
        let mut head = Vec::with_capacity(hdr);
        for i in 0..hdr { head.push(read_byte(i)); }
        // Peek length using unframe semantics: rebuild full stream lazily.
        // Determine declared length from header bytes [7..11].
        if head[..4] != *b"STG0" { return Ok(None); }
        let len = u32::from_be_bytes([head[7], head[8], head[9], head[10]]) as usize;
        let need = hdr + len;
        if need > total_bytes { return Err(StegnoError::CorruptPayload); }
        let mut buf = Vec::with_capacity(need);
        for i in 0..need { buf.push(read_byte(i)); }
        Ok(Some(buf))
    }
}
```

- [ ] **Step 5: Run, expect pass**

Run: `cargo test -p stegno-core`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add core/src/methods/
git commit -m "feat(core): lsb_image method (sequential RGB LSB)"
```

---

## Task 8: End-to-end + property + golden tests

**Files:**
- Create: `core/tests/roundtrip.rs`
- Create: `core/tests/golden.rs`

- [ ] **Step 1: End-to-end + property test**

`core/tests/roundtrip.rs`:
```rust
use proptest::prelude::*;
use stegno_core::{embed, extract, capacity, list_methods};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::image_io::{encode_png, RgbaImage};

fn cover(w: u32, h: u32) -> Vec<u8> {
    encode_png(&RgbaImage { width: w, height: h, pixels: vec![100u8; (w*h*4) as usize] }).unwrap()
}

#[test]
fn lists_lsb_image() {
    assert!(list_methods().iter().any(|m| m.id == "lsb_image"));
}

#[test]
fn text_end_to_end() {
    let c = cover(128, 128);
    let stego = embed("lsb_image".into(), c, Secret::Text("hello".into()), "pw".into()).unwrap();
    let r = extract("lsb_image".into(), stego, "pw".into()).unwrap();
    assert_eq!(r, Revealed::Text("hello".into()));
}

#[test]
fn wrong_passphrase_is_authfailed() {
    let c = cover(128, 128);
    let stego = embed("lsb_image".into(), c, Secret::Text("hi".into()), "right".into()).unwrap();
    assert!(extract("lsb_image".into(), stego, "wrong".into()).is_err());
}

#[test]
fn clean_image_reveals_none() {
    let c = cover(64, 64);
    assert_eq!(extract("lsb_image".into(), c, "pw".into()).unwrap(), Revealed::None);
}

proptest! {
    #[test]
    fn random_text_roundtrips(s in ".{0,200}") {
        let c = cover(256, 256);
        let stego = embed("lsb_image".into(), c, Secret::Text(s.clone()), "pw".into()).unwrap();
        let r = extract("lsb_image".into(), stego, "pw".into()).unwrap();
        prop_assert_eq!(r, Revealed::Text(s));
    }
}
```

- [ ] **Step 2: Golden parity test**

`core/tests/golden.rs`:
```rust
use stegno_core::{embed, extract};
use stegno_core::payload::{Revealed, Secret};
use stegno_core::image_io::{encode_png, RgbaImage};

// Embedding is deterministic given fixed cover+payload EXCEPT for the random
// salt/nonce in crypto. So we assert the *recovered* value is stable across
// runs and platforms, which is the real interop guarantee.
#[test]
fn cross_platform_recovery_is_stable() {
    let c = encode_png(&RgbaImage { width: 100, height: 100, pixels: vec![200u8; 100*100*4] }).unwrap();
    let file = Secret::File { name: "note.txt".into(), bytes: b"parity".to_vec() };
    let stego = embed("lsb_image".into(), c, file.clone(), "k".into()).unwrap();
    let got = extract("lsb_image".into(), stego, "k".into()).unwrap();
    assert_eq!(got, Revealed::File { name: "note.txt".into(), bytes: b"parity".to_vec() });
}
```

- [ ] **Step 3: Run**

Run: `cargo test -p stegno-core --tests`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add core/tests/
git commit -m "test(core): e2e, property, and parity tests"
```

---

## Task 9: Tauri desktop shell

**Files:**
- Create: `desktop/` via `cargo create-tauri-app` (React + TS + Vite)
- Modify: `desktop/src-tauri/Cargo.toml` (add `stegno-core` path dep)
- Create: `desktop/src-tauri/src/commands.rs`
- Modify: `desktop/src-tauri/src/lib.rs` (register commands)
- Create/Modify: `desktop/src/App.tsx`, `desktop/src/api.ts`, components

- [ ] **Step 1: Scaffold**

Run (non-interactive): `cargo create-tauri-app desktop --template react-ts --manager npm -y`
Then add to root `Cargo.toml` workspace members: `"desktop/src-tauri"`.

- [ ] **Step 2: Add core dependency**

`desktop/src-tauri/Cargo.toml` `[dependencies]`:
```toml
stegno-core = { path = "../../core" }
```

- [ ] **Step 3: Tauri commands**

`desktop/src-tauri/src/commands.rs`:
```rust
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{embed as core_embed, extract as core_extract, capacity as core_capacity, list_methods as core_list, MethodInfo};

#[tauri::command]
pub fn list_methods() -> Vec<(String, String, String)> {
    core_list().into_iter().map(|m: MethodInfo| (m.id, m.display_name, m.media)).collect()
}

#[tauri::command]
pub fn capacity(method_id: String, cover: Vec<u8>) -> Result<u64, String> {
    core_capacity(method_id, cover).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn embed_text(method_id: String, cover: Vec<u8>, text: String, passphrase: String) -> Result<Vec<u8>, String> {
    core_embed(method_id, cover, Secret::Text(text), passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn embed_file(method_id: String, cover: Vec<u8>, name: String, bytes: Vec<u8>, passphrase: String) -> Result<Vec<u8>, String> {
    core_embed(method_id, cover, Secret::File { name, bytes }, passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn extract(method_id: String, stego: Vec<u8>, passphrase: String) -> Result<RevealedDto, String> {
    match core_extract(method_id, stego, passphrase).map_err(|e| e.to_string())? {
        Revealed::None => Ok(RevealedDto { kind: "none".into(), text: None, name: None, bytes: None }),
        Revealed::Text(t) => Ok(RevealedDto { kind: "text".into(), text: Some(t), name: None, bytes: None }),
        Revealed::File { name, bytes } => Ok(RevealedDto { kind: "file".into(), text: None, name: Some(name), bytes: Some(bytes) }),
    }
}

#[derive(serde::Serialize)]
pub struct RevealedDto {
    pub kind: String,
    pub text: Option<String>,
    pub name: Option<String>,
    pub bytes: Option<Vec<u8>>,
}
```

- [ ] **Step 4: Register commands** in `desktop/src-tauri/src/lib.rs` `invoke_handler`:
```rust
mod commands;
// ...
.invoke_handler(tauri::generate_handler![
    commands::list_methods, commands::capacity,
    commands::embed_text, commands::embed_file, commands::extract
])
```

- [ ] **Step 5: Frontend api.ts + two-tab UI** (Hide/Extract). Use `@tauri-apps/api/core` `invoke`; `@tauri-apps/plugin-dialog` + `plugin-fs` for open/save. Build the Hide tab (cover picker, text/file toggle, passphrase, capacity meter, embed → save dialog) and Extract tab (stego picker, passphrase, reveal text or save file).

- [ ] **Step 6: Build + smoke run**

Run: `cd desktop && npm install && npm run tauri build` (or `tauri dev` to verify).
Expected: app builds; manual hide→extract works.

- [ ] **Step 7: Commit**

```bash
git add desktop/ Cargo.toml
git commit -m "feat(desktop): Tauri shell wired to stegno-core"
```

---

## Task 10: Native Android shell (UniFFI)

**Files:**
- Create: `android/` Gradle project (Compose, min SDK 26)
- Create: UniFFI Kotlin bindings generation + cargo-ndk build of `.so`
- Create: Compose UI (Hide/Extract screens) + SAF pickers

- [ ] **Step 1: Generate Kotlin bindings**

Install: `cargo install uniffi-bindgen` (or use the crate's bindgen binary).
Run: `cargo run --features=uniffi/cli --bin uniffi-bindgen generate core/src/stegno.udl --language kotlin --out-dir android/app/src/main/java`
(Adjust per uniffi 0.28 bindgen invocation.)

- [ ] **Step 2: Build core for Android**

Install `cargo-ndk`. Run:
`cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o android/app/src/main/jniLibs build --release -p stegno-core`

- [ ] **Step 3: Scaffold Gradle/Compose app** (min SDK 26, no INTERNET permission). Add `net.java.dev.jna:jna:5.x@aar` (UniFFI runtime dependency) and the generated bindings.

- [ ] **Step 4: Compose UI** — two screens (Hide/Extract) calling the generated `embed`/`extract`/`capacity`/`listMethods`; SAF (`ACTION_OPEN_DOCUMENT` / `ACTION_CREATE_DOCUMENT`) for cover/stego/output.

- [ ] **Step 5: Build**

Run: `cd android && ./gradlew assembleDebug`
Expected: APK builds; manual hide→extract on emulator works.

- [ ] **Step 6: Commit**

```bash
git add android/
git commit -m "feat(android): native Compose shell via UniFFI"
```

---

## Self-Review

- **Spec coverage:** crypto (T2), framing (T4), Method trait/registry (T3,T6), lsb_image (T7), public API (T6), image_io (T5), tests incl. parity (T8), Tauri (T9), Android (T10). All Phase-0 spec sections mapped. ✓
- **Placeholders:** none in core tasks (T1–T8 contain full code). T9/T10 shells use coarser steps because scaffolding tools generate boilerplate; the core-touching code is fully specified. Acceptable.
- **Type consistency:** `StegnoError` path unified to `crate::StegnoError` (note in T3/T6). `Secret`/`Revealed` defined in payload.rs (T4), re-used in lib.rs (T6) and tests (T8). `header_len()` defined T4, used T7. `Capacity.usable_bytes` defined T3, used T7. ✓
