//! Audit every registered method against real files.
//!
//! Run:
//! `cargo run --release -p stegno-core --example method_audit -- <dir-of-real-files>`
//!
//! Round-tripping is the floor, not the bar. A method also has to keep its
//! promise: a JPEG method must emit a decodable JPEG, `png_text` must leave the
//! pixels untouched, `polyglot` must be valid as both a PNG and a ZIP, an LSB
//! method must only disturb low bits, and a text method must leave the visible
//! text alone. A method that round-trips while corrupting the carrier is worse
//! than one that fails loudly, because the damage is silent.

use std::collections::BTreeMap;
use std::path::Path;

use stegno_core::method::Media;
use stegno_core::payload::{Revealed, Secret};
use stegno_core::{capacity, embed, extract, registry};

/// What a check concluded.
enum Check {
    Pass(String),
    Fail(String),
    /// Not applicable to this method/cover pairing.
    Skip(String),
}

fn load(dir: &Path, name: &str) -> Option<Vec<u8>> {
    std::fs::read(dir.join(name)).ok()
}

/// Covers to try for a method, most representative first.
///
/// The `File` media deliberately sweeps every non-image, non-audio cover in the
/// corpus: a method that claims to work on "any file" has to be shown doing so
/// on documents, archives, models, audio and video containers alike.
fn covers_for(media: Media, files: &BTreeMap<String, Vec<u8>>) -> Vec<(String, Vec<u8>)> {
    let take = |names: &[&str]| -> Vec<(String, Vec<u8>)> {
        names
            .iter()
            .filter_map(|n| files.get(*n).map(|b| (n.to_string(), b.clone())))
            .collect()
    };
    match media {
        Media::Image => take(&["real.png", "real.jpg", "real.webp"]),
        Media::Audio => take(&["real.wav"]),
        Media::Text => take(&["real.txt", "real.md", "real.json", "real.svg"]),
        Media::File => take(&[
            "real.pdf", "real.docx", "real.pptx", "real.zip", "real.stl", "real.mp3", "real.mp4",
            "real.y4m", "real.json",
        ]),
    }
}

fn decodes_as_image(bytes: &[u8]) -> bool {
    stegno_core::image_io::decode_rgba(bytes).is_ok()
}

/// Does the output still parse as the same container the cover was?
fn container_intact(id: &str, cover_name: &str, cover: &[u8], stego: &[u8]) -> Check {
    // Image methods legitimately re-encode to PNG, and JPEG methods to JPEG;
    // either way the result must still decode as an image.
    if cover_name.ends_with(".png") || cover_name.ends_with(".jpg") || cover_name.ends_with(".webp") {
        return if decodes_as_image(stego) {
            Check::Pass("output still decodes as an image".into())
        } else {
            Check::Fail("output no longer decodes as an image — carrier corrupted".into())
        };
    }
    if cover_name.ends_with(".wav") {
        let ok = stego.len() > 12 && &stego[0..4] == b"RIFF" && &stego[8..12] == b"WAVE";
        return if ok {
            Check::Pass("still a RIFF/WAVE file".into())
        } else {
            Check::Fail("WAV header destroyed".into())
        };
    }
    if cover_name.ends_with(".pdf") {
        return if stego.starts_with(b"%PDF-") {
            Check::Pass("still starts with %PDF-".into())
        } else {
            Check::Fail("PDF header destroyed".into())
        };
    }
    if cover_name.ends_with(".docx") {
        return if stego.starts_with(b"PK") {
            Check::Pass("still a ZIP/OOXML container".into())
        } else {
            Check::Fail("DOCX (zip) header destroyed".into())
        };
    }
    if cover_name.ends_with(".txt") {
        return match std::str::from_utf8(stego) {
            Ok(_) => Check::Pass("still valid UTF-8 text".into()),
            Err(_) => Check::Fail("text cover is no longer valid UTF-8".into()),
        };
    }
    let _ = (id, cover);
    Check::Skip("no container rule".into())
}

/// Method-specific promises, beyond "it round-tripped".
fn keeps_its_promise(id: &str, cover: &[u8], stego: &[u8]) -> Check {
    match id {
        // Metadata-only: the picture itself must be bit-identical.
        "png_text" => {
            let (a, b) = (
                stegno_core::image_io::decode_rgba(cover),
                stegno_core::image_io::decode_rgba(stego),
            );
            match (a, b) {
                (Ok(a), Ok(b)) if a.pixels == b.pixels => {
                    Check::Pass("pixels bit-identical, as claimed".into())
                }
                (Ok(_), Ok(_)) => Check::Fail("claims metadata-only but pixels changed".into()),
                _ => Check::Fail("could not decode to compare pixels".into()),
            }
        }
        // Appends past the logical end: the cover must survive as an exact prefix.
        "append_eof" => {
            if stego.len() >= cover.len() && &stego[..cover.len()] == cover {
                Check::Pass("cover preserved as an exact prefix".into())
            } else {
                Check::Fail("cover bytes were modified".into())
            }
        }
        // Valid as both a PNG and a ZIP.
        "polyglot" => {
            let png_ok = decodes_as_image(stego);
            let zip_ok = stego.windows(4).any(|w| w == b"PK\x03\x04")
                && stego.windows(4).any(|w| w == b"PK\x05\x06");
            match (png_ok, zip_ok) {
                (true, true) => Check::Pass("valid as both image and ZIP".into()),
                (false, _) => Check::Fail("not a valid image — polyglot claim broken".into()),
                (_, false) => Check::Fail("no ZIP structure — polyglot claim broken".into()),
            }
        }
        // Spatial LSB family: every changed sample must move by at most one.
        "lsb_image" | "lsb_seeded" | "lsb_matching" | "lsbmr" | "edge_adaptive" | "adaptive_cost"
        | "hill" => match (
            stegno_core::image_io::decode_rgba(cover),
            stegno_core::image_io::decode_rgba(stego),
        ) {
            (Ok(a), Ok(b)) if a.pixels.len() == b.pixels.len() => {
                let worst = a
                    .pixels
                    .iter()
                    .zip(b.pixels.iter())
                    .map(|(x, y)| (*x as i16 - *y as i16).abs())
                    .max()
                    .unwrap_or(0);
                if worst <= 1 {
                    Check::Pass(format!("max sample change ±{worst}"))
                } else {
                    Check::Fail(format!("changes samples by up to {worst}, not ±1"))
                }
            }
            (Ok(a), Ok(b)) => Check::Fail(format!(
                "dimensions changed: {}x{} -> {}x{}",
                a.width, a.height, b.width, b.height
            )),
            _ => Check::Fail("could not decode to compare".into()),
        },
        // Audio LSB: headers untouched, samples move by at most one.
        "wav_lsb" => {
            if stego.len() != cover.len() {
                return Check::Fail("WAV length changed".into());
            }
            let worst = cover
                .iter()
                .zip(stego.iter())
                .map(|(a, b)| (*a as i16 - *b as i16).abs())
                .max()
                .unwrap_or(0);
            if worst <= 1 {
                Check::Pass(format!("max byte change ±{worst}, length unchanged"))
            } else {
                Check::Fail(format!("alters bytes by up to {worst}"))
            }
        }
        // Text channels: the readable words must be untouched. Invisible
        // carriers (zero-width, tag chars) and layout whitespace are stripped
        // before comparing, since those *are* the channel.
        "zero_width" | "unicode_tags" | "whitespace" => {
            let strip = |s: &str| -> String {
                s.chars()
                    .filter(|c| {
                        !matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}')
                            && !('\u{E0000}'..='\u{E007F}').contains(c)
                            && !c.is_whitespace()
                    })
                    .collect()
            };
            match (std::str::from_utf8(cover), std::str::from_utf8(stego)) {
                (Ok(a), Ok(b)) if strip(a) == strip(b) => {
                    Check::Pass("visible words unchanged".into())
                }
                (Ok(_), Ok(_)) => Check::Fail("visible text was altered".into()),
                _ => Check::Fail("output is not valid UTF-8".into()),
            }
        }
        // JPEG-domain methods must emit a real JPEG, not a PNG in disguise.
        "jpeg_jsteg" | "jpeg_f5" | "jpeg_outguess" | "jpeg_mc" => {
            if stego.starts_with(&[0xFF, 0xD8, 0xFF]) && decodes_as_image(stego) {
                Check::Pass("emits a decodable JPEG".into())
            } else if decodes_as_image(stego) {
                Check::Fail("output decodes, but is not a JPEG".into())
            } else {
                Check::Fail("output is not a decodable image".into())
            }
        }
        "dwt_haar" | "lsb_high" | "pvd" => match (
            stegno_core::image_io::decode_rgba(cover),
            stegno_core::image_io::decode_rgba(stego),
        ) {
            (Ok(a), Ok(b)) if a.width == b.width && a.height == b.height => {
                Check::Pass("dimensions preserved".into())
            }
            _ => Check::Fail("image dimensions changed or undecodable".into()),
        },
        "mimic_words" => Check::Skip("generative: discards the cover by design".into()),
        _ => Check::Skip("no specific promise recorded".into()),
    }
}

/// The stealth tier the planner advertises for a method.
fn claimed_tier(id: &str) -> u8 {
    match id {
        "lsb_image" | "lsb_high" | "append_eof" | "png_text" | "polyglot" | "whitespace" => 0,
        "lsb_seeded" | "lsb_matching" | "edge_adaptive" | "pvd" | "wav_lsb" | "zero_width"
        | "unicode_tags" => 1,
        "dwt_haar" | "jpeg_jsteg" | "jpeg_f5" | "jpeg_outguess" | "jpeg_mc" | "adaptive_cost"
        | "hill" | "mimic_words" => 2,
        _ => 1,
    }
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: method_audit <dir-of-real-files>");
    let dir = Path::new(&dir);

    // Everything the corpus offers, so nothing silently goes untested.
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("real.") {
                if let Some(b) = load(dir, &name) {
                    files.insert(name, b);
                }
            }
        }
    }
    let payload = load(dir, "payload.bin").expect("payload.bin missing");
    println!(
        "corpus: {}\n",
        files.keys().cloned().collect::<Vec<_>>().join(", ")
    );

    // Detectability of each image method on one shared cover, so the stealth
    // claims can be compared like for like.
    let mut stealth: Vec<(String, u8, f64)> = Vec::new();

    let mut broken: Vec<String> = Vec::new();

    for m in registry::registry() {
        let id = m.id();
        let covers = covers_for(m.media(), &files);
        if covers.is_empty() {
            println!("{id:<15} SKIP  no real cover of its media type available");
            continue;
        }
        for (cover_name, cover) in covers {
            let cap = match capacity(id.to_string(), cover.clone()) {
                Ok(c) => c as usize,
                Err(e) => {
                    println!("{id:<15} {cover_name:<11} declines this cover ({e})");
                    continue;
                }
            };
            // Use a real payload, trimmed to what this cover can hold.
            let want = payload.len().min(cap.saturating_sub(64)).max(1);
            if cap < 128 {
                println!("{id:<15} {cover_name:<11} SKIP  capacity only {cap} bytes");
                continue;
            }
            let secret = Secret::File {
                name: "payload.bin".into(),
                bytes: payload[..want].to_vec(),
            };

            let stego = match embed(id.to_string(), cover.clone(), secret, "audit pass".into()) {
                Ok(s) => s,
                Err(e) => {
                    println!("{id:<15} {cover_name:<11} FAIL  embed error: {e}");
                    broken.push(format!("{id} ({cover_name}): embed failed — {e}"));
                    continue;
                }
            };

            // 1. Does the hidden data come back intact?
            let round = match extract(id.to_string(), stego.clone(), "audit pass".into()) {
                Ok(Revealed::File { bytes, .. }) if bytes == payload[..want] => {
                    Check::Pass(format!("{want} bytes recovered exactly"))
                }
                Ok(Revealed::File { bytes, .. }) => {
                    Check::Fail(format!("recovered {} bytes, expected {want}", bytes.len()))
                }
                Ok(other) => Check::Fail(format!("recovered wrong kind: {other:?}")),
                Err(e) => Check::Fail(format!("extract error: {e}")),
            };
            let container = container_intact(id, &cover_name, &cover, &stego);
            let promise = keeps_its_promise(id, &cover, &stego);

            // The path the Reveal screen actually takes: the recipient is not
            // told which method was used. A method whose output cannot be
            // auto-detected is broken from the user's side however well it
            // round-trips when you name it explicitly.
            let auto = match stegno_core::extract_auto(stego.clone(), "audit pass".into()) {
                Ok(a) => match a.revealed {
                    Revealed::File { bytes, .. } if bytes == payload[..want] => {
                        Check::Pass(format!("auto-detected as {}", a.method_id))
                    }
                    Revealed::None => Check::Fail("reveal-without-method finds nothing".into()),
                    _ => Check::Fail("reveal-without-method returned the wrong data".into()),
                },
                Err(e) => Check::Fail(format!("reveal-without-method errored: {e}")),
            };

            let mut verdict = "OK";
            let mut notes: Vec<String> = Vec::new();
            for (label, c) in [
                ("roundtrip", round),
                ("container", container),
                ("promise", promise),
                ("auto-reveal", auto),
            ] {
                match c {
                    Check::Pass(_) => {}
                    Check::Skip(_) => {}
                    Check::Fail(why) => {
                        verdict = "FAIL";
                        notes.push(format!("{label}: {why}"));
                    }
                }
            }
            if verdict == "FAIL" {
                broken.push(format!("{id} ({cover_name}): {}", notes.join("; ")));
            }
            println!(
                "{id:<15} {cover_name:<11} {verdict}  cap {:>9}  {}",
                cap,
                notes.join(" | ")
            );

            // How suspicious does the result actually look? Only meaningful on
            // the shared photo cover, and only for pixel-domain output.
            if cover_name == "real.png" && verdict == "OK" {
                if let Ok(d) = stegno_core::detect_lsb(stego.clone()) {
                    stealth.push((id.to_string(), claimed_tier(id), d.ml_confidence));
                }
            }
        }
    }

    // --- do the stealth claims survive contact with a detector? ---
    //
    // Measured across fill rates, because the answer depends entirely on them.
    // At full capacity nothing hides: the LSB plane is replaced wholesale and
    // every detector screams. Content-adaptive placement is supposed to earn its
    // keep at the *low* rates people actually use, so judging a stealth claim on
    // a 100%-full cover would condemn every method equally and prove nothing.
    println!("\n============ STEALTH CLAIMS vs MEASURED ============");
    let _ = &stealth;
    if let Some(base) = files.get("real.png") {
        let clean = stegno_core::detect_lsb(base.clone())
            .map(|d| d.ml_confidence)
            .unwrap_or(0.0);
        println!("clean photo measures {clean:.3} suspicious");
        println!("(1.000 = certainly carries hidden data, 0.000 = looks untouched)\n");
        println!(
            "{:<15} {:>7} {:>9} {:>9} {:>9}   {}",
            "method", "claimed", "5% full", "25% full", "90% full", "verdict"
        );

        let mut rows: Vec<(String, u8, [f64; 3], String)> = Vec::new();
        for m in registry::registry() {
            let id = m.id();
            if m.media() != Media::Image || !m.preserves_cover() {
                continue;
            }
            let cap = match capacity(id.to_string(), base.clone()) {
                Ok(c) => c as usize,
                Err(_) => continue,
            };
            let mut measured = [f64::NAN; 3];
            for (slot, pct) in [5usize, 25, 90].iter().enumerate() {
                let want = (cap * pct / 100).saturating_sub(64);
                if want < 32 {
                    continue;
                }
                let secret = Secret::File {
                    name: "p".into(),
                    bytes: payload.iter().cycle().take(want).copied().collect(),
                };
                if let Ok(s) = embed(id.to_string(), base.clone(), secret, "audit pass".into()) {
                    if let Ok(d) = stegno_core::detect_lsb(s) {
                        measured[slot] = d.ml_confidence;
                    }
                }
            }
            let tier = claimed_tier(id);
            let low = measured[0];
            let verdict = if low.is_nan() {
                "cover too small to judge".to_string()
            } else if tier >= 2 && low > 0.5 {
                "CLAIM NOT MET — tier 2 yet obvious even at 5%".to_string()
            } else if tier == 1 && low > 0.8 {
                "CLAIM NOT MET — tier 1 yet obvious even at 5%".to_string()
            } else {
                "consistent".to_string()
            };
            rows.push((id.to_string(), tier, measured, verdict));
        }
        rows.sort_by(|a, b| {
            a.2[0].partial_cmp(&b.2[0]).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(&b.0))
        });
        let show = |v: f64| if v.is_nan() { "  —".to_string() } else { format!("{v:.3}") };
        for (id, tier, m, verdict) in &rows {
            println!(
                "{id:<15} {tier:>7} {:>9} {:>9} {:>9}   {verdict}",
                show(m[0]),
                show(m[1]),
                show(m[2])
            );
        }
    } else {
        println!("(no shared photo cover in the corpus)");
    }

    println!("\n================ BROKEN ================");
    if broken.is_empty() {
        println!("none");
    } else {
        for b in &broken {
            println!("  {b}");
        }
        println!("\n{} failing method/cover combinations", broken.len());
    }
}
