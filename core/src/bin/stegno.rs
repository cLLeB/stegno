//! `stegno` — command-line front-end for the stegno-core engine.
//!
//! A thin, offline CLI over the same audited engine the desktop and Android apps
//! use. No new dependencies: argument parsing is hand-rolled so the binary stays
//! as auditable as the library.
//!
//! Usage:
//!   stegno methods
//!   stegno capacity <method> <cover>
//!   stegno hide <method> <cover> <out> --pass P (--text T | --file F) [--robust 1..3]
//!   stegno reveal <stego> --pass P [--method M] [--out FILE]
//!   stegno analyze <file>
//!   stegno strength <passphrase>
//!
//! Built with `--features cli`.

use std::process::ExitCode;

use stegno_core::benchmark::detectability;
use stegno_core::crypto::benchmark_kdf;
use stegno_core::doctor::run_self_test;
use stegno_core::fingerprint::fingerprint;
use stegno_core::passphrase::estimate_passphrase_strength;
use stegno_core::payload::{Revealed, Secret};
use stegno_core::planner::plan_embedding;
use stegno_core::sanitize::sanitize;
use stegno_core::sss::SecretShare;
use stegno_core::structural::scan_structure;
use stegno_core::visualize::{bit_plane, change_map};
use stegno_core::{
    capacity, cover_info, detect_lsb, embed_advanced, embed_composite, embed_multi, extract,
    extract_auto, extract_composite, list_methods, sss_combine_secret, sss_split_secret, ByteChunk,
    Recipient,
};

const USAGE: &str = "\
stegno — offline steganography toolkit

USAGE:
    stegno methods
    stegno doctor
    stegno capacity <method> <cover>
    stegno plan <cover> <payload-bytes>
    stegno risk <method> <cover> <payload-bytes>
    stegno cover <file>
    stegno hide <method> <cover> <out> --pass <P> (--text <T> | --file <path>) [--robust <1-3>] [--compress]
    stegno multi <cover> <out> (--to <pass>:<message> | --to-file <pass>:<path>) ...
    stegno compose --cover <path> [--cover <path> ...] --out <prefix>
                   (--secret <pass>:<text> | --secret-file <pass>:<path>) ...
                   [--robust <1-3>] [--compress]
    stegno reveal <stego> [<stego> ...] --pass <P> [--method <M>] [--out <path>]
    stegno analyze <file>
    stegno bitplane <image> <out> [--channel 0-2] [--plane 0-7]
    stegno changemap <cover> <stego> <out>
    stegno scan <dir> [--threshold <0-100>] [--json]
    stegno sanitize <file> <out>
    stegno strength <passphrase>
    stegno kdftime
    stegno split (--text <T> | --file <path>) --threshold <k> --shares <n>
    stegno combine <share> <share> ...            (shares look like `1:ab12…`)

NOTES:
    Covers can be any file: photo, audio, text, document, video, anything.
    `cover` reports which carrier a file gets and how much it holds.
    `compose` is the general form — one secret and one cover is a plain hide,
    several secrets share a cover (each password opens only its own, so one can
    be handed over as a decoy), several covers split the payload across them
    (all parts required), and any combination works at once.
    reveal takes every part of a split, and without --method auto-detects which
    method hid the data.
    --robust adds Reed-Solomon error correction so the payload survives light
    carrier damage (recompression, resize, scan). Level 1 (small) to 3 (most).
    --compress shrinks the secret before encryption to fit more in a cover.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    match cmd {
        "methods" => cmd_methods(),
        "doctor" => cmd_doctor(),
        "capacity" => cmd_capacity(&args[1..]),
        "plan" => cmd_plan(&args[1..]),
        "risk" => cmd_risk(&args[1..]),
        "hide" => cmd_hide(&args[1..]),
        "multi" => cmd_multi(&args[1..]),
        "compose" => cmd_compose(&args[1..]),
        "cover" => cmd_cover(&args[1..]),
        "reveal" => cmd_reveal(&args[1..]),
        "analyze" => cmd_analyze(&args[1..]),
        "bitplane" => cmd_bitplane(&args[1..]),
        "changemap" => cmd_changemap(&args[1..]),
        "scan" => cmd_scan(&args[1..]),
        "sanitize" => cmd_sanitize(&args[1..]),
        "strength" => cmd_strength(&args[1..]),
        "kdftime" => cmd_kdftime(),
        "split" => cmd_split(&args[1..]),
        "combine" => cmd_combine(&args[1..]),
        "help" | "-h" | "--help" | "" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

// --- flag parsing helpers -------------------------------------------------

/// Pull `--name <value>` out of args, returning the value if present.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Every value of a flag that may repeat (e.g. `--to a --to b`).
fn flag_all<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| a.as_str() == name)
        .filter_map(|(i, _)| args.get(i + 1))
        .map(String::as_str)
        .collect()
}

/// Boolean flags that take no value (so positional parsing skips only the flag).
const BOOL_FLAGS: &[&str] = &["--compress"];

/// Positional (non-flag, non-flag-value) arguments in order.
fn positionals(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            i += if BOOL_FLAGS.contains(&args[i].as_str()) { 1 } else { 2 };
        } else {
            out.push(args[i].as_str());
            i += 1;
        }
    }
    out
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))
}

fn write(path: &str, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("writing {path}: {e}"))
}

// --- commands -------------------------------------------------------------

fn cmd_methods() -> Result<(), String> {
    println!("{:<16} {:<8} {}", "ID", "MEDIA", "NAME");
    for m in list_methods() {
        println!("{:<16} {:<8} {}", m.id, m.media, m.display_name);
    }
    Ok(())
}

fn cmd_doctor() -> Result<(), String> {
    let results = run_self_test();
    let mut failed = 0;
    println!("{:<16} {:<8} {:<8} {:<12} {}", "METHOD", "MEDIA", "STATUS", "CAPACITY", "DETAIL");
    for r in &results {
        let status = if r.ok { "PASS" } else { failed += 1; "FAIL" };
        println!(
            "{:<16} {:<8} {:<8} {:<12} {}",
            r.method_id, r.media, status, r.usable_bytes, r.detail
        );
    }
    println!("\n{}/{} methods healthy", results.len() - failed, results.len());
    if failed > 0 {
        return Err(format!("{failed} method(s) failed self-test"));
    }
    Ok(())
}

fn cmd_capacity(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let (method, cover) = match p.as_slice() {
        [m, c] => (*m, *c),
        _ => return Err("usage: stegno capacity <method> <cover>".into()),
    };
    let bytes = capacity(method.to_string(), read(cover)?).map_err(|e| e.to_string())?;
    println!("{bytes} bytes usable with `{method}`");
    Ok(())
}

fn cmd_plan(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let (cover, payload) = match p.as_slice() {
        [c, n] => (*c, *n),
        _ => return Err("usage: stegno plan <cover> <payload-bytes>".into()),
    };
    let payload_len: u64 = payload.parse().map_err(|_| "payload-bytes must be a number")?;
    let recs = plan_embedding(read(cover)?, payload_len);
    if recs.is_empty() {
        return Err("no method can read this cover".into());
    }
    println!(
        "hiding {payload_len} bytes — {:<16} {:<8} {:<10} {:<7} {}",
        "METHOD", "FITS", "USABLE", "STEALTH", "NOTE"
    );
    for r in recs {
        let stealth = ["low", "medium", "high"][r.stealth_tier.min(2) as usize];
        println!(
            "                     {:<16} {:<8} {:<10} {:<7} {}",
            r.method_id,
            if r.fits { "yes" } else { "no" },
            r.usable_bytes,
            stealth,
            r.note
        );
    }
    Ok(())
}

fn cmd_risk(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let (method, cover, payload) = match p.as_slice() {
        [m, c, n] => (*m, *c, *n),
        _ => return Err("usage: stegno risk <method> <cover> <payload-bytes>".into()),
    };
    let payload_len: u64 = payload.parse().map_err(|_| "payload-bytes must be a number")?;
    let r = detectability(method.to_string(), read(cover)?, payload_len).map_err(|e| e.to_string())?;
    println!("method           : {}", r.method_id);
    println!("clean confidence : {:.3}", r.clean_confidence);
    println!("stego confidence : {:.3}", r.stego_confidence);
    println!("delta            : {:+.3}", r.delta);
    println!("PSNR             : {:.1} dB", r.psnr_db);
    println!("detectability    : {}", r.verdict.to_uppercase());
    Ok(())
}

/// A file's own name, for payloads that should keep their identity.
fn file_name_of(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("payload")
        .to_string()
}

/// Read a `Secret` from `--text` or `--file`. Shared by every command that
/// takes a payload, so a file is never second-class next to a message.
fn secret_from_flags(args: &[String]) -> Result<Secret, String> {
    if let Some(text) = flag(args, "--text") {
        return Ok(Secret::Text {
            text: text.to_string(),
        });
    }
    if let Some(path) = flag(args, "--file") {
        return Ok(Secret::File {
            name: file_name_of(path),
            bytes: read(path)?,
        });
    }
    Err("provide a secret with --text <T> or --file <path>".into())
}

/// Parse a `<pass>:<value>` pair, where the value may itself contain colons.
fn split_spec<'a>(spec: &'a str, flag_name: &str) -> Result<(&'a str, &'a str), String> {
    spec.split_once(':')
        .ok_or_else(|| format!("each {flag_name} must look like <pass>:<value>"))
}

/// Collect entries from repeated `--secret <pass>:<text>` and
/// `--secret-file <pass>:<path>` flags, so any entry can be text or a file.
fn entries_from_flags(args: &[String]) -> Result<Vec<Recipient>, String> {
    let mut entries = Vec::new();
    for spec in flag_all(args, "--secret") {
        let (pass, text) = split_spec(&spec, "--secret")?;
        entries.push(Recipient {
            secret: Secret::Text {
                text: text.to_string(),
            },
            passphrase: pass.to_string(),
        });
    }
    for spec in flag_all(args, "--secret-file") {
        let (pass, path) = split_spec(&spec, "--secret-file")?;
        entries.push(Recipient {
            secret: Secret::File {
                name: file_name_of(path),
                bytes: read(path)?,
            },
            passphrase: pass.to_string(),
        });
    }
    if entries.is_empty() {
        return Err("provide at least one --secret <pass>:<text> or --secret-file <pass>:<path>".into());
    }
    Ok(entries)
}

fn cmd_hide(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let (method, cover, out) = match p.as_slice() {
        [m, c, o] => (*m, *c, *o),
        _ => return Err("usage: stegno hide <method> <cover> <out> --pass P (--text T | --file F) [--robust N]".into()),
    };
    let pass = flag(args, "--pass").ok_or("missing --pass")?;
    let secret = secret_from_flags(args)?;

    let robustness: u8 = match flag(args, "--robust") {
        Some(level) => level.parse().map_err(|_| "--robust must be 1, 2, or 3")?,
        None => 0,
    };
    let compress = has_flag(args, "--compress");

    let cover_bytes = read(cover)?;
    let stego = embed_advanced(
        method.to_string(),
        cover_bytes,
        secret,
        pass.to_string(),
        robustness,
        compress,
    )
    .map_err(|e| e.to_string())?;

    write(out, &stego)?;
    let extras = match (robustness, compress) {
        (0, false) => String::new(),
        (r, c) => format!(
            " [{}{}]",
            if r > 0 { format!("robust {r}") } else { String::new() },
            if c { " +compress" } else { "" }
        ),
    };
    println!(
        "hid payload with `{method}`{extras} -> {out} ({} bytes)",
        stego.len()
    );
    Ok(())
}

fn cmd_multi(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let (cover, out) = match p.as_slice() {
        [c, o] => (*c, *o),
        _ => return Err("usage: stegno multi <cover> <out> --to <pass>:<message> ...".into()),
    };
    let mut recipients = Vec::new();
    for spec in flag_all(args, "--to") {
        let (pass, msg) = split_spec(&spec, "--to")?;
        recipients.push(Recipient {
            secret: Secret::Text {
                text: msg.to_string(),
            },
            passphrase: pass.to_string(),
        });
    }
    for spec in flag_all(args, "--to-file") {
        let (pass, path) = split_spec(&spec, "--to-file")?;
        recipients.push(Recipient {
            secret: Secret::File {
                name: file_name_of(path),
                bytes: read(path)?,
            },
            passphrase: pass.to_string(),
        });
    }
    if recipients.len() < 2 {
        return Err("provide at least two recipients (--to <pass>:<message> or --to-file <pass>:<path>)".into());
    }
    let n = recipients.len();
    let stego = embed_multi(read(cover)?, recipients).map_err(|e| e.to_string())?;
    write(out, &stego)?;
    println!("hid {n} secrets for {n} recipients -> {out} ({} bytes)", stego.len());
    Ok(())
}

/// The full composite primitive: any number of secrets across any number of
/// covers of any medium. This is the command-line twin of the apps' composer.
fn cmd_compose(args: &[String]) -> Result<(), String> {
    let covers = flag_all(args, "--cover");
    if covers.is_empty() {
        return Err("provide at least one --cover <path>".into());
    }
    let out_prefix = flag(args, "--out").ok_or("missing --out <prefix>")?;
    let entries = entries_from_flags(args)?;
    let robustness: u8 = match flag(args, "--robust") {
        Some(level) => level.parse().map_err(|_| "--robust must be 1, 2, or 3")?,
        None => 0,
    };
    let compress = has_flag(args, "--compress");

    let chunks: Vec<ByteChunk> = covers
        .iter()
        .map(|p| read(p).map(|bytes| ByteChunk { bytes }))
        .collect::<Result<_, _>>()?;
    let n_entries = entries.len();
    let stegos = embed_composite(chunks, entries, robustness, compress).map_err(|e| e.to_string())?;

    for (i, (chunk, cover_path)) in stegos.iter().zip(covers.iter()).enumerate() {
        // Name each output for the carrier it came from: an appended-region
        // carrier keeps its container (a PDF stays a PDF), an image becomes PNG.
        let info = cover_info(chunk.bytes.clone()).map_err(|e| e.to_string())?;
        let path = if info.preserves_container {
            let ext = std::path::Path::new(cover_path)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or(&info.extension)
                .to_string();
            part_path(out_prefix, i, stegos.len(), &ext)
        } else {
            part_path(out_prefix, i, stegos.len(), &info.extension)
        };
        write(&path, &chunk.bytes)?;
        println!("  {path} ({} bytes, {} carrier)", chunk.bytes.len(), info.kind);
    }
    println!(
        "composed {n_entries} secret(s) across {} cover(s){}",
        stegos.len(),
        if stegos.len() > 1 { " — all parts are required to rebuild" } else { "" }
    );
    Ok(())
}

/// `prefix.ext` for a single output, `prefix-1.ext` … when there are several.
fn part_path(prefix: &str, index: usize, total: usize, ext: &str) -> String {
    if total == 1 {
        format!("{prefix}.{ext}")
    } else {
        format!("{prefix}-{}.{ext}", index + 1)
    }
}

/// Report what the engine makes of a cover: its carrier and usable capacity.
fn cmd_cover(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let path = match p.as_slice() {
        [c] => *c,
        _ => return Err("usage: stegno cover <file>".into()),
    };
    let info = cover_info(read(path)?).map_err(|e| e.to_string())?;
    println!("carrier       : {}", info.kind);
    println!("container     : {}", info.format);
    println!("slots         : {}", info.slots);
    println!("capacity      : {} bytes", info.capacity_bytes);
    println!(
        "output        : {}",
        if info.preserves_container {
            "keeps this file's own container".to_string()
        } else {
            format!("re-encoded as .{}", info.extension)
        }
    );
    Ok(())
}

fn cmd_reveal(args: &[String]) -> Result<(), String> {
    let paths = positionals(args);
    if paths.is_empty() {
        return Err("usage: stegno reveal <stego> [<stego> ...] --pass P [--method M] [--out FILE]".into());
    }
    let pass = flag(args, "--pass").ok_or("missing --pass")?;

    // Several files means a composite split: every part is needed, and only the
    // composite reader knows how a frame was spread across them.
    if paths.len() > 1 {
        let chunks: Vec<ByteChunk> = paths
            .iter()
            .map(|p| read(p).map(|bytes| ByteChunk { bytes }))
            .collect::<Result<_, _>>()?;
        let revealed =
            extract_composite(chunks, pass.to_string()).map_err(|e| e.to_string())?;
        return report_revealed(args, String::new(), revealed);
    }

    let stego_bytes = read(paths[0])?;
    let (method_id, revealed) = match flag(args, "--method") {
        Some(m) => (
            m.to_string(),
            extract(m.to_string(), stego_bytes, pass.to_string()).map_err(|e| e.to_string())?,
        ),
        None => {
            // A single file may still be a one-cover composite (a decoy or a
            // multi-recipient hide), which `extract_auto` covers via its region
            // fallbacks — but try the composite reader too before giving up.
            let found =
                extract_auto(stego_bytes.clone(), pass.to_string()).map_err(|e| e.to_string())?;
            match found.revealed {
                Revealed::None => (
                    String::new(),
                    extract_composite(
                        vec![ByteChunk { bytes: stego_bytes }],
                        pass.to_string(),
                    )
                    .map_err(|e| e.to_string())?,
                ),
                revealed => (found.method_id, revealed),
            }
        }
    };
    report_revealed(args, method_id, revealed)
}

/// Print or save whatever an extraction produced.
fn report_revealed(args: &[String], method_id: String, revealed: Revealed) -> Result<(), String> {

    match revealed {
        Revealed::None => Err("no hidden data found".into()),
        Revealed::Text { text } => {
            if !method_id.is_empty() {
                eprintln!("(method: {method_id})");
            }
            println!("{text}");
            Ok(())
        }
        Revealed::File { name, bytes } => {
            let out = flag(args, "--out").unwrap_or(&name).to_string();
            write(&out, &bytes)?;
            eprintln!("recovered file `{name}` -> {out} ({} bytes)", bytes.len());
            Ok(())
        }
        Revealed::Files { files } => {
            for f in files {
                write(&f.name, &f.bytes)?;
                eprintln!("recovered `{}` ({} bytes)", f.name, f.bytes.len());
            }
            Ok(())
        }
    }
}

fn cmd_analyze(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let file = match p.as_slice() {
        [f] => *f,
        _ => return Err("usage: stegno analyze <file>".into()),
    };
    let data = read(file)?;

    // Structural (all formats).
    let s = scan_structure(data.clone());
    println!("format: {}", s.format);
    println!("structural: {}", if s.suspicious { "SUSPICIOUS" } else { "clean" });
    for f in &s.findings {
        let sev = ["info", "note", "STRONG"][f.severity.min(2) as usize];
        println!("  [{sev}] {}: {}", f.kind, f.detail);
    }

    // Pixel statistics (image formats only).
    if s.format == "png" || s.format == "jpeg" || s.format == "gif" {
        match detect_lsb(data.clone()) {
            Ok(d) => {
                println!("pixel LSB statistics:");
                println!("  chi-square p       : {:.3}", d.chi_square_p);
                println!("  RS regularity gap  : {:.3}", d.rs_regularity_gap);
                println!("  sample-pair rate   : {:.3}", d.sample_pair_rate);
                println!("  ML confidence      : {:.3}", d.ml_confidence);
            }
            Err(e) => eprintln!("  (pixel analysis skipped: {e})"),
        }
    }

    // Method fingerprint — which technique most likely produced this file.
    println!("likely method(s):");
    for guess in fingerprint(data) {
        println!("  {:>4.0}%  {}  ({})", guess.confidence * 100.0, guess.label, guess.reason);
    }
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "bad hex digit".to_string()))
        .collect()
}

fn cmd_split(args: &[String]) -> Result<(), String> {
    // Split the *typed* secret, so a shared file recombines under its own name
    // instead of as anonymous bytes the recipient has to guess at.
    let secret = secret_from_flags(args)?;
    let k: u8 = flag(args, "--threshold")
        .ok_or("missing --threshold")?
        .parse()
        .map_err(|_| "--threshold must be a number")?;
    let n: u8 = flag(args, "--shares")
        .ok_or("missing --shares")?
        .parse()
        .map_err(|_| "--shares must be a number")?;
    let shares = sss_split_secret(secret, k, n).map_err(|e| e.to_string())?;
    eprintln!("any {k} of these {n} shares reconstruct the secret:");
    for s in shares {
        println!("{}:{}", s.x, to_hex(&s.y));
    }
    Ok(())
}

fn cmd_combine(args: &[String]) -> Result<(), String> {
    let parts = positionals(args);
    if parts.is_empty() {
        return Err("usage: stegno combine <share> <share> ...".into());
    }
    let mut shares = Vec::with_capacity(parts.len());
    for p in parts {
        let (x, y) = p.split_once(':').ok_or("share must look like `x:hex`")?;
        let x: u8 = x.parse().map_err(|_| "bad share x-coordinate")?;
        shares.push(SecretShare { x, y: from_hex(y)? });
    }
    let revealed = sss_combine_secret(shares).map_err(|e| e.to_string())?;
    report_revealed(args, String::new(), revealed)
}

/// Recursively collect file paths under `dir`.
fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.is_file() {
                out.push(path);
            }
        }
    }
}

fn cmd_scan(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let dir = match p.as_slice() {
        [d] => *d,
        _ => return Err("usage: stegno scan <dir> [--threshold <0-100>] [--json]".into()),
    };
    let threshold: f64 = flag(args, "--threshold")
        .map(|t| t.parse::<f64>().unwrap_or(50.0))
        .unwrap_or(50.0)
        / 100.0;
    let json = has_flag(args, "--json");

    let mut files = Vec::new();
    walk(std::path::Path::new(dir), &mut files);

    // (path, confidence, label) for every file whose top guess clears threshold.
    let mut hits: Vec<(String, f64, String)> = Vec::new();
    let mut scanned = 0usize;
    for path in &files {
        let Ok(bytes) = std::fs::read(path) else { continue };
        scanned += 1;
        let guesses = fingerprint(bytes);
        if let Some(top) = guesses.first() {
            if top.label != "none" && top.confidence >= threshold {
                hits.push((path.display().to_string(), top.confidence, top.label.clone()));
            }
        }
    }
    hits.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    if json {
        // Minimal hand-rolled JSON (no serde dependency in the binary).
        print!("[");
        for (i, (path, conf, label)) in hits.iter().enumerate() {
            if i > 0 {
                print!(",");
            }
            print!(
                "{{\"file\":\"{}\",\"confidence\":{:.3},\"method\":\"{}\"}}",
                json_escape(path),
                conf,
                json_escape(label)
            );
        }
        println!("]");
    } else {
        eprintln!(
            "scanned {scanned} files, {} flagged at >= {:.0}% confidence:",
            hits.len(),
            threshold * 100.0
        );
        for (path, conf, label) in &hits {
            println!("  {:>4.0}%  {}  [{}]", conf * 100.0, path, label);
        }
    }
    Ok(())
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn cmd_bitplane(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let (image, out) = match p.as_slice() {
        [i, o] => (*i, *o),
        _ => return Err("usage: stegno bitplane <image> <out> [--channel 0-2] [--plane 0-7]".into()),
    };
    let channel: u8 = flag(args, "--channel").map(|c| c.parse().unwrap_or(0)).unwrap_or(0);
    let plane: u8 = flag(args, "--plane").map(|c| c.parse().unwrap_or(0)).unwrap_or(0);
    let png = bit_plane(read(image)?, channel, plane).map_err(|e| e.to_string())?;
    write(out, &png)?;
    println!("bit-plane (channel {channel}, plane {plane}) -> {out}");
    Ok(())
}

fn cmd_changemap(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let (cover, stego, out) = match p.as_slice() {
        [c, s, o] => (*c, *s, *o),
        _ => return Err("usage: stegno changemap <cover> <stego> <out>".into()),
    };
    let png = change_map(read(cover)?, read(stego)?).map_err(|e| e.to_string())?;
    write(out, &png)?;
    println!("change-map -> {out}");
    Ok(())
}

fn cmd_sanitize(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let (file, out) = match p.as_slice() {
        [f, o] => (*f, *o),
        _ => return Err("usage: stegno sanitize <file> <out>".into()),
    };
    let r = sanitize(read(file)?);
    write(out, &r.cleaned)?;
    if r.changed {
        eprintln!("sanitized ({}) -> {out}:", r.format);
        for a in &r.actions {
            eprintln!("  - {a}");
        }
    } else {
        eprintln!("no hidden-data channels found; copied unchanged -> {out}");
    }
    Ok(())
}

fn cmd_kdftime() -> Result<(), String> {
    let b = benchmark_kdf();
    println!("Argon2id: {} KiB, {} iterations", b.memory_kib, b.iterations);
    println!("time    : {:.0} ms/derivation", b.millis);
    println!("verdict : {}", b.verdict.to_uppercase());
    println!("meaning : {}", b.explanation);
    Ok(())
}

fn cmd_strength(args: &[String]) -> Result<(), String> {
    let p = positionals(args);
    let pass = match p.as_slice() {
        [s] => *s,
        _ => return Err("usage: stegno strength <passphrase>".into()),
    };
    let s = estimate_passphrase_strength(pass.to_string());
    let bar = "#".repeat(s.score as usize) + &"-".repeat(4 - s.score as usize);
    println!("score      : {}/4 [{bar}]", s.score);
    println!("entropy    : {:.1} bits", s.entropy_bits);
    println!("crack time : {}", s.crack_time_display);
    if !s.warning.is_empty() {
        println!("warning    : {}", s.warning);
    }
    for tip in &s.suggestions {
        println!("  - {tip}");
    }
    Ok(())
}
