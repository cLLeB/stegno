//! Optional ffmpeg bridge for frame-level video embedding.
//!
//! The engine embeds into video frames through lossless YUV4MPEG2 (see
//! `stegno_core::video`). Everyday clips are H.264/HEVC/VP9 in MP4, MKV or WebM,
//! so this module transcodes into and back out of y4m using a **system** ffmpeg.
//!
//! Desktop only, and deliberately optional:
//!
//! * The browser PWA and the Android app cannot spawn processes, and bundling a
//!   codec would bloat an offline build for something a lossy re-encode can
//!   never preserve anyway — AES-GCM authenticates the payload, so one flipped
//!   bit fails the tag.
//! * Without ffmpeg installed, compressed video still works as a cover via the
//!   appended-region carrier. Only frame-level embedding needs this.
//!
//! Re-encoding therefore targets **FFV1**, a mathematically lossless codec, in
//! Matroska. Anything lossy would destroy the payload on the way out.
//!
//! ffmpeg is invoked with an explicit argument vector and never through a shell,
//! so paths containing spaces, quotes or shell metacharacters are passed through
//! literally rather than interpreted.

use serde::Serialize;
use std::io::Write;
use std::process::{Command, Stdio};

/// Whether a usable ffmpeg is present, and which one.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FfmpegStatus {
    pub available: bool,
    /// First line of `ffmpeg -version`, or the reason it is unusable.
    pub detail: String,
}

/// An ffmpeg invocation that won't flash a console window on Windows.
#[cfg(windows)]
fn ffmpeg() -> Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut cmd = Command::new("ffmpeg");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

#[cfg(not(windows))]
fn ffmpeg() -> Command {
    Command::new("ffmpeg")
}

#[tauri::command]
pub fn ffmpeg_status() -> FfmpegStatus {
    let out = ffmpeg().arg("-version").stdin(Stdio::null()).output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            FfmpegStatus {
                available: true,
                detail: text.lines().next().unwrap_or("ffmpeg").to_string(),
            }
        }
        Ok(o) => FfmpegStatus {
            available: false,
            detail: format!("ffmpeg exited with {}", o.status),
        },
        Err(e) => FfmpegStatus {
            available: false,
            detail: format!("ffmpeg not found on PATH ({e})"),
        },
    }
}

/// Fail with ffmpeg's own diagnostics rather than a bare exit code — its stderr
/// is what actually explains an unsupported stream or a missing codec.
fn ffmpeg_error(stage: &str, stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let tail: Vec<&str> = text.lines().rev().take(4).collect();
    let tail: Vec<&str> = tail.into_iter().rev().collect();
    format!("ffmpeg failed to {stage}: {}", tail.join(" / "))
}

/// Decode a video file to lossless 8-bit 4:2:0 y4m the engine can carry.
///
/// The result is raw video and can be very large — roughly `width × height ×
/// 1.5` bytes per frame — which is why callers should keep clips short.
#[tauri::command]
pub fn video_to_y4m(path: String) -> Result<Vec<u8>, String> {
    let out = ffmpeg()
        .args([
            "-v", "error",
            "-nostdin",
            "-i", &path,
            "-an", // audio is carried across separately on the way back
            "-pix_fmt", "yuv420p",
            "-f", "yuv4mpegpipe",
            "-",
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run ffmpeg: {e}"))?;
    if !out.status.success() {
        return Err(ffmpeg_error("decode that video", &out.stderr));
    }
    if out.stdout.is_empty() {
        return Err("ffmpeg produced no video frames — is that file a video?".into());
    }
    Ok(out.stdout)
}

/// Re-encode carried y4m frames to lossless FFV1 in Matroska, restoring the
/// original file's audio track if it had one.
///
/// FFV1 is mandatory here: the payload lives in the luma LSBs, so any lossy
/// codec would discard it. The output is correspondingly large.
#[tauri::command]
pub fn y4m_to_video(y4m: Vec<u8>, original_path: String, out_path: String) -> Result<(), String> {
    let mut child = ffmpeg()
        .args([
            "-v", "error",
            "-nostdin",
            "-y",
            "-f", "yuv4mpegpipe",
            "-i", "-",            // carried frames on stdin
            "-i", &original_path, // only for its audio
            "-map", "0:v:0",
            "-map", "1:a?", // '?' so a silent clip isn't an error
            "-c:v", "ffv1",
            "-level", "3",
            "-c:a", "copy",
            &out_path,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run ffmpeg: {e}"))?;

    // Write the frames on a worker: a clip large enough to fill the pipe buffer
    // would deadlock if we wrote and waited on the same thread.
    let mut stdin = child.stdin.take().ok_or("ffmpeg stdin unavailable")?;
    let writer = std::thread::spawn(move || stdin.write_all(&y4m));

    let out = child
        .wait_with_output()
        .map_err(|e| format!("ffmpeg did not finish: {e}"))?;
    let write_result = writer.join().map_err(|_| "frame writer panicked")?;

    if !out.status.success() {
        return Err(ffmpeg_error("re-encode that video", &out.stderr));
    }
    // A broken pipe here means ffmpeg quit early; its stderr above is the real
    // explanation, so only report the write error when ffmpeg claimed success.
    write_result.map_err(|e| format!("could not send frames to ffmpeg: {e}"))?;
    Ok(())
}
