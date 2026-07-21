//! Offline passphrase-strength estimation.
//!
//! Argon2id makes brute force expensive but cannot rescue a weak passphrase, so
//! the apps warn *before* a weak secret is used to seal data. This is a compact,
//! fully offline entropy estimator (no bundled dictionary, no network): it scores
//! the character-class space, then discounts for the cheap patterns real users
//! reach for — a handful of very common passwords, single character classes,
//! keyboard/alphanumeric runs, and repetition.
//!
//! It is deliberately conservative: it estimates an *upper bound* on strength and
//! discounts toward realism, so it never over-promises secrecy.

/// A strength estimate surfaced to the UI.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PassphraseStrength {
    /// 0 (very weak) … 4 (very strong).
    pub score: u8,
    /// Estimated guessing entropy in bits, after pattern discounts.
    pub entropy_bits: f64,
    /// Human-readable offline crack-time estimate at 10¹⁰ guesses/second.
    pub crack_time_display: String,
    /// The single most important problem, or empty if none.
    pub warning: String,
    /// Concrete, ordered suggestions to improve the passphrase.
    pub suggestions: Vec<String>,
}

/// A tiny, embedded set of the most-abused passwords. Not a substitute for a
/// full breach list — just enough to hard-zero the obvious ones offline.
const COMMON: &[&str] = &[
    "password", "123456", "123456789", "12345678", "12345", "qwerty", "abc123",
    "password1", "111111", "123123", "admin", "letmein", "welcome", "monkey",
    "iloveyou", "dragon", "sunshine", "princess", "football", "qwerty123",
    "1q2w3e4r", "000000", "passw0rd", "trustno1", "changeme", "secret",
];

fn char_classes(pw: &str) -> (bool, bool, bool, bool, bool) {
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut symbol = false;
    let mut space = false;
    for c in pw.chars() {
        if c.is_ascii_lowercase() {
            lower = true;
        } else if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else if c == ' ' {
            space = true;
        } else {
            symbol = true;
        }
    }
    (lower, upper, digit, symbol, space)
}

fn pool_size(pw: &str) -> f64 {
    let (lower, upper, digit, symbol, space) = char_classes(pw);
    let mut pool = 0f64;
    if lower {
        pool += 26.0;
    }
    if upper {
        pool += 26.0;
    }
    if digit {
        pool += 10.0;
    }
    if symbol {
        pool += 33.0; // printable ASCII punctuation
    }
    if space {
        pool += 1.0;
    }
    // Any non-ASCII characters widen the pool considerably.
    if pw.chars().any(|c| !c.is_ascii()) {
        pool += 100.0;
    }
    pool.max(1.0)
}

/// Count characters that are part of a monotonic run of length ≥ 3 (e.g. `abc`,
/// `123`, `zyx`), which add little real entropy.
fn sequential_run_penalty(pw: &str) -> f64 {
    let bytes: Vec<char> = pw.chars().collect();
    if bytes.len() < 3 {
        return 0.0;
    }
    let mut in_run = 0usize;
    for w in bytes.windows(3) {
        let (a, b, c) = (w[0] as i32, w[1] as i32, w[2] as i32);
        if (b - a == 1 && c - b == 1) || (a - b == 1 && b - c == 1) {
            in_run += 1;
        }
    }
    in_run as f64
}

/// Fraction of characters that are immediate repeats (`aaaa`, `1111`).
fn repeat_penalty(pw: &str) -> f64 {
    let chars: Vec<char> = pw.chars().collect();
    if chars.len() < 2 {
        return 0.0;
    }
    let repeats = chars.windows(2).filter(|w| w[0] == w[1]).count();
    repeats as f64
}

fn crack_time_display(entropy_bits: f64) -> String {
    // Average guesses to hit = 2^(bits-1); attacker at 1e10 guesses/sec.
    let guesses = 2f64.powf((entropy_bits - 1.0).max(0.0));
    let seconds = guesses / 1e10;
    const MINUTE: f64 = 60.0;
    const HOUR: f64 = 3600.0;
    const DAY: f64 = 86_400.0;
    const YEAR: f64 = 31_557_600.0;
    if seconds < 1.0 {
        "instant".to_string()
    } else if seconds < MINUTE {
        format!("{:.0} seconds", seconds)
    } else if seconds < HOUR {
        format!("{:.0} minutes", seconds / MINUTE)
    } else if seconds < DAY {
        format!("{:.0} hours", seconds / HOUR)
    } else if seconds < YEAR {
        format!("{:.0} days", seconds / DAY)
    } else if seconds < YEAR * 1000.0 {
        format!("{:.0} years", seconds / YEAR)
    } else if seconds < YEAR * 1e9 {
        format!("{:.0} thousand years", seconds / (YEAR * 1000.0))
    } else {
        "centuries".to_string()
    }
}

/// Estimate the strength of `passphrase`, fully offline.
#[uniffi::export]
pub fn estimate_passphrase_strength(passphrase: String) -> PassphraseStrength {
    let pw = passphrase;
    let len = pw.chars().count();

    // Hard zero for empty or known-common secrets.
    let lowered = pw.to_lowercase();
    let is_common = COMMON.contains(&lowered.as_str())
        || COMMON.iter().any(|c| lowered == format!("{c}!") || lowered == format!("{c}1"));

    if len == 0 {
        return PassphraseStrength {
            score: 0,
            entropy_bits: 0.0,
            crack_time_display: "instant".into(),
            warning: "No passphrase entered.".into(),
            suggestions: vec!["Use at least a 4-word phrase or 12+ mixed characters.".into()],
        };
    }

    let pool = pool_size(&pw);
    let base_bits = len as f64 * pool.log2();

    // Discounts (in bits) for cheap structure.
    let seq = sequential_run_penalty(&pw);
    let rep = repeat_penalty(&pw);
    let per_char = pool.log2();
    let mut bits = base_bits - (seq + rep) * per_char * 0.75;

    let (lower, upper, digit, symbol, _space) = char_classes(&pw);
    let classes = [lower, upper, digit, symbol].iter().filter(|&&b| b).count();
    if classes <= 1 {
        bits *= 0.65; // single character class is much weaker than its size implies
    }

    if is_common {
        bits = bits.min(8.0);
    }
    bits = bits.max(0.0);

    let score = match bits {
        b if b < 28.0 => 0,
        b if b < 40.0 => 1,
        b if b < 56.0 => 2,
        b if b < 72.0 => 3,
        _ => 4,
    };

    // Warning + suggestions.
    let mut warning = String::new();
    let mut suggestions = Vec::new();
    if is_common {
        warning = "This is one of the most common passwords in the world.".into();
    } else if len < 8 {
        warning = "Too short to resist offline guessing.".into();
    } else if classes <= 1 {
        warning = "Uses only one kind of character.".into();
    } else if rep as usize * 2 >= len && len > 0 {
        warning = "Mostly repeated characters.".into();
    } else if seq > 0.0 {
        warning = "Contains an easy-to-guess sequence.".into();
    }

    if len < 12 {
        suggestions.push("Make it longer — aim for 12+ characters or 4+ words.".into());
    }
    if !upper || !lower {
        suggestions.push("Mix upper- and lower-case letters.".into());
    }
    if !digit {
        suggestions.push("Add digits.".into());
    }
    if !symbol {
        suggestions.push("Add a symbol or two.".into());
    }
    if seq > 0.0 || rep > 0.0 {
        suggestions.push("Avoid runs and repeats like `abc`, `111`.".into());
    }
    if suggestions.is_empty() && score >= 4 {
        suggestions.push("Strong. A passphrase of unrelated words is easy to remember and strong.".into());
    }

    PassphraseStrength {
        score,
        entropy_bits: (bits * 10.0).round() / 10.0,
        crack_time_display: crack_time_display(bits),
        warning,
        suggestions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        let s = estimate_passphrase_strength(String::new());
        assert_eq!(s.score, 0);
        assert_eq!(s.entropy_bits, 0.0);
    }

    #[test]
    fn common_password_is_weak() {
        let s = estimate_passphrase_strength("password".into());
        assert_eq!(s.score, 0);
        assert!(s.warning.to_lowercase().contains("common"));
    }

    #[test]
    fn short_single_class_is_weak() {
        let s = estimate_passphrase_strength("abcdef".into());
        assert!(s.score <= 1, "score was {}", s.score);
    }

    #[test]
    fn long_mixed_phrase_is_strong() {
        let s = estimate_passphrase_strength("Tr0ub4dour&3xplori^ng-Whales".into());
        assert!(s.score >= 3, "score was {} bits {}", s.score, s.entropy_bits);
        assert!(s.entropy_bits > 56.0);
    }

    #[test]
    fn monotonic_score_with_length() {
        let a = estimate_passphrase_strength("aA1!".into()).entropy_bits;
        let b = estimate_passphrase_strength("aA1!aA1!aA1!".into()).entropy_bits;
        assert!(b > a);
    }

    #[test]
    fn sequences_are_penalized() {
        let plain = estimate_passphrase_strength("Xq7!Kp2@Ldz".into()).entropy_bits;
        let seq = estimate_passphrase_strength("abcdefghijk".into()).entropy_bits;
        assert!(plain > seq);
    }
}
