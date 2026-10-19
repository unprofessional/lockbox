//! Code generation and `otpauth://` parsing (BRIEF §7). Seeds stay in Rust;
//! the webview only ever gets rendered codes and metadata (BRIEF §5).

use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Builder, Secret};
use zeroize::Zeroizing;

pub const DIGITS: std::ops::RangeInclusive<u32> = 6..=8;
pub const PERIOD: std::ops::RangeInclusive<u32> = 10..=300;
/// 80 bits. RFC 4226 asks for 128, but many real services still issue 80-bit seeds.
pub const MIN_SECRET_BYTES: usize = 10;
const MAX_TEXT_CHARS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Totp,
    Hotp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algo {
    SHA1,
    SHA256,
    SHA512,
}

impl Algo {
    fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Ok(Self::SHA1),
            "SHA256" => Ok(Self::SHA256),
            "SHA512" => Ok(Self::SHA512),
            _ => Err(format!("unsupported algorithm '{s}' (use SHA1, SHA256 or SHA512)")),
        }
    }

    fn to_totp(self) -> Algorithm {
        match self {
            Self::SHA1 => Algorithm::SHA1,
            Self::SHA256 => Algorithm::SHA256,
            Self::SHA512 => Algorithm::SHA512,
        }
    }
}

/// A validated account ready to go into the vault. `seed_b32` is normalized
/// (uppercase, no spaces/dashes/padding).
pub struct NewEntry {
    pub issuer: String,
    pub account: String,
    pub seed_b32: Zeroizing<String>,
    pub digits: u32,
    pub period: u32,
    pub algorithm: Algo,
    pub kind: Kind,
    pub counter: Option<u64>,
}

/// The manual-entry form as typed by the user. The seed travels webview →
/// Rust once, here, and never back.
#[derive(Deserialize)]
pub struct ManualForm {
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub account: String,
    pub seed: String,
    pub digits: Option<u32>,
    pub period: Option<u32>,
    pub algorithm: Option<String>,
    pub kind: Option<Kind>,
    pub counter: Option<u64>,
}

pub fn from_manual(form: ManualForm) -> Result<NewEntry, String> {
    let seed = Zeroizing::new(form.seed);
    let kind = form.kind.unwrap_or(Kind::Totp);
    validate(NewEntry {
        issuer: form.issuer.trim().into(),
        account: form.account.trim().into(),
        seed_b32: normalize_seed(&seed),
        digits: form.digits.unwrap_or(6),
        period: form.period.unwrap_or(30),
        algorithm: form.algorithm.as_deref().map(Algo::parse).transpose()?.unwrap_or(Algo::SHA1),
        kind,
        counter: (kind == Kind::Hotp).then(|| form.counter.unwrap_or(0)),
    })
}

/// Parses `otpauth://totp/Issuer:account?secret=...&issuer=...` (and hotp).
/// Lenient about case, whitespace and missing optional params; strict about
/// anything that would produce wrong codes.
pub fn parse_uri(uri: &str) -> Result<NewEntry, String> {
    let uri = Zeroizing::new(uri.trim().to_string());
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("otpauth-migration://") {
        return Err("Google Authenticator export links aren't supported yet (planned for bulk import)."
            .into());
    }
    let rest = lower
        .strip_prefix("otpauth://")
        .map(|_| &uri["otpauth://".len()..])
        .ok_or("not an otpauth:// link")?;

    let (kind_str, rest) = rest.split_once('/').ok_or("missing type (totp or hotp)")?;
    let kind = match kind_str.to_ascii_lowercase().as_str() {
        "totp" => Kind::Totp,
        "hotp" => Kind::Hotp,
        other => return Err(format!("unsupported type '{other}' (expected totp or hotp)")),
    };
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = percent_decode(label, false)?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };

    let mut secret = None;
    let mut issuer = None;
    let mut digits = None;
    let mut period = None;
    let mut algorithm = None;
    let mut counter = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = Zeroizing::new(percent_decode(v, true)?);
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(v),
            "issuer" => issuer = Some(v.trim().to_string()),
            "digits" => digits = Some(parse_num::<u32>("digits", &v)?),
            "period" => period = Some(parse_num::<u32>("period", &v)?),
            "algorithm" => algorithm = Some(Algo::parse(&v)?),
            "counter" => counter = Some(parse_num::<u64>("counter", &v)?),
            _ => {} // image=, color= and other vendor extras
        }
    }
    let secret = secret.ok_or("link has no secret")?;

    validate(NewEntry {
        // The issuer parameter wins over the label prefix when both exist.
        issuer: issuer.filter(|s| !s.is_empty()).unwrap_or(label_issuer),
        account,
        seed_b32: normalize_seed(&secret),
        digits: digits.unwrap_or(6),
        period: period.unwrap_or(30),
        algorithm: algorithm.unwrap_or(Algo::SHA1),
        kind,
        counter: (kind == Kind::Hotp).then(|| counter.unwrap_or(0)),
    })
}

fn parse_num<T: std::str::FromStr>(name: &str, v: &str) -> Result<T, String> {
    v.trim()
        .parse()
        .map_err(|_| format!("{name} must be a whole number (got '{v}')"))
}

pub fn normalize_seed(seed: &str) -> Zeroizing<String> {
    Zeroizing::new(
        seed.chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    )
}

fn decode_seed(seed_b32: &str) -> Result<Secret, String> {
    Secret::try_from_base32(seed_b32).map_err(|_| "secret isn't valid base32".to_string())
}

fn validate(e: NewEntry) -> Result<NewEntry, String> {
    if e.issuer.is_empty() && e.account.is_empty() {
        return Err("give at least an issuer or an account name".into());
    }
    if e.issuer.chars().count() > MAX_TEXT_CHARS || e.account.chars().count() > MAX_TEXT_CHARS {
        return Err(format!("issuer and account must be at most {MAX_TEXT_CHARS} characters"));
    }
    if !DIGITS.contains(&e.digits) {
        return Err(format!("digits must be {} to {}", DIGITS.start(), DIGITS.end()));
    }
    if e.kind == Kind::Totp && !PERIOD.contains(&e.period) {
        return Err(format!(
            "period must be {} to {} seconds",
            PERIOD.start(),
            PERIOD.end()
        ));
    }
    if e.seed_b32.is_empty() {
        return Err("secret is empty".into());
    }
    if decode_seed(&e.seed_b32)?.len() < MIN_SECRET_BYTES {
        return Err(format!(
            "secret is too short (needs at least {} base32 characters)",
            MIN_SECRET_BYTES * 8 / 5
        ));
    }
    Ok(e)
}

/// The code for `moving_factor`: unix time for TOTP, the counter for HOTP.
pub fn code(
    seed_b32: &str,
    algorithm: Algo,
    digits: u32,
    kind: Kind,
    period: u32,
    moving_factor: u64,
) -> Result<String, String> {
    // HOTP is TOTP with a 1-second step and the counter as the "time".
    let step = match kind {
        Kind::Totp => u64::from(period),
        Kind::Hotp => 1,
    };
    let totp = Builder::new()
        .with_algorithm(algorithm.to_totp())
        .with_digits(digits as u8)
        .with_step_duration(step)
        .with_secret(decode_seed(seed_b32)?)
        .build_noncompliant();
    Ok(totp.generate(moving_factor).to_string())
}

pub fn seconds_remaining(period: u32, now: u64) -> u64 {
    let p = u64::from(period);
    p - (now % p)
}

fn percent_decode(s: &str, plus_is_space: bool) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or("link has a broken %-escape")?;
                out.push(hex);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out.to_vec()).map_err(|_| "link isn't valid UTF-8".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B seeds: "12345678901234567890" repeated to the hash size.
    const SEED_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const SEED_SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const SEED_SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    #[test]
    fn rfc6238_test_vectors() {
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, sha1, sha256, sha512) in cases {
            assert_eq!(code(SEED_SHA1, Algo::SHA1, 8, Kind::Totp, 30, t).unwrap(), sha1, "SHA1 t={t}");
            assert_eq!(code(SEED_SHA256, Algo::SHA256, 8, Kind::Totp, 30, t).unwrap(), sha256, "SHA256 t={t}");
            assert_eq!(code(SEED_SHA512, Algo::SHA512, 8, Kind::Totp, 30, t).unwrap(), sha512, "SHA512 t={t}");
        }
    }

    #[test]
    fn rfc4226_hotp_test_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(
                code(SEED_SHA1, Algo::SHA1, 6, Kind::Hotp, 30, counter as u64).unwrap(),
                *want,
                "counter {counter}"
            );
        }
    }

    #[test]
    fn six_digit_codes_keep_leading_zeros() {
        // RFC 6238 SHA1 at t=1111111109 is 07081804; the 6-digit form is 081804.
        assert_eq!(code(SEED_SHA1, Algo::SHA1, 6, Kind::Totp, 30, 1111111109).unwrap(), "081804");
    }

    #[test]
    fn seconds_remaining_counts_down() {
        assert_eq!(seconds_remaining(30, 60), 30);
        assert_eq!(seconds_remaining(30, 61), 29);
        assert_eq!(seconds_remaining(30, 89), 1);
    }

    #[test]
    fn parses_typical_uri() {
        let e = parse_uri(
            "otpauth://totp/GitHub:mads%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=GitHub",
        )
        .unwrap();
        assert_eq!(e.issuer, "GitHub");
        assert_eq!(e.account, "mads@example.com");
        assert_eq!(*e.seed_b32, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
        assert_eq!((e.digits, e.period, e.algorithm, e.kind), (6, 30, Algo::SHA1, Kind::Totp));
        assert_eq!(e.counter, None);
    }

    #[test]
    fn issuer_param_wins_and_spaces_decode() {
        let e = parse_uri(
            "otpauth://totp/Old%20Name:  me  ?secret=jbsw y3dp-ehpk3pxp====&issuer=New+Name&digits=8&period=60&algorithm=sha256",
        )
        .unwrap();
        assert_eq!(e.issuer, "New Name");
        assert_eq!(e.account, "me");
        assert_eq!(*e.seed_b32, "JBSWY3DPEHPK3PXP");
        assert_eq!((e.digits, e.period, e.algorithm), (8, 60, Algo::SHA256));
    }

    #[test]
    fn label_without_issuer_and_odd_casing() {
        let e = parse_uri("  OTPAUTH://TOTP/just-an-account?SECRET=JBSWY3DPEHPK3PXP&Image=x  ").unwrap();
        assert_eq!(e.issuer, "");
        assert_eq!(e.account, "just-an-account");
    }

    #[test]
    fn colon_in_account_keeps_the_rest() {
        let e = parse_uri("otpauth://totp/Acme:user:with:colons?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(e.issuer, "Acme");
        assert_eq!(e.account, "user:with:colons");
    }

    #[test]
    fn hotp_uri_keeps_counter() {
        let e = parse_uri("otpauth://hotp/Acme:me?secret=JBSWY3DPEHPK3PXP&counter=42").unwrap();
        assert_eq!(e.kind, Kind::Hotp);
        assert_eq!(e.counter, Some(42));
        let e = parse_uri("otpauth://hotp/Acme:me?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(e.counter, Some(0));
    }

    #[test]
    fn rejects_bad_uris() {
        let err = |u: &str| parse_uri(u).err().unwrap_or_else(|| panic!("accepted {u}"));
        assert!(err("https://example.com").contains("otpauth"));
        assert!(err("otpauth-migration://offline?data=abc").contains("Google Authenticator"));
        assert!(err("otpauth://steam/x?secret=JBSWY3DPEHPK3PXP").contains("unsupported type"));
        assert!(err("otpauth://totp/x").contains("no secret"));
        assert!(err("otpauth://totp/x?secret=not*base32!").contains("base32"));
        assert!(err("otpauth://totp/x?secret=JBSWY3DP").contains("too short"));
        assert!(err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10").contains("digits"));
        assert!(err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=six").contains("whole number"));
        assert!(err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0").contains("period"));
        assert!(err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5").contains("algorithm"));
        assert!(err("otpauth://totp/?secret=JBSWY3DPEHPK3PXP").contains("issuer or an account"));
        assert!(err("otpauth://totp/a%2?secret=JBSWY3DPEHPK3PXP").contains("%-escape"));
    }

    #[test]
    fn manual_form_defaults_and_validation() {
        let form = |seed: &str| ManualForm {
            issuer: " Acme ".into(),
            account: "".into(),
            seed: seed.into(),
            digits: None,
            period: None,
            algorithm: None,
            kind: None,
            counter: None,
        };
        let e = from_manual(form("jbsw y3dp ehpk 3pxp")).unwrap();
        assert_eq!(e.issuer, "Acme");
        assert_eq!(*e.seed_b32, "JBSWY3DPEHPK3PXP");
        assert_eq!((e.digits, e.period, e.algorithm, e.kind), (6, 30, Algo::SHA1, Kind::Totp));
        assert!(from_manual(form("")).is_err());
        assert!(from_manual(form("0189")).is_err());
    }
}
