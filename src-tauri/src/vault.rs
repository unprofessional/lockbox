//! Encrypted vault (BRIEF §6).
//!
//! Key hierarchy, designed so Touch ID (§6.3) slots in without a migration:
//!
//!   master password --argon2id--> KEK --wraps--> VK --encrypts--> payload
//!
//! VK is a random 256-bit vault key. Today only the password-derived KEK
//! wraps it (`key_wrap`); a Keychain-held wrap can be added beside it later.
//! Both layers are AES-256-GCM with a fresh 96-bit random nonce per seal.

use aes_gcm::aead::{Aead, Generate, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const FORMAT_VERSION: u32 = 1;
pub const MIN_PASSWORD_CHARS: usize = 8;

const KDF_ALGO: &str = "argon2id";
const CIPHER_ALGO: &str = "aes-256-gcm";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;
// Domain-separate the two GCM layers so one ciphertext can't stand in for the other.
const AAD_KEY_WRAP: &[u8] = b"lockbox/v1/key-wrap";
const AAD_PAYLOAD: &[u8] = b"lockbox/v1/payload";

type Key = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// BRIEF §6.2. Recorded in every envelope, so changing this later only
    /// affects vaults created or re-keyed afterwards.
    pub const DEFAULT: Self = Self {
        m_kib: 64 * 1024,
        t: 3,
        p: 4,
    };

    /// Bounds on params read from disk, so a tampered file can't make unlock
    /// allocate gigabytes or spin for minutes before failing.
    fn check(&self) -> Result<(), VaultError> {
        let ok = (1..=16).contains(&self.p)
            && (8 * self.p..=1024 * 1024).contains(&self.m_kib)
            && (1..=20).contains(&self.t);
        if ok {
            Ok(())
        } else {
            Err(VaultError::Corrupt("KDF parameters out of range".into()))
        }
    }
}

/// A TOTP/HOTP account. Lives only inside the decrypted payload; never crosses
/// IPC with its seed (BRIEF §5). CRUD arrives in M3.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub seed_b32: String,
    pub digits: u32,
    pub period: u32,
    pub algorithm: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<u64>,
    pub added_at: u64,
    #[serde(default)]
    pub tags: Vec<String>,
}

// ---- on-disk envelope (BRIEF §6.1) ----

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u32,
    kdf: KdfHeader,
    key_wrap: SealedHeader,
    cipher: CipherHeader,
    payload: String,
    created_at: u64,
    updated_at: u64,
}

#[derive(Serialize, Deserialize)]
struct KdfHeader {
    algo: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct SealedHeader {
    algo: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct CipherHeader {
    algo: String,
    nonce: String,
}

#[derive(Debug)]
pub enum VaultError {
    AlreadyExists,
    NotFound,
    WrongPassword,
    WeakPassword,
    /// Payload failed GCM authentication even though the key unwrapped.
    Tampered,
    Corrupt(String),
    UnsupportedVersion(u32),
    Io(io::Error),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => write!(f, "a vault already exists"),
            Self::NotFound => write!(f, "no vault found"),
            Self::WrongPassword => write!(f, "wrong password"),
            Self::WeakPassword => write!(
                f,
                "password must be at least {MIN_PASSWORD_CHARS} characters"
            ),
            Self::Tampered => write!(f, "vault failed integrity check (modified or damaged)"),
            Self::Corrupt(why) => write!(f, "vault file is unreadable: {why}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported vault version {v}"),
            Self::Io(e) => write!(f, "vault I/O error: {e}"),
        }
    }
}

impl From<io::Error> for VaultError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// An unlocked vault. Dropping it is locking it: the vault key and every
/// entry (seeds included) are zeroized.
pub struct Vault {
    path: PathBuf,
    vault_key: Key,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    key_wrap: SealedHeader,
    created_at: u64,
    entries: Vec<Entry>,
}

impl Vault {
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    pub fn create(path: &Path, password: &str, kdf: KdfParams) -> Result<Self, VaultError> {
        check_password(password)?;
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let vault_key: Key = Zeroizing::new(<[u8; KEY_LEN]>::generate());
        let salt = <[u8; SALT_LEN]>::generate();
        let key_wrap = wrap_key(&vault_key, password, &salt, &kdf)?;
        let mut vault = Self {
            path: path.to_path_buf(),
            vault_key,
            kdf,
            salt,
            key_wrap,
            created_at: now(),
            entries: Vec::new(),
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn unlock(path: &Path, password: &str) -> Result<Self, VaultError> {
        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(VaultError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let env: Envelope =
            serde_json::from_slice(&raw).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        if env.version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(env.version));
        }
        if env.kdf.algo != KDF_ALGO
            || env.key_wrap.algo != CIPHER_ALGO
            || env.cipher.algo != CIPHER_ALGO
        {
            return Err(VaultError::Corrupt("unknown algorithm".into()));
        }
        let kdf = KdfParams {
            m_kib: env.kdf.m_kib,
            t: env.kdf.t,
            p: env.kdf.p,
        };
        kdf.check()?;
        let salt: [u8; SALT_LEN] = decode_fixed(&env.kdf.salt, "salt")?;

        let vault_key = unwrap_key(&env.key_wrap, password, &salt, &kdf)?;

        let nonce: [u8; NONCE_LEN] = decode_fixed(&env.cipher.nonce, "payload nonce")?;
        let ciphertext = decode(&env.payload, "payload")?;
        let plaintext =
            open(&vault_key, &nonce, AAD_PAYLOAD, &ciphertext).ok_or(VaultError::Tampered)?;
        let entries: Vec<Entry> = serde_json::from_slice(&plaintext)
            .map_err(|e| VaultError::Corrupt(format!("payload: {e}")))?;

        Ok(Self {
            path: path.to_path_buf(),
            vault_key,
            kdf,
            salt,
            key_wrap: env.key_wrap,
            created_at: env.created_at,
            entries,
        })
    }

    /// Re-checks the master password against this vault (for actions that
    /// need fresh proof of the password, like installing an update).
    pub fn verify_password(&self, password: &str) -> Result<(), VaultError> {
        unwrap_key(&self.key_wrap, password, &self.salt, &self.kdf).map(drop)
    }

    /// Verifies `old`, then re-keys everything: new vault key, new salt,
    /// current default KDF params, payload re-encrypted (BRIEF §8).
    pub fn change_password(&mut self, old: &str, new: &str) -> Result<(), VaultError> {
        self.change_password_with(old, new, KdfParams::DEFAULT)
    }

    fn change_password_with(
        &mut self,
        old: &str,
        new: &str,
        kdf: KdfParams,
    ) -> Result<(), VaultError> {
        check_password(new)?;
        self.verify_password(old)?;

        let vault_key: Key = Zeroizing::new(<[u8; KEY_LEN]>::generate());
        let salt = <[u8; SALT_LEN]>::generate();
        let key_wrap = wrap_key(&vault_key, new, &salt, &kdf)?;

        let previous = (
            std::mem::replace(&mut self.vault_key, vault_key),
            std::mem::replace(&mut self.kdf, kdf),
            std::mem::replace(&mut self.salt, salt),
            std::mem::replace(&mut self.key_wrap, key_wrap),
        );
        if let Err(e) = self.save() {
            // Disk still holds the old vault; keep memory consistent with it.
            (self.vault_key, self.kdf, self.salt, self.key_wrap) = previous;
            return Err(e);
        }
        Ok(())
    }

    fn save(&mut self) -> Result<(), VaultError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&self.entries).map_err(|e| VaultError::Corrupt(e.to_string()))?,
        );
        let (nonce, ciphertext) = seal(&self.vault_key, AAD_PAYLOAD, &plaintext);
        let env = Envelope {
            version: FORMAT_VERSION,
            kdf: KdfHeader {
                algo: KDF_ALGO.into(),
                m_kib: self.kdf.m_kib,
                t: self.kdf.t,
                p: self.kdf.p,
                salt: B64.encode(self.salt),
            },
            key_wrap: self.key_wrap.clone(),
            cipher: CipherHeader {
                algo: CIPHER_ALGO.into(),
                nonce: B64.encode(nonce),
            },
            payload: B64.encode(ciphertext),
            created_at: self.created_at,
            updated_at: now(),
        };
        let json =
            serde_json::to_vec_pretty(&env).map_err(|e| VaultError::Corrupt(e.to_string()))?;
        write_atomic_with_backup(&self.path, &json)?;
        Ok(())
    }
}

fn check_password(password: &str) -> Result<(), VaultError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        Err(VaultError::WeakPassword)
    } else {
        Ok(())
    }
}

fn derive_kek(password: &str, salt: &[u8], kdf: &KdfParams) -> Result<Key, VaultError> {
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(KEY_LEN))
        .map_err(|e| VaultError::Corrupt(format!("KDF parameters: {e}")))?;
    let mut kek: Key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, kek.as_mut())
        .map_err(|e| VaultError::Corrupt(format!("KDF: {e}")))?;
    Ok(kek)
}

fn wrap_key(
    vault_key: &Key,
    password: &str,
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<SealedHeader, VaultError> {
    let kek = derive_kek(password, salt, kdf)?;
    let (nonce, ciphertext) = seal(&kek, AAD_KEY_WRAP, vault_key.as_ref());
    Ok(SealedHeader {
        algo: CIPHER_ALGO.into(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

/// A wrong password and a tampered key wrap are indistinguishable under GCM;
/// both report `WrongPassword`.
fn unwrap_key(
    wrap: &SealedHeader,
    password: &str,
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<Key, VaultError> {
    let nonce: [u8; NONCE_LEN] = decode_fixed(&wrap.nonce, "key-wrap nonce")?;
    let ciphertext = decode(&wrap.ciphertext, "key wrap")?;
    let kek = derive_kek(password, salt, kdf)?;
    let raw = open(&kek, &nonce, AAD_KEY_WRAP, &ciphertext).ok_or(VaultError::WrongPassword)?;
    let mut vault_key: Key = Zeroizing::new([0u8; KEY_LEN]);
    if raw.len() != KEY_LEN {
        return Err(VaultError::Corrupt("vault key has wrong length".into()));
    }
    vault_key.copy_from_slice(&raw);
    Ok(vault_key)
}

fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> ([u8; NONCE_LEN], Vec<u8>) {
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
    let nonce = <[u8; NONCE_LEN]>::generate();
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption cannot fail for in-memory buffers");
    (nonce, ciphertext)
}

fn open(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
    cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

fn decode(b64: &str, what: &str) -> Result<Vec<u8>, VaultError> {
    B64.decode(b64)
        .map_err(|_| VaultError::Corrupt(format!("{what} is not valid base64")))
}

fn decode_fixed<const N: usize>(b64: &str, what: &str) -> Result<[u8; N], VaultError> {
    decode(b64, what)?
        .try_into()
        .map_err(|_| VaultError::Corrupt(format!("{what} has wrong length")))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// BRIEF §6.1: serialize → encrypt → write `.tmp` → fsync → rename, keeping
/// the previous file as a single rolling `.bak`. The directory is 0700 and
/// files are 0600.
fn write_atomic_with_backup(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().expect("vault path has a parent directory");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

    let tmp = sibling(path, "tmp");
    write_synced(&tmp, bytes)?;

    if path.exists() {
        let bak = sibling(path, "bak");
        let bak_tmp = sibling(path, "bak.tmp");
        write_synced(&bak_tmp, &fs::read(path)?)?;
        fs::rename(&bak_tmp, &bak)?;
    }

    fs::rename(&tmp, path)?;
    fs::File::open(dir)?.sync_all()
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// `vault.enc` → `vault.enc.<suffix>`
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().expect("vault path has a file name").to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny params so tests are fast; DEFAULT is exercised in its own test.
    const FAST: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    const PW: &str = "correct horse battery";

    fn setup() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lockbox/vault.enc");
        (dir, path)
    }

    fn sample_entry() -> Entry {
        Entry {
            id: "e1".into(),
            issuer: "Example".into(),
            account: "mads@example.com".into(),
            seed_b32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
            kind: "totp".into(),
            counter: None,
            added_at: 1,
            tags: vec!["work".into()],
        }
    }

    fn read_env(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn write_env(path: &Path, env: &serde_json::Value) {
        fs::write(path, serde_json::to_vec(env).unwrap()).unwrap();
    }

    #[test]
    fn create_then_unlock() {
        let (_d, path) = setup();
        assert!(!Vault::exists(&path));
        Vault::create(&path, PW, FAST).unwrap();
        assert!(Vault::exists(&path));
        let v = Vault::unlock(&path, PW).unwrap();
        assert!(v.entries.is_empty());
    }

    #[test]
    fn entries_round_trip_through_encryption() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        v.entries.push(sample_entry());
        v.save().unwrap();
        drop(v);

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("GEZDGNBV"), "seed must not appear in plaintext");
        assert!(!raw.contains("Example"), "metadata is inside the payload too");

        let v = Vault::unlock(&path, PW).unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].seed_b32, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(v.entries[0].tags, vec!["work".to_string()]);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        assert!(matches!(
            Vault::unlock(&path, "correct horse battery!"),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        assert!(matches!(
            Vault::create(&path, PW, FAST),
            Err(VaultError::AlreadyExists)
        ));
    }

    #[test]
    fn short_password_is_rejected() {
        let (_d, path) = setup();
        assert!(matches!(
            Vault::create(&path, "1234567", FAST),
            Err(VaultError::WeakPassword)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn missing_vault_is_not_found() {
        let (_d, path) = setup();
        assert!(matches!(Vault::unlock(&path, PW), Err(VaultError::NotFound)));
    }

    #[test]
    fn payload_tamper_is_detected() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        v.entries.push(sample_entry());
        v.save().unwrap();

        let mut env = read_env(&path);
        let mut ct = B64.decode(env["payload"].as_str().unwrap()).unwrap();
        ct[3] ^= 0x01;
        env["payload"] = B64.encode(ct).into();
        write_env(&path, &env);

        assert!(matches!(Vault::unlock(&path, PW), Err(VaultError::Tampered)));
    }

    #[test]
    fn swapped_payload_nonce_is_detected() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        let mut env = read_env(&path);
        env["cipher"]["nonce"] = B64.encode([7u8; NONCE_LEN]).into();
        write_env(&path, &env);
        assert!(matches!(Vault::unlock(&path, PW), Err(VaultError::Tampered)));
    }

    #[test]
    fn key_wrap_tamper_fails_like_wrong_password() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        let mut env = read_env(&path);
        let mut ct = B64.decode(env["key_wrap"]["ciphertext"].as_str().unwrap()).unwrap();
        ct[0] ^= 0x80;
        env["key_wrap"]["ciphertext"] = B64.encode(ct).into();
        write_env(&path, &env);
        assert!(matches!(
            Vault::unlock(&path, PW),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn edited_kdf_params_fail_like_wrong_password() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        let mut env = read_env(&path);
        env["kdf"]["t"] = 2.into();
        write_env(&path, &env);
        assert!(matches!(
            Vault::unlock(&path, PW),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn kdf_params_round_trip_through_envelope() {
        let (_d, path) = setup();
        let custom = KdfParams {
            m_kib: 128,
            t: 2,
            p: 2,
        };
        Vault::create(&path, PW, custom).unwrap();
        let env = read_env(&path);
        assert_eq!(env["version"], FORMAT_VERSION);
        assert_eq!(env["kdf"]["algo"], "argon2id");
        assert_eq!(env["kdf"]["m_kib"], 128);
        assert_eq!(env["kdf"]["t"], 2);
        assert_eq!(env["kdf"]["p"], 2);
        assert_eq!(B64.decode(env["kdf"]["salt"].as_str().unwrap()).unwrap().len(), SALT_LEN);
        assert_eq!(env["cipher"]["algo"], "aes-256-gcm");
        assert_eq!(env["key_wrap"]["algo"], "aes-256-gcm");
        assert_eq!(Vault::unlock(&path, PW).unwrap().kdf, custom);
    }

    #[test]
    fn default_kdf_params_work() {
        let (_d, path) = setup();
        Vault::create(&path, PW, KdfParams::DEFAULT).unwrap();
        assert_eq!(Vault::unlock(&path, PW).unwrap().kdf, KdfParams::DEFAULT);
    }

    #[test]
    fn absurd_kdf_params_are_rejected_before_deriving() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        let mut env = read_env(&path);
        env["kdf"]["m_kib"] = (u32::MAX).into();
        write_env(&path, &env);
        assert!(matches!(Vault::unlock(&path, PW), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn future_version_is_refused() {
        let (_d, path) = setup();
        Vault::create(&path, PW, FAST).unwrap();
        let mut env = read_env(&path);
        env["version"] = 2.into();
        write_env(&path, &env);
        assert!(matches!(
            Vault::unlock(&path, PW),
            Err(VaultError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn garbage_file_is_corrupt() {
        let (_d, path) = setup();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not a vault").unwrap();
        assert!(matches!(Vault::unlock(&path, PW), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn change_password_rekeys_and_keeps_entries() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        v.entries.push(sample_entry());
        v.save().unwrap();
        let old_env = read_env(&path);

        v.change_password_with(PW, "a brand new passphrase", FAST)
            .unwrap();
        drop(v);

        let new_env = read_env(&path);
        assert_ne!(old_env["kdf"]["salt"], new_env["kdf"]["salt"]);
        assert_ne!(old_env["key_wrap"], new_env["key_wrap"]);
        assert!(matches!(
            Vault::unlock(&path, PW),
            Err(VaultError::WrongPassword)
        ));
        let v = Vault::unlock(&path, "a brand new passphrase").unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].id, "e1");
    }

    #[test]
    fn change_password_requires_old_password() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            v.change_password_with("not the password", "a brand new passphrase", FAST),
            Err(VaultError::WrongPassword)
        ));
        assert!(matches!(
            v.change_password_with(PW, "short", FAST),
            Err(VaultError::WeakPassword)
        ));
        assert_eq!(fs::read(&path).unwrap(), before, "vault untouched");
        // The in-memory vault still works with the original password.
        v.save().unwrap();
        Vault::unlock(&path, PW).unwrap();
    }

    #[test]
    fn verify_password_checks_against_vault() {
        let (_d, path) = setup();
        let v = Vault::create(&path, PW, FAST).unwrap();
        assert!(v.verify_password(PW).is_ok());
        assert!(matches!(
            v.verify_password("not the password"),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn saves_are_atomic_and_keep_one_backup() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        let bak = sibling(&path, "bak");
        assert!(!bak.exists(), "first write has nothing to back up");

        let first = fs::read(&path).unwrap();
        v.entries.push(sample_entry());
        v.save().unwrap();
        assert_eq!(fs::read(&bak).unwrap(), first, "backup is the previous version");

        let second = fs::read(&path).unwrap();
        v.save().unwrap();
        assert_eq!(fs::read(&bak).unwrap(), second, "backup rolls forward");

        assert!(!sibling(&path, "tmp").exists());
        assert!(!sibling(&path, "bak.tmp").exists());

        // The backup is itself a valid vault (corruption recovery).
        let restored = Vault::unlock(&bak, PW).unwrap();
        assert_eq!(restored.entries.len(), 1);
    }

    #[test]
    fn files_and_dir_are_private() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        v.save().unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&sibling(&path, "bak")), 0o600);
    }

    #[test]
    fn nonces_and_salts_are_fresh() {
        let (_d, path) = setup();
        let mut v = Vault::create(&path, PW, FAST).unwrap();
        let a = read_env(&path);
        v.save().unwrap();
        let b = read_env(&path);
        assert_ne!(a["cipher"]["nonce"], b["cipher"]["nonce"]);

        let (_d2, path2) = setup();
        Vault::create(&path2, PW, FAST).unwrap();
        let c = read_env(&path2);
        assert_ne!(a["kdf"]["salt"], c["kdf"]["salt"]);
    }
}
