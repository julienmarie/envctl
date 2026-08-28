use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use directories::ProjectDirs;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SERVICE: &str = "envctl";
const ACCOUNT: &str = "master-key";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("failed to encrypt secret value")]
    Encrypt,
    #[error("failed to decrypt secret value")]
    Decrypt,
    #[error("invalid encryption key")]
    InvalidKey,
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("could not resolve envctl config directory")]
    ConfigDir,
    #[error("keyring error: {0}")]
    Keyring(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
}

#[derive(Debug, Clone)]
pub struct MasterKey(Zeroizing<Vec<u8>>);

impl MasterKey {
    pub fn generate() -> Self {
        let mut key = vec![0_u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        Self(Zeroizing::new(key))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn as_key(&self) -> &Key {
        Key::from_slice(&self.0)
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(&self.0)
    }

    pub fn from_base64(value: &str) -> Result<Self, CryptoError> {
        Self::from_bytes(STANDARD.decode(value)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedValue {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub fn encrypt_value(key: &MasterKey, plaintext: &str) -> Result<EncryptedValue, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.as_key());
    let mut nonce = vec![0_u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(EncryptedValue { ciphertext, nonce })
}

pub fn decrypt_value(
    key: &MasterKey,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<String, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonce);
    }

    let cipher = ChaCha20Poly1305::new(key.as_key());
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;
    String::from_utf8(plaintext).map_err(|_| CryptoError::Decrypt)
}

#[derive(Debug, Clone)]
pub struct KeyManager {
    config_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyMeta {
    backend: String,
}

impl KeyManager {
    pub fn new() -> Result<Self, CryptoError> {
        let dirs = ProjectDirs::from("", "", "envctl").ok_or(CryptoError::ConfigDir)?;
        Ok(Self {
            config_dir: dirs.config_dir().to_path_buf(),
        })
    }

    pub fn with_config_dir(config_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_dir: config_dir.into(),
        }
    }

    pub fn load_or_init(&self) -> Result<MasterKey, CryptoError> {
        fs::create_dir_all(&self.config_dir)?;

        if let Ok(key) = self.load_keyring() {
            return Ok(key);
        }

        let fallback_path = self.fallback_key_path();
        if fallback_path.exists() {
            return self.load_fallback();
        }

        let key = MasterKey::generate();
        match self.store_keyring(&key) {
            Ok(()) => {
                self.write_meta("keyring")?;
                Ok(key)
            }
            Err(_) => {
                self.store_fallback(&key)?;
                self.write_meta("fallback-file")?;
                Ok(key)
            }
        }
    }

    fn load_keyring(&self) -> Result<MasterKey, CryptoError> {
        let entry = keyring::Entry::new(SERVICE, ACCOUNT)
            .map_err(|err| CryptoError::Keyring(err.to_string()))?;
        let encoded = entry
            .get_password()
            .map_err(|err| CryptoError::Keyring(err.to_string()))?;
        MasterKey::from_base64(&encoded)
    }

    fn store_keyring(&self, key: &MasterKey) -> Result<(), CryptoError> {
        let entry = keyring::Entry::new(SERVICE, ACCOUNT)
            .map_err(|err| CryptoError::Keyring(err.to_string()))?;
        entry
            .set_password(&key.to_base64())
            .map_err(|err| CryptoError::Keyring(err.to_string()))
    }

    fn load_fallback(&self) -> Result<MasterKey, CryptoError> {
        let encoded = fs::read_to_string(self.fallback_key_path())?;
        MasterKey::from_base64(encoded.trim())
    }

    fn store_fallback(&self, key: &MasterKey) -> Result<(), CryptoError> {
        fs::create_dir_all(&self.config_dir)?;
        write_restrictive(self.fallback_key_path(), key.to_base64().as_bytes())
    }

    fn write_meta(&self, backend: &str) -> Result<(), CryptoError> {
        let meta = KeyMeta {
            backend: backend.to_string(),
        };
        let body = serde_json::to_vec_pretty(&meta)?;
        fs::write(self.config_dir.join("keyring-meta.json"), body)?;
        Ok(())
    }

    fn fallback_key_path(&self) -> PathBuf {
        self.config_dir.join("master-key")
    }
}

#[cfg(unix)]
fn write_restrictive(path: impl AsRef<Path>, contents: &[u8]) -> Result<(), CryptoError> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_restrictive(path: impl AsRef<Path>, contents: &[u8]) -> Result<(), CryptoError> {
    fs::write(path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_round_trip() {
        let key = MasterKey::generate();
        let encrypted = encrypt_value(&key, "postgres://localhost/dev").unwrap();
        assert_ne!(encrypted.ciphertext, b"postgres://localhost/dev");
        let decrypted = decrypt_value(&key, &encrypted.ciphertext, &encrypted.nonce).unwrap();
        assert_eq!(decrypted, "postgres://localhost/dev");
    }

    #[test]
    fn generated_nonces_are_distinct() {
        let key = MasterKey::generate();
        let first = encrypt_value(&key, "same").unwrap();
        let second = encrypt_value(&key, "same").unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn fallback_key_loads_from_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let manager = KeyManager::with_config_dir(dir.path());
        let key = MasterKey::generate();
        manager.store_fallback(&key).unwrap();
        let loaded = manager.load_fallback().unwrap();
        assert_eq!(key.to_base64(), loaded.to_base64());
    }
}
