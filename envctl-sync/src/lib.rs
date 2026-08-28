use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use envctl_crypto::{MasterKey, decrypt_value, encrypt_value};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;

const SYNC_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairingTicket {
    pub device_id: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireOperation {
    pub id: String,
    pub kind: String,
    pub payload: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncBundle {
    pub version: u32,
    pub device_id: String,
    pub operations: Vec<WireOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EncryptedBundle {
    version: u32,
    nonce: String,
    ciphertext: String,
}

pub fn init_key_file(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(anyhow!("sync key file already exists: {}", path.display()));
    }
    let mut key = [0_u8; SYNC_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    write_restrictive(path, STANDARD.encode(key).as_bytes())
}

pub fn read_key_file(path: &Path) -> Result<Vec<u8>> {
    let encoded = fs::read_to_string(path)
        .with_context(|| format!("failed to read sync key file {}", path.display()))?;
    let key = STANDARD
        .decode(encoded.trim())
        .context("sync key file is not valid base64")?;
    if key.len() != SYNC_KEY_LEN {
        return Err(anyhow!("sync key must be {SYNC_KEY_LEN} bytes"));
    }
    Ok(key)
}

pub fn write_bundle(path: &Path, key: &[u8], bundle: &SyncBundle) -> Result<()> {
    let master_key = MasterKey::from_bytes(key.to_vec())?;
    let body = serde_json::to_string(bundle)?;
    let encrypted = encrypt_value(&master_key, &body)?;
    let wrapped = EncryptedBundle {
        version: 1,
        nonce: STANDARD.encode(encrypted.nonce),
        ciphertext: STANDARD.encode(encrypted.ciphertext),
    };
    write_restrictive(path, serde_json::to_vec_pretty(&wrapped)?.as_slice())
}

pub fn read_bundle(path: &Path, key: &[u8]) -> Result<SyncBundle> {
    let wrapped: EncryptedBundle = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("failed to read bundle {}", path.display()))?,
    )?;
    if wrapped.version != 1 {
        return Err(anyhow!(
            "unsupported sync bundle version {}",
            wrapped.version
        ));
    }
    let master_key = MasterKey::from_bytes(key.to_vec())?;
    let nonce = STANDARD.decode(wrapped.nonce)?;
    let ciphertext = STANDARD.decode(wrapped.ciphertext)?;
    let body = decrypt_value(&master_key, &ciphertext, &nonce)?;
    Ok(serde_json::from_str(&body)?)
}

pub fn load_or_create_device(path: &Path) -> Result<DeviceIdentity> {
    if path.exists() {
        let body = fs::read_to_string(path)
            .with_context(|| format!("failed to read device file {}", path.display()))?;
        return serde_json_like_device(&body);
    }
    let identity = DeviceIdentity {
        id: Uuid::new_v4().to_string(),
    };
    let body = format!("{{\"id\":\"{}\"}}\n", identity.id);
    write_restrictive(path, body.as_bytes())?;
    Ok(identity)
}

pub fn create_pairing_ticket(device_id: &str) -> PairingTicket {
    let mut bytes = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    PairingTicket {
        device_id: device_id.to_string(),
        code: STANDARD.encode(bytes),
    }
}

fn serde_json_like_device(body: &str) -> Result<DeviceIdentity> {
    let body = body.trim();
    let Some(start) = body.find("\"id\"") else {
        return Err(anyhow!("device identity file is missing id"));
    };
    let tail = &body[start + 4..];
    let Some(colon) = tail.find(':') else {
        return Err(anyhow!("device identity file is invalid"));
    };
    let value = tail[colon + 1..].trim();
    let value = value.trim_start_matches('"');
    let Some(end) = value.find('"') else {
        return Err(anyhow!("device identity file is invalid"));
    };
    Ok(DeviceIdentity {
        id: value[..end].to_string(),
    })
}

#[cfg(unix)]
fn write_restrictive(path: &Path, contents: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(contents)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_restrictive(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_reads_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-root.key");
        init_key_file(&path).unwrap();
        assert_eq!(read_key_file(&path).unwrap().len(), SYNC_KEY_LEN);
    }

    #[test]
    fn creates_pairing_ticket() {
        let ticket = create_pairing_ticket("device-a");
        assert_eq!(ticket.device_id, "device-a");
        assert!(!ticket.code.is_empty());
    }

    #[test]
    fn encrypted_bundle_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("sync-root.key");
        let bundle_path = dir.path().join("bundle.json");
        init_key_file(&key_path).unwrap();
        let key = read_key_file(&key_path).unwrap();
        let bundle = SyncBundle {
            version: 1,
            device_id: "device-a".to_string(),
            operations: vec![WireOperation {
                id: "op-1".to_string(),
                kind: "secret.add".to_string(),
                payload: "{\"key\":\"DATABASE_URL\"}".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
            }],
        };

        write_bundle(&bundle_path, &key, &bundle).unwrap();
        let raw = fs::read_to_string(&bundle_path).unwrap();
        assert!(!raw.contains("DATABASE_URL"));
        assert_eq!(read_bundle(&bundle_path, &key).unwrap(), bundle);
    }
}
