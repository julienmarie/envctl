use chrono::{DateTime, Utc};
use directories::ProjectDirs;
use envctl_core::{DomainError, Environment, Id, Project, Secret, SecretRegistry, SecretVariant};
use envctl_crypto::{CryptoError, KeyManager, MasterKey, decrypt_value, encrypt_value};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("could not resolve envctl data directory")]
    DataDir,
    #[error("invalid timestamp in database: {0}")]
    InvalidTimestamp(String),
    #[error("invalid id in database: {0}")]
    InvalidId(String),
    #[error("invalid sync payload: {0}")]
    InvalidSyncPayload(String),
}

pub struct Store {
    conn: Connection,
    key: MasterKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOperation {
    pub id: Id,
    pub kind: String,
    pub payload: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub operation_count: usize,
    pub latest_operation: Option<SyncOperation>,
}

impl Store {
    pub fn open_default() -> Result<Self, StoreError> {
        let (data_dir, key_manager) = if let Ok(home) = std::env::var("ENVCTL_HOME") {
            let home = PathBuf::from(home);
            (home.clone(), KeyManager::with_config_dir(home))
        } else {
            let dirs = ProjectDirs::from("", "", "envctl").ok_or(StoreError::DataDir)?;
            (dirs.data_dir().to_path_buf(), KeyManager::new()?)
        };
        std::fs::create_dir_all(&data_dir)
            .map_err(|err| StoreError::Crypto(CryptoError::Io(err)))?;
        let key = key_manager.load_or_init()?;
        Self::open_with_key(data_dir.join("store.db"), key)
    }

    pub fn open_at(
        path: impl AsRef<Path>,
        config_dir: impl Into<PathBuf>,
    ) -> Result<Self, StoreError> {
        let key = KeyManager::with_config_dir(config_dir).load_or_init()?;
        Self::open_with_key(path, key)
    }

    pub fn open_with_key(path: impl AsRef<Path>, key: MasterKey) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { conn, key };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_memory_for_tests() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self {
            conn,
            key: MasterKey::generate(),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS environments (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                key TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secret_variants (
                id TEXT PRIMARY KEY,
                secret_id TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(secret_id, environment_id),
                FOREIGN KEY(secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
                FOREIGN KEY(environment_id) REFERENCES environments(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS project_secrets (
                project_id TEXT NOT NULL,
                secret_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(project_id, secret_id),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY(secret_id) REFERENCES secrets(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS sync_operations (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_devices (
                id TEXT PRIMARY KEY,
                name TEXT,
                created_at TEXT NOT NULL,
                last_seen_at TEXT
            );
            "#,
        )?;
        Ok(())
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn sync_status(&self) -> Result<SyncStatus, StoreError> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM sync_operations", [], |row| row.get(0))?;
        let latest_operation = self
            .conn
            .query_row(
                "SELECT id, kind, ciphertext, nonce, created_at FROM sync_operations ORDER BY created_at DESC, id DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(id, kind, ciphertext, nonce, created_at)| -> Result<SyncOperation, StoreError> {
                    let payload = decrypt_value(&self.key, &ciphertext, &nonce)?;
                    Ok(SyncOperation {
                        id: parse_id(&id)?,
                        kind,
                        payload,
                        created_at: parse_time(&created_at)?,
                    })
                },
            )
            .transpose()?;

        Ok(SyncStatus {
            operation_count: count as usize,
            latest_operation,
        })
    }

    pub fn list_sync_operations(&self) -> Result<Vec<SyncOperation>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, ciphertext, nonce, created_at FROM sync_operations ORDER BY created_at, id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;

        rows.map(|row| {
            let (id, kind, ciphertext, nonce, created_at) = row?;
            let payload = decrypt_value(&self.key, &ciphertext, &nonce)?;
            Ok(SyncOperation {
                id: parse_id(&id)?,
                kind,
                payload,
                created_at: parse_time(&created_at)?,
            })
        })
        .collect()
    }

    pub fn import_sync_operations(
        &mut self,
        operations: &[SyncOperation],
    ) -> Result<usize, StoreError> {
        let mut imported = 0_usize;
        let mut sorted = operations.to_vec();
        sorted.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });

        for operation in sorted {
            if self.sync_operation_exists(operation.id)? {
                continue;
            }
            self.apply_sync_operation(&operation)?;
            self.insert_sync_operation(&operation)?;
            imported += 1;
        }

        Ok(imported)
    }

    fn append_sync_operation(
        &self,
        kind: &str,
        payload: serde_json::Value,
    ) -> Result<(), StoreError> {
        let operation = SyncOperation {
            id: Uuid::new_v4(),
            kind: kind.to_string(),
            payload: payload.to_string(),
            created_at: Utc::now(),
        };
        self.insert_sync_operation(&operation)
    }

    fn insert_sync_operation(&self, operation: &SyncOperation) -> Result<(), StoreError> {
        let encrypted = encrypt_value(&self.key, &operation.payload)?;
        self.conn.execute(
            "INSERT INTO sync_operations (id, kind, ciphertext, nonce, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                operation.id.to_string(),
                operation.kind,
                encrypted.ciphertext,
                encrypted.nonce,
                operation.created_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    fn sync_operation_exists(&self, id: Id) -> Result<bool, StoreError> {
        let exists: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM sync_operations WHERE id = ?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(exists.is_some())
    }

    fn apply_sync_operation(&mut self, operation: &SyncOperation) -> Result<(), StoreError> {
        let payload: Value = serde_json::from_str(&operation.payload)
            .map_err(|err| StoreError::Crypto(CryptoError::Json(err)))?;
        match operation.kind.as_str() {
            "project.add" => {
                let name = payload_str(&payload, "name")?;
                if self.project_by_name_optional(name)?.is_none() {
                    let id = Uuid::new_v4();
                    let now = operation.created_at.to_rfc3339();
                    self.conn.execute(
                        "INSERT INTO projects (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![id.to_string(), name, payload_opt_str(&payload, "description"), now, now],
                    )?;
                }
            }
            "project.rename" => {
                let old = payload_str(&payload, "old")?;
                let new = payload_str(&payload, "new")?;
                if self.project_by_name_optional(new)?.is_none()
                    && self.project_by_name_optional(old)?.is_some()
                {
                    self.conn.execute(
                        "UPDATE projects SET name = ?1, updated_at = ?2 WHERE name = ?3",
                        params![new, operation.created_at.to_rfc3339(), old],
                    )?;
                }
            }
            "project.remove" => {
                let name = payload_str(&payload, "name")?;
                self.conn
                    .execute("DELETE FROM projects WHERE name = ?1", [name])?;
            }
            "environment.add" => {
                let name = payload_str(&payload, "name")?;
                if self.environment_by_name_optional(name)?.is_none() {
                    let id = Uuid::new_v4();
                    let now = operation.created_at.to_rfc3339();
                    self.conn.execute(
                        "INSERT INTO environments (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![id.to_string(), name, payload_opt_str(&payload, "description"), now, now],
                    )?;
                }
            }
            "environment.rename" => {
                let old = payload_str(&payload, "old")?;
                let new = payload_str(&payload, "new")?;
                if self.environment_by_name_optional(new)?.is_none()
                    && self.environment_by_name_optional(old)?.is_some()
                {
                    self.conn.execute(
                        "UPDATE environments SET name = ?1, updated_at = ?2 WHERE name = ?3",
                        params![new, operation.created_at.to_rfc3339(), old],
                    )?;
                }
            }
            "environment.remove" => {
                let name = payload_str(&payload, "name")?;
                self.conn
                    .execute("DELETE FROM environments WHERE name = ?1", [name])?;
            }
            "secret.add" => {
                let key = payload_str(&payload, "key")?;
                if self.secret_by_key_optional(key)?.is_none() {
                    let id = Uuid::new_v4();
                    let now = operation.created_at.to_rfc3339();
                    self.conn.execute(
                        "INSERT INTO secrets (id, key, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![id.to_string(), key, payload_opt_str(&payload, "description"), now, now],
                    )?;
                }
            }
            "secret.rename" => {
                let old = payload_str(&payload, "old")?;
                let new = payload_str(&payload, "new")?;
                if self.secret_by_key_optional(new)?.is_none()
                    && self.secret_by_key_optional(old)?.is_some()
                {
                    self.conn.execute(
                        "UPDATE secrets SET key = ?1, updated_at = ?2 WHERE key = ?3",
                        params![new, operation.created_at.to_rfc3339(), old],
                    )?;
                }
            }
            "secret.remove" => {
                let key = payload_str(&payload, "key")?;
                self.conn
                    .execute("DELETE FROM secrets WHERE key = ?1", [key])?;
            }
            "secret.describe" => {
                let key = payload_str(&payload, "key")?;
                if self.secret_by_key_optional(key)?.is_some() {
                    self.conn.execute(
                        "UPDATE secrets SET description = ?1, updated_at = ?2 WHERE key = ?3",
                        params![
                            payload_opt_str(&payload, "description"),
                            operation.created_at.to_rfc3339(),
                            key
                        ],
                    )?;
                }
            }
            "variant.set" => {
                let key = payload_str(&payload, "key")?;
                let environment = payload_str(&payload, "environment")?;
                let value = payload_str(&payload, "value")?;
                if self.secret_by_key_optional(key)?.is_some()
                    && self.environment_by_name_optional(environment)?.is_some()
                    && self
                        .variant_updated_at(key, environment)?
                        .map(|updated_at| operation.created_at >= updated_at)
                        .unwrap_or(true)
                {
                    self.set_variant_without_log(key, environment, value, operation.created_at)?;
                }
            }
            "variant.unset" => {
                let key = payload_str(&payload, "key")?;
                let environment = payload_str(&payload, "environment")?;
                if self.secret_by_key_optional(key)?.is_some()
                    && self.environment_by_name_optional(environment)?.is_some()
                    && self
                        .variant_updated_at(key, environment)?
                        .map(|updated_at| operation.created_at >= updated_at)
                        .unwrap_or(false)
                {
                    let secret = self.get_secret(key)?;
                    let environment = self.get_environment(environment)?;
                    self.conn.execute(
                        "DELETE FROM secret_variants WHERE secret_id = ?1 AND environment_id = ?2",
                        params![secret.id.to_string(), environment.id.to_string()],
                    )?;
                }
            }
            "secret.assign" => {
                let key = payload_str(&payload, "key")?;
                let project = payload_str(&payload, "project")?;
                if self.secret_by_key_optional(key)?.is_some()
                    && self.project_by_name_optional(project)?.is_some()
                {
                    let secret = self.get_secret(key)?;
                    let project = self.get_project(project)?;
                    self.conn.execute(
                        "INSERT OR IGNORE INTO project_secrets (project_id, secret_id, created_at) VALUES (?1, ?2, ?3)",
                        params![project.id.to_string(), secret.id.to_string(), operation.created_at.to_rfc3339()],
                    )?;
                }
            }
            "secret.unassign" => {
                let key = payload_str(&payload, "key")?;
                let project = payload_str(&payload, "project")?;
                if self.secret_by_key_optional(key)?.is_some()
                    && self.project_by_name_optional(project)?.is_some()
                {
                    let secret = self.get_secret(key)?;
                    let project = self.get_project(project)?;
                    self.conn.execute(
                        "DELETE FROM project_secrets WHERE project_id = ?1 AND secret_id = ?2",
                        params![project.id.to_string(), secret.id.to_string()],
                    )?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn variant_updated_at(
        &self,
        key: &str,
        environment: &str,
    ) -> Result<Option<DateTime<Utc>>, StoreError> {
        let secret = self.get_secret(key)?;
        let environment = self.get_environment(environment)?;
        let updated_at = self
            .conn
            .query_row(
                "SELECT updated_at FROM secret_variants WHERE secret_id = ?1 AND environment_id = ?2",
                params![secret.id.to_string(), environment.id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        updated_at.map(|value| parse_time(&value)).transpose()
    }

    fn set_variant_without_log(
        &mut self,
        key: &str,
        environment: &str,
        value: &str,
        timestamp: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let secret = self.get_secret(key)?;
        let environment = self.get_environment(environment)?;
        let encrypted = encrypt_value(&self.key, value)?;
        let id = Uuid::new_v4();
        let now = timestamp.to_rfc3339();
        self.conn.execute(
            r#"
            INSERT INTO secret_variants
                (id, secret_id, environment_id, ciphertext, nonce, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(secret_id, environment_id)
            DO UPDATE SET ciphertext = excluded.ciphertext, nonce = excluded.nonce, updated_at = excluded.updated_at
            "#,
            params![
                id.to_string(),
                secret.id.to_string(),
                environment.id.to_string(),
                encrypted.ciphertext,
                encrypted.nonce,
                now,
                now
            ],
        )?;
        Ok(())
    }

    fn project_by_name_optional(&self, name: &str) -> Result<Option<Project>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, name, description, created_at, updated_at FROM projects WHERE name = ?1",
                [name],
                |row| {
                    let id: String = row.get(0)?;
                    let name: String = row.get(1)?;
                    let description: Option<String> = row.get(2)?;
                    let created_at: String = row.get(3)?;
                    let updated_at: String = row.get(4)?;
                    Ok((id, name, description, created_at, updated_at))
                },
            )
            .optional()?;

        row.map(|(id, name, description, created_at, updated_at)| {
            Ok(Project {
                id: parse_id(&id)?,
                name,
                description,
                assigned_secret_ids: self.assigned_secret_ids_for_project(&id)?,
                created_at: parse_time(&created_at)?,
                updated_at: parse_time(&updated_at)?,
            })
        })
        .transpose()
    }

    fn environment_by_name_optional(&self, name: &str) -> Result<Option<Environment>, StoreError> {
        self.conn
            .query_row(
                "SELECT id, name, description, created_at, updated_at FROM environments WHERE name = ?1",
                [name],
                |row| {
                    Ok(Environment {
                        id: parse_id(&row.get::<_, String>(0)?)
                            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?,
                        name: row.get(1)?,
                        description: row.get(2)?,
                        created_at: parse_time(&row.get::<_, String>(3)?)
                            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?,
                        updated_at: parse_time(&row.get::<_, String>(4)?)
                            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    fn secret_by_key_optional(&self, key: &str) -> Result<Option<Secret>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, key, description, created_at, updated_at FROM secrets WHERE key = ?1",
                [key],
                |row| {
                    let id: String = row.get(0)?;
                    let key: String = row.get(1)?;
                    let description: Option<String> = row.get(2)?;
                    let created_at: String = row.get(3)?;
                    let updated_at: String = row.get(4)?;
                    Ok((id, key, description, created_at, updated_at))
                },
            )
            .optional()?;

        row.map(|(id, key, description, created_at, updated_at)| {
            Ok(Secret {
                id: parse_id(&id)?,
                key,
                description,
                assigned_project_ids: self.assigned_project_ids_for_secret(&id)?,
                created_at: parse_time(&created_at)?,
                updated_at: parse_time(&updated_at)?,
            })
        })
        .transpose()
    }

    fn assigned_secret_ids_for_project(&self, project_id: &str) -> Result<Vec<Id>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT secret_id FROM project_secrets WHERE project_id = ?1 ORDER BY secret_id",
        )?;
        let rows = stmt.query_map([project_id], |row| row.get::<_, String>(0))?;
        rows.map(|row| parse_id(&row?)).collect()
    }

    fn assigned_project_ids_for_secret(&self, secret_id: &str) -> Result<Vec<Id>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT project_id FROM project_secrets WHERE secret_id = ?1 ORDER BY project_id",
        )?;
        let rows = stmt.query_map([secret_id], |row| row.get::<_, String>(0))?;
        rows.map(|row| parse_id(&row?)).collect()
    }
}

impl SecretRegistry for Store {
    type Error = StoreError;

    fn add_project(
        &mut self,
        name: &str,
        description: Option<&str>,
    ) -> Result<Project, StoreError> {
        if self.project_by_name_optional(name)?.is_some() {
            return Err(DomainError::DuplicateProject {
                project: name.to_string(),
            }
            .into());
        }
        let id = Uuid::new_v4();
        let now = now_string();
        self.conn.execute(
            "INSERT INTO projects (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id.to_string(), name, description, now, now],
        )?;
        self.append_sync_operation(
            "project.add",
            json!({"name": name, "description": description}),
        )?;
        self.get_project(name)
    }

    fn rename_project(&mut self, old_name: &str, new_name: &str) -> Result<Project, StoreError> {
        self.get_project(old_name)?;
        if self.project_by_name_optional(new_name)?.is_some() {
            return Err(DomainError::DuplicateProject {
                project: new_name.to_string(),
            }
            .into());
        }
        self.conn.execute(
            "UPDATE projects SET name = ?1, updated_at = ?2 WHERE name = ?3",
            params![new_name, now_string(), old_name],
        )?;
        self.append_sync_operation("project.rename", json!({"old": old_name, "new": new_name}))?;
        self.get_project(new_name)
    }

    fn remove_project(&mut self, name: &str) -> Result<(), StoreError> {
        self.get_project(name)?;
        self.conn
            .execute("DELETE FROM projects WHERE name = ?1", [name])?;
        self.append_sync_operation("project.remove", json!({"name": name}))?;
        Ok(())
    }

    fn list_projects(&self) -> Result<Vec<Project>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, description, created_at, updated_at FROM projects ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let description: Option<String> = row.get(2)?;
            let created_at: String = row.get(3)?;
            let updated_at: String = row.get(4)?;
            Ok((id, name, description, created_at, updated_at))
        })?;
        rows.map(|row| {
            let (id, name, description, created_at, updated_at) = row?;
            Ok(Project {
                id: parse_id(&id)?,
                name,
                description,
                assigned_secret_ids: self.assigned_secret_ids_for_project(&id)?,
                created_at: parse_time(&created_at)?,
                updated_at: parse_time(&updated_at)?,
            })
        })
        .collect()
    }

    fn get_project(&self, name: &str) -> Result<Project, StoreError> {
        self.project_by_name_optional(name)?
            .ok_or_else(|| DomainError::ProjectNotFound(name.to_string()).into())
    }

    fn add_environment(
        &mut self,
        name: &str,
        description: Option<&str>,
    ) -> Result<Environment, StoreError> {
        if self.environment_by_name_optional(name)?.is_some() {
            return Err(DomainError::DuplicateEnvironment {
                environment: name.to_string(),
            }
            .into());
        }
        let id = Uuid::new_v4();
        let now = now_string();
        self.conn.execute(
            "INSERT INTO environments (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id.to_string(), name, description, now, now],
        )?;
        self.append_sync_operation(
            "environment.add",
            json!({"name": name, "description": description}),
        )?;
        self.get_environment(name)
    }

    fn rename_environment(
        &mut self,
        old_name: &str,
        new_name: &str,
    ) -> Result<Environment, StoreError> {
        self.get_environment(old_name)?;
        if self.environment_by_name_optional(new_name)?.is_some() {
            return Err(DomainError::DuplicateEnvironment {
                environment: new_name.to_string(),
            }
            .into());
        }
        self.conn.execute(
            "UPDATE environments SET name = ?1, updated_at = ?2 WHERE name = ?3",
            params![new_name, now_string(), old_name],
        )?;
        self.append_sync_operation(
            "environment.rename",
            json!({"old": old_name, "new": new_name}),
        )?;
        self.get_environment(new_name)
    }

    fn remove_environment(&mut self, name: &str, force: bool) -> Result<(), StoreError> {
        let count = self.variant_count_for_environment(name)?;
        if count > 0 && !force {
            return Err(DomainError::EnvironmentHasVariants {
                environment: name.to_string(),
                variant_count: count,
            }
            .into());
        }
        self.conn
            .execute("DELETE FROM environments WHERE name = ?1", [name])?;
        self.append_sync_operation("environment.remove", json!({"name": name, "force": force}))?;
        Ok(())
    }

    fn list_environments(&self) -> Result<Vec<Environment>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, description, created_at, updated_at FROM environments ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        rows.map(|row| {
            let (id, name, description, created_at, updated_at) = row?;
            Ok(Environment {
                id: parse_id(&id)?,
                name,
                description,
                created_at: parse_time(&created_at)?,
                updated_at: parse_time(&updated_at)?,
            })
        })
        .collect()
    }

    fn get_environment(&self, name: &str) -> Result<Environment, StoreError> {
        self.environment_by_name_optional(name)?
            .ok_or_else(|| DomainError::EnvironmentNotFound(name.to_string()).into())
    }

    fn add_secret(&mut self, key: &str, description: Option<&str>) -> Result<Secret, StoreError> {
        if self.secret_by_key_optional(key)?.is_some() {
            return Err(DomainError::DuplicateSecret {
                key: key.to_string(),
            }
            .into());
        }
        let id = Uuid::new_v4();
        let now = now_string();
        self.conn.execute(
            "INSERT INTO secrets (id, key, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id.to_string(), key, description, now, now],
        )?;
        self.append_sync_operation(
            "secret.add",
            json!({"key": key, "description": description}),
        )?;
        self.get_secret(key)
    }

    fn rename_secret(&mut self, old_key: &str, new_key: &str) -> Result<Secret, StoreError> {
        self.get_secret(old_key)?;
        if self.secret_by_key_optional(new_key)?.is_some() {
            return Err(DomainError::DuplicateSecret {
                key: new_key.to_string(),
            }
            .into());
        }
        self.conn.execute(
            "UPDATE secrets SET key = ?1, updated_at = ?2 WHERE key = ?3",
            params![new_key, now_string(), old_key],
        )?;
        self.append_sync_operation("secret.rename", json!({"old": old_key, "new": new_key}))?;
        self.get_secret(new_key)
    }

    fn remove_secret(&mut self, key: &str) -> Result<(), StoreError> {
        self.get_secret(key)?;
        self.conn
            .execute("DELETE FROM secrets WHERE key = ?1", [key])?;
        self.append_sync_operation("secret.remove", json!({"key": key}))?;
        Ok(())
    }

    fn list_secrets(&self) -> Result<Vec<Secret>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, key, description, created_at, updated_at FROM secrets ORDER BY key",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        rows.map(|row| {
            let (id, key, description, created_at, updated_at) = row?;
            Ok(Secret {
                id: parse_id(&id)?,
                key,
                description,
                assigned_project_ids: self.assigned_project_ids_for_secret(&id)?,
                created_at: parse_time(&created_at)?,
                updated_at: parse_time(&updated_at)?,
            })
        })
        .collect()
    }

    fn get_secret(&self, key: &str) -> Result<Secret, StoreError> {
        self.secret_by_key_optional(key)?
            .ok_or_else(|| DomainError::SecretNotFound(key.to_string()).into())
    }

    fn set_secret_description(
        &mut self,
        key: &str,
        description: Option<&str>,
    ) -> Result<Secret, StoreError> {
        self.get_secret(key)?;
        self.conn.execute(
            "UPDATE secrets SET description = ?1, updated_at = ?2 WHERE key = ?3",
            params![description, now_string(), key],
        )?;
        self.append_sync_operation(
            "secret.describe",
            json!({"key": key, "description": description}),
        )?;
        self.get_secret(key)
    }

    fn set_variant(&mut self, key: &str, environment: &str, value: &str) -> Result<(), StoreError> {
        let secret = self.get_secret(key)?;
        let environment = self.get_environment(environment)?;
        let encrypted = encrypt_value(&self.key, value)?;
        let id = Uuid::new_v4();
        let now = now_string();
        self.conn.execute(
            r#"
            INSERT INTO secret_variants
                (id, secret_id, environment_id, ciphertext, nonce, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(secret_id, environment_id)
            DO UPDATE SET ciphertext = excluded.ciphertext, nonce = excluded.nonce, updated_at = excluded.updated_at
            "#,
            params![
                id.to_string(),
                secret.id.to_string(),
                environment.id.to_string(),
                encrypted.ciphertext,
                encrypted.nonce,
                now,
                now
            ],
        )?;
        self.append_sync_operation(
            "variant.set",
            json!({"key": key, "environment": environment.name, "value": value}),
        )?;
        Ok(())
    }

    fn unset_variant(&mut self, key: &str, environment: &str) -> Result<(), StoreError> {
        let secret = self.get_secret(key)?;
        let environment = self.get_environment(environment)?;
        self.conn.execute(
            "DELETE FROM secret_variants WHERE secret_id = ?1 AND environment_id = ?2",
            params![secret.id.to_string(), environment.id.to_string()],
        )?;
        self.append_sync_operation(
            "variant.unset",
            json!({"key": key, "environment": environment.name}),
        )?;
        Ok(())
    }

    fn get_variant(&self, key: &str, environment: &str) -> Result<Option<String>, StoreError> {
        let secret = self.get_secret(key)?;
        let environment = self.get_environment(environment)?;
        let encrypted = self
            .conn
            .query_row(
                "SELECT ciphertext, nonce FROM secret_variants WHERE secret_id = ?1 AND environment_id = ?2",
                params![secret.id.to_string(), environment.id.to_string()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        encrypted
            .map(|(ciphertext, nonce)| decrypt_value(&self.key, &ciphertext, &nonce))
            .transpose()
            .map_err(StoreError::from)
    }

    fn assign_secret(&mut self, key: &str, project: &str) -> Result<(), StoreError> {
        let secret = self.get_secret(key)?;
        let project = self.get_project(project)?;
        self.conn.execute(
            "INSERT OR IGNORE INTO project_secrets (project_id, secret_id, created_at) VALUES (?1, ?2, ?3)",
            params![project.id.to_string(), secret.id.to_string(), now_string()],
        )?;
        self.append_sync_operation(
            "secret.assign",
            json!({"key": key, "project": project.name}),
        )?;
        Ok(())
    }

    fn unassign_secret(&mut self, key: &str, project: &str) -> Result<(), StoreError> {
        let secret = self.get_secret(key)?;
        let project = self.get_project(project)?;
        self.conn.execute(
            "DELETE FROM project_secrets WHERE project_id = ?1 AND secret_id = ?2",
            params![project.id.to_string(), secret.id.to_string()],
        )?;
        self.append_sync_operation(
            "secret.unassign",
            json!({"key": key, "project": project.name}),
        )?;
        Ok(())
    }

    fn variants_for_secret(&self, key: &str) -> Result<Vec<SecretVariant>, StoreError> {
        let secret = self.get_secret(key)?;
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, secret_id, environment_id, ciphertext, nonce, created_at, updated_at
            FROM secret_variants
            WHERE secret_id = ?1
            ORDER BY environment_id
            "#,
        )?;
        let rows = stmt.query_map([secret.id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;

        rows.map(|row| {
            let (id, secret_id, environment_id, ciphertext, nonce, created_at, updated_at) = row?;
            Ok(SecretVariant {
                id: parse_id(&id)?,
                secret_id: parse_id(&secret_id)?,
                environment_id: parse_id(&environment_id)?,
                value: decrypt_value(&self.key, &ciphertext, &nonce)?,
                created_at: parse_time(&created_at)?,
                updated_at: parse_time(&updated_at)?,
            })
        })
        .collect()
    }

    fn variant_count_for_environment(&self, environment: &str) -> Result<usize, StoreError> {
        let environment = self.get_environment(environment)?;
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM secret_variants WHERE environment_id = ?1",
            [environment.id.to_string()],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }
}

fn now_string() -> String {
    Utc::now().to_rfc3339()
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StoreError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| StoreError::InvalidTimestamp(value.to_string()))
}

fn parse_id(value: &str) -> Result<Id, StoreError> {
    Uuid::parse_str(value).map_err(|_| StoreError::InvalidId(value.to_string()))
}

fn payload_str<'a>(payload: &'a Value, key: &str) -> Result<&'a str, StoreError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| StoreError::InvalidSyncPayload(format!("missing string field {key}")))
}

fn payload_opt_str<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use envctl_core::{coverage, resolve};

    #[test]
    fn creates_entities_assigns_and_resolves() {
        let mut store = Store::open_memory_for_tests().unwrap();
        store.add_project("bowtieduck", None).unwrap();
        store.add_project("helmwave", None).unwrap();
        store.add_environment("dev", None).unwrap();
        store.add_secret("DATABASE_URL", Some("Main DB")).unwrap();
        store.assign_secret("DATABASE_URL", "bowtieduck").unwrap();
        store.assign_secret("DATABASE_URL", "helmwave").unwrap();
        store
            .set_variant("DATABASE_URL", "dev", "postgres://localhost/dev")
            .unwrap();

        let resolution = resolve(&store, "bowtieduck", "dev").unwrap();
        assert_eq!(resolution.secrets[0].key, "DATABASE_URL");
        assert_eq!(resolution.secrets[0].value, "postgres://localhost/dev");
    }

    #[test]
    fn missing_variant_blocks_resolution() {
        let mut store = Store::open_memory_for_tests().unwrap();
        store.add_project("bowtieduck", None).unwrap();
        store.add_environment("prod", None).unwrap();
        store.add_secret("REDIS_URL", None).unwrap();
        store.assign_secret("REDIS_URL", "bowtieduck").unwrap();

        let report = coverage(&store, "bowtieduck", "prod").unwrap();
        assert_eq!(report.missing_keys(), vec!["REDIS_URL"]);
        let err = resolve(&store, "bowtieduck", "prod").unwrap_err();
        assert!(err.to_string().contains("Cannot resolve secrets"));
    }

    #[test]
    fn deleting_environment_with_variants_requires_force() {
        let mut store = Store::open_memory_for_tests().unwrap();
        store.add_environment("dev", None).unwrap();
        store.add_secret("DATABASE_URL", None).unwrap();
        store
            .set_variant("DATABASE_URL", "dev", "postgres://localhost/dev")
            .unwrap();

        assert!(store.remove_environment("dev", false).is_err());
        store.remove_environment("dev", true).unwrap();
    }

    #[test]
    fn duplicate_secret_keys_are_rejected() {
        let mut store = Store::open_memory_for_tests().unwrap();
        store.add_secret("OPENAI_API_KEY", None).unwrap();
        let err = store.add_secret("OPENAI_API_KEY", None).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn mutating_operations_are_logged_for_sync() {
        let mut store = Store::open_memory_for_tests().unwrap();
        store.add_project("bowtieduck", None).unwrap();
        store.add_environment("prod", None).unwrap();
        store.add_secret("DATABASE_URL", None).unwrap();
        store
            .set_variant("DATABASE_URL", "prod", "postgres://localhost/prod")
            .unwrap();

        let operations = store.list_sync_operations().unwrap();
        assert_eq!(operations.len(), 4);
        let latest = operations.last().unwrap();
        assert_eq!(latest.kind, "variant.set");
        assert!(latest.payload.contains("DATABASE_URL"));
        assert!(latest.payload.contains("postgres://localhost/prod"));
    }

    #[test]
    fn imported_sync_operations_replay_into_empty_store() {
        let mut source = Store::open_memory_for_tests().unwrap();
        source.add_project("bowtieduck", None).unwrap();
        source.add_environment("prod", None).unwrap();
        source.add_secret("DATABASE_URL", None).unwrap();
        source.assign_secret("DATABASE_URL", "bowtieduck").unwrap();
        source
            .set_variant("DATABASE_URL", "prod", "postgres://localhost/prod")
            .unwrap();

        let operations = source.list_sync_operations().unwrap();
        let mut target = Store::open_memory_for_tests().unwrap();
        let imported = target.import_sync_operations(&operations).unwrap();

        assert_eq!(imported, operations.len());
        let resolution = resolve(&target, "bowtieduck", "prod").unwrap();
        assert_eq!(resolution.secrets[0].key, "DATABASE_URL");
        assert_eq!(resolution.secrets[0].value, "postgres://localhost/prod");
        assert_eq!(target.import_sync_operations(&operations).unwrap(), 0);
    }

    #[test]
    fn older_imported_variant_does_not_overwrite_newer_local_variant() {
        let mut source = Store::open_memory_for_tests().unwrap();
        source.add_project("bowtieduck", None).unwrap();
        source.add_environment("prod", None).unwrap();
        source.add_secret("DATABASE_URL", None).unwrap();
        source
            .set_variant("DATABASE_URL", "prod", "postgres://old")
            .unwrap();
        let operations = source.list_sync_operations().unwrap();

        let mut target = Store::open_memory_for_tests().unwrap();
        target.add_project("bowtieduck", None).unwrap();
        target.add_environment("prod", None).unwrap();
        target.add_secret("DATABASE_URL", None).unwrap();
        target
            .set_variant("DATABASE_URL", "prod", "postgres://new")
            .unwrap();

        target.import_sync_operations(&operations).unwrap();
        assert_eq!(
            target.get_variant("DATABASE_URL", "prod").unwrap().unwrap(),
            "postgres://new"
        );
    }
}
