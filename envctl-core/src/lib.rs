use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;

pub type Id = Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub id: Id,
    pub name: String,
    pub description: Option<String>,
    pub assigned_secret_ids: Vec<Id>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    pub id: Id,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    pub id: Id,
    pub key: String,
    pub description: Option<String>,
    pub assigned_project_ids: Vec<Id>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVariant {
    pub id: Id,
    pub secret_id: Id,
    pub environment_id: Id,
    pub value: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretCoverage {
    pub key: String,
    pub resolved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSecret {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub project: Project,
    pub environment: Environment,
    pub secrets: Vec<ResolvedSecret>,
}

impl Resolution {
    pub fn into_env_map(self) -> BTreeMap<String, String> {
        self.secrets
            .into_iter()
            .map(|secret| (secret.key, secret.value))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageReport {
    pub project: Project,
    pub environment: Environment,
    pub items: Vec<SecretCoverage>,
}

impl CoverageReport {
    pub fn missing_keys(&self) -> Vec<String> {
        self.items
            .iter()
            .filter(|item| !item.resolved)
            .map(|item| item.key.clone())
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.items.iter().all(|item| item.resolved)
    }
}

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Project \"{0}\" not found.")]
    ProjectNotFound(String),
    #[error("Environment \"{0}\" not found.")]
    EnvironmentNotFound(String),
    #[error("Secret \"{0}\" not found.")]
    SecretNotFound(String),
    #[error("Project \"{project}\" already exists.")]
    DuplicateProject { project: String },
    #[error("Environment \"{environment}\" already exists.")]
    DuplicateEnvironment { environment: String },
    #[error("Secret key \"{key}\" already exists.")]
    DuplicateSecret { key: String },
    #[error("Cannot resolve secrets for project \"{project}\" in environment \"{environment}\".")]
    MissingVariants {
        project: String,
        environment: String,
        missing_keys: Vec<String>,
    },
    #[error("No command provided after --.\nUsage: envctl run <project> <env> -- <cmd>")]
    EmptyCommand,
    #[error(
        "Cannot delete environment \"{environment}\" because it has {variant_count} variant(s)."
    )]
    EnvironmentHasVariants {
        environment: String,
        variant_count: usize,
    },
}

pub trait SecretRegistry {
    type Error;

    fn add_project(
        &mut self,
        name: &str,
        description: Option<&str>,
    ) -> Result<Project, Self::Error>;
    fn rename_project(&mut self, old_name: &str, new_name: &str) -> Result<Project, Self::Error>;
    fn remove_project(&mut self, name: &str) -> Result<(), Self::Error>;
    fn list_projects(&self) -> Result<Vec<Project>, Self::Error>;
    fn get_project(&self, name: &str) -> Result<Project, Self::Error>;

    fn add_environment(
        &mut self,
        name: &str,
        description: Option<&str>,
    ) -> Result<Environment, Self::Error>;
    fn rename_environment(
        &mut self,
        old_name: &str,
        new_name: &str,
    ) -> Result<Environment, Self::Error>;
    fn remove_environment(&mut self, name: &str, force: bool) -> Result<(), Self::Error>;
    fn list_environments(&self) -> Result<Vec<Environment>, Self::Error>;
    fn get_environment(&self, name: &str) -> Result<Environment, Self::Error>;

    fn add_secret(&mut self, key: &str, description: Option<&str>) -> Result<Secret, Self::Error>;
    fn rename_secret(&mut self, old_key: &str, new_key: &str) -> Result<Secret, Self::Error>;
    fn remove_secret(&mut self, key: &str) -> Result<(), Self::Error>;
    fn list_secrets(&self) -> Result<Vec<Secret>, Self::Error>;
    fn get_secret(&self, key: &str) -> Result<Secret, Self::Error>;
    fn set_secret_description(
        &mut self,
        key: &str,
        description: Option<&str>,
    ) -> Result<Secret, Self::Error>;
    fn set_variant(&mut self, key: &str, environment: &str, value: &str)
    -> Result<(), Self::Error>;
    fn unset_variant(&mut self, key: &str, environment: &str) -> Result<(), Self::Error>;
    fn get_variant(&self, key: &str, environment: &str) -> Result<Option<String>, Self::Error>;
    fn assign_secret(&mut self, key: &str, project: &str) -> Result<(), Self::Error>;
    fn unassign_secret(&mut self, key: &str, project: &str) -> Result<(), Self::Error>;
    fn variants_for_secret(&self, key: &str) -> Result<Vec<SecretVariant>, Self::Error>;
    fn variant_count_for_environment(&self, environment: &str) -> Result<usize, Self::Error>;
}

pub fn coverage<R>(
    registry: &R,
    project: &str,
    environment: &str,
) -> Result<CoverageReport, R::Error>
where
    R: SecretRegistry,
{
    let project_record = registry.get_project(project)?;
    let environment_record = registry.get_environment(environment)?;
    let mut items = Vec::new();

    for secret in registry.list_secrets()? {
        if !secret.assigned_project_ids.contains(&project_record.id) {
            continue;
        }

        let resolved = registry.get_variant(&secret.key, environment)?.is_some();
        items.push(SecretCoverage {
            key: secret.key,
            resolved,
        });
    }

    Ok(CoverageReport {
        project: project_record,
        environment: environment_record,
        items,
    })
}

pub fn resolve<R>(registry: &R, project: &str, environment: &str) -> Result<Resolution, R::Error>
where
    R: SecretRegistry,
    R::Error: From<DomainError>,
{
    let report = coverage(registry, project, environment)?;
    let missing_keys = report.missing_keys();
    if !missing_keys.is_empty() {
        return Err(DomainError::MissingVariants {
            project: report.project.name,
            environment: report.environment.name,
            missing_keys,
        }
        .into());
    }

    let mut secrets = Vec::new();
    for item in report.items {
        if let Some(value) = registry.get_variant(&item.key, environment)? {
            secrets.push(ResolvedSecret {
                key: item.key,
                value,
            });
        }
    }

    Ok(Resolution {
        project: report.project,
        environment: report.environment,
        secrets,
    })
}
