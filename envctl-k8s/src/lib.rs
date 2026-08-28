use anyhow::{Context, Result, anyhow};
use envctl_core::{DomainError, SecretRegistry, resolve};
use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretManifestOptions {
    pub name: String,
    pub namespace: String,
}

pub fn render_secret<R>(
    registry: &R,
    project: &str,
    environment: &str,
    options: &SecretManifestOptions,
) -> Result<String>
where
    R: SecretRegistry,
    R::Error: From<DomainError> + std::error::Error + Send + Sync + 'static,
{
    let resolution = resolve(registry, project, environment)?;
    let values = resolution.into_env_map();
    Ok(render_secret_from_map(
        project,
        environment,
        &values,
        options,
    ))
}

pub fn render_secret_from_map(
    project: &str,
    environment: &str,
    values: &BTreeMap<String, String>,
    options: &SecretManifestOptions,
) -> String {
    let mut out = String::new();
    out.push_str("apiVersion: v1\n");
    out.push_str("kind: Secret\n");
    out.push_str("metadata:\n");
    out.push_str(&format!("  name: {}\n", yaml_scalar(&options.name)));
    out.push_str(&format!(
        "  namespace: {}\n",
        yaml_scalar(&options.namespace)
    ));
    out.push_str("  labels:\n");
    out.push_str("    app.kubernetes.io/managed-by: envctl\n");
    out.push_str("  annotations:\n");
    out.push_str(&format!(
        "    envctl.io/project: {}\n",
        yaml_scalar(project)
    ));
    out.push_str(&format!(
        "    envctl.io/environment: {}\n",
        yaml_scalar(environment)
    ));
    out.push_str("type: Opaque\n");
    out.push_str("stringData:\n");
    for (key, value) in values {
        out.push_str(&format!("  {}: {}\n", yaml_key(key), yaml_scalar(value)));
    }
    out
}

pub fn kubectl_apply(manifest: &str) -> Result<()> {
    let mut child = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to spawn kubectl")?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to open kubectl stdin"))?;
    stdin
        .write_all(manifest.as_bytes())
        .context("failed to write manifest to kubectl")?;
    drop(stdin);

    let status = child.wait().context("failed to wait for kubectl")?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("kubectl apply failed with status {status}"))
    }
}

fn yaml_key(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
    {
        value.to_string()
    } else {
        yaml_scalar(value)
    }
}

fn yaml_scalar(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_deterministic_secret_yaml() {
        let mut values = BTreeMap::new();
        values.insert("REDIS_URL".to_string(), "redis://localhost".to_string());
        values.insert(
            "DATABASE_URL".to_string(),
            "postgres://localhost/dev".to_string(),
        );

        let manifest = render_secret_from_map(
            "app",
            "prod",
            &values,
            &SecretManifestOptions {
                name: "app-secrets".to_string(),
                namespace: "prod".to_string(),
            },
        );

        assert!(manifest.contains("kind: Secret"));
        assert!(manifest.contains("  DATABASE_URL: \"postgres://localhost/dev\""));
        assert!(manifest.find("DATABASE_URL").unwrap() < manifest.find("REDIS_URL").unwrap());
    }
}
