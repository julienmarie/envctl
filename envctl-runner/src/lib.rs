use std::collections::BTreeMap;
use std::process::{Command, ExitStatus};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("No command provided after --.\nUsage: envctl run <project> <env> -- <cmd>")]
    EmptyCommand,
    #[error("failed to spawn command: {0}")]
    Spawn(#[from] std::io::Error),
}

pub fn run_with_env(
    command: &[String],
    env: &BTreeMap<String, String>,
) -> Result<ExitStatus, RunnerError> {
    let (program, args) = command.split_first().ok_or(RunnerError::EmptyCommand)?;
    Command::new(program)
        .args(args)
        .envs(env)
        .status()
        .map_err(RunnerError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_command() {
        let env = BTreeMap::new();
        let err = run_with_env(&[], &env).unwrap_err();
        assert!(err.to_string().contains("No command provided"));
    }
}
