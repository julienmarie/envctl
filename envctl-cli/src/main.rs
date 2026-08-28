use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand};
use directories::ProjectDirs;
use envctl_core::{DomainError, SecretRegistry, coverage, resolve};
use envctl_k8s::{SecretManifestOptions, kubectl_apply, render_secret};
use envctl_runner::run_with_env;
use envctl_store::{Store, StoreError, SyncOperation};
use envctl_sync::{
    SyncBundle, WireOperation, create_pairing_ticket, init_key_file, load_or_create_device,
    read_bundle, read_key_file, write_bundle,
};
use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "envctl")]
#[command(version)]
#[command(about = "Local-first encrypted developer secret manager")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Open the terminal UI")]
    Tui,
    #[command(about = "Run a command with resolved project/environment secrets")]
    Run(RunArgs),
    #[command(about = "Check project/environment secret coverage")]
    Check(CheckArgs),
    #[command(about = "Show resolved secret status with values masked")]
    Resolve(ResolveArgs),
    #[command(subcommand, about = "Manage projects")]
    Project(ProjectCommand),
    #[command(subcommand, name = "env", about = "Manage environments")]
    Environment(EnvironmentCommand),
    #[command(subcommand, about = "Manage secrets")]
    Secret(SecretCommand),
    #[command(
        name = "import-dotenv",
        about = "Import a .env file into one project/environment"
    )]
    ImportDotenv(ImportDotenvArgs),
    #[command(subcommand, about = "Manage trusted-device sync")]
    Sync(SyncCommand),
    #[command(subcommand, about = "Render or apply Kubernetes secrets")]
    K8s(K8sCommand),
}

#[derive(Debug, Args)]
struct RunArgs {
    project: String,
    environment: String,
    #[arg(long)]
    check: bool,
    #[arg(required = false, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct CheckArgs {
    project: Option<String>,
    environment: Option<String>,
}

#[derive(Debug, Args)]
struct ResolveArgs {
    project: String,
    environment: String,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    List,
    Add {
        name: String,
    },
    Rename {
        old: String,
        new: String,
    },
    Remove {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum EnvironmentCommand {
    List,
    Add {
        name: String,
    },
    Rename {
        old: String,
        new: String,
    },
    Remove {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SecretCommand {
    List,
    Add {
        key: String,
    },
    Rename {
        old: String,
        new: String,
    },
    Remove {
        key: String,
        #[arg(long)]
        yes: bool,
    },
    Set {
        key: String,
        environment: String,
    },
    Unset {
        key: String,
        environment: String,
    },
    Assign {
        key: String,
        project: String,
    },
    Unassign {
        key: String,
        project: String,
    },
    Describe {
        key: String,
        description: Option<String>,
    },
}

#[derive(Debug, Args)]
struct ImportDotenvArgs {
    project: String,
    environment: String,
    path: PathBuf,
    #[arg(long, help = "Allow overwriting existing variants")]
    yes: bool,
}

#[derive(Debug, Subcommand)]
enum SyncCommand {
    #[command(about = "Initialize the local sync root key")]
    Init(SyncKeyArgs),
    #[command(about = "Create a short-lived pairing ticket")]
    Pair,
    #[command(about = "Join using a pairing code and sync key")]
    Join(SyncJoinArgs),
    #[command(about = "Show local sync status")]
    Status,
    #[command(about = "Export encrypted operations to a portable sync bundle")]
    Export(SyncBundleArgs),
    #[command(about = "Import encrypted operations from a portable sync bundle")]
    Import(SyncBundleArgs),
    #[command(about = "Exchange pending operations with peers")]
    Now,
    #[command(about = "Run sync loop in the foreground")]
    Daemon,
}

#[derive(Debug, Args)]
struct SyncKeyArgs {
    #[arg(long)]
    key_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SyncJoinArgs {
    pairing_code: String,
    #[arg(long)]
    key_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct SyncBundleArgs {
    path: PathBuf,
    #[arg(long)]
    key_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum K8sCommand {
    #[command(about = "Render a Kubernetes Secret manifest")]
    Render(K8sSecretArgs),
    #[command(about = "Apply a Kubernetes Secret through kubectl")]
    Apply(K8sSecretArgs),
}

#[derive(Debug, Args)]
struct K8sSecretArgs {
    project: String,
    environment: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    namespace: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            print_error(&err);
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        None | Some(Command::Tui) => {
            let store = Store::open_default()?;
            envctl_tui::run(store)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(command) => {
            let mut store = Store::open_default()?;
            handle_command(&mut store, command)
        }
    }
}

fn handle_command(store: &mut Store, command: Command) -> Result<ExitCode> {
    match command {
        Command::Tui => unreachable!(),
        Command::Run(args) => run_command(store, args),
        Command::Check(args) => check_command(store, args),
        Command::Resolve(args) => {
            print_coverage(store, &args.project, &args.environment)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Project(command) => project_command(store, command),
        Command::Environment(command) => environment_command(store, command),
        Command::Secret(command) => secret_command(store, command),
        Command::ImportDotenv(args) => import_dotenv(store, args),
        Command::Sync(command) => sync_command(store, command),
        Command::K8s(command) => k8s_command(store, command),
    }
}

fn run_command(store: &Store, args: RunArgs) -> Result<ExitCode> {
    if args.check {
        let complete = print_coverage(store, &args.project, &args.environment)?;
        return Ok(exit_for_complete(complete));
    }

    if args.command.is_empty() {
        return Err(DomainError::EmptyCommand.into());
    }

    let resolution = resolve(store, &args.project, &args.environment)?;
    let env = resolution.into_env_map();
    let status = run_with_env(&args.command, &env)?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn check_command(store: &Store, args: CheckArgs) -> Result<ExitCode> {
    match (args.project, args.environment) {
        (Some(project), Some(environment)) => {
            let complete = print_coverage(store, &project, &environment)?;
            Ok(exit_for_complete(complete))
        }
        (None, None) => {
            let mut all_complete = true;
            let projects = store.list_projects()?;
            let environments = store.list_environments()?;
            for project in projects {
                for environment in &environments {
                    let report = coverage(store, &project.name, &environment.name)?;
                    if !report.is_complete() {
                        all_complete = false;
                        let missing = report.missing_keys().join(", ");
                        println!(
                            "{}\t{}\t{}",
                            report.project.name, report.environment.name, missing
                        );
                    }
                }
            }
            if all_complete {
                println!("All project/environment combinations are complete.");
            }
            Ok(exit_for_complete(all_complete))
        }
        _ => Err(anyhow!(
            "Usage: envctl check or envctl check <project> <environment>"
        )),
    }
}

fn project_command(store: &mut Store, command: ProjectCommand) -> Result<ExitCode> {
    match command {
        ProjectCommand::List => {
            for project in store.list_projects()? {
                println!(
                    "{}\t{} secrets",
                    project.name,
                    project.assigned_secret_ids.len()
                );
            }
        }
        ProjectCommand::Add { name } => {
            store.add_project(&name, None)?;
            println!("Added project \"{}\".", name);
        }
        ProjectCommand::Rename { old, new } => {
            store.rename_project(&old, &new)?;
            println!("Renamed project \"{}\" to \"{}\".", old, new);
        }
        ProjectCommand::Remove { name, yes } => {
            require_yes(yes, "project remove")?;
            store.remove_project(&name)?;
            println!("Removed project \"{}\".", name);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn environment_command(store: &mut Store, command: EnvironmentCommand) -> Result<ExitCode> {
    match command {
        EnvironmentCommand::List => {
            for environment in store.list_environments()? {
                let count = store.variant_count_for_environment(&environment.name)?;
                println!("{}\t{} variants", environment.name, count);
            }
        }
        EnvironmentCommand::Add { name } => {
            store.add_environment(&name, None)?;
            println!("Added environment \"{}\".", name);
        }
        EnvironmentCommand::Rename { old, new } => {
            store.rename_environment(&old, &new)?;
            println!("Renamed environment \"{}\" to \"{}\".", old, new);
        }
        EnvironmentCommand::Remove { name, yes } => {
            require_yes(yes, "env remove")?;
            store.remove_environment(&name, true)?;
            println!("Removed environment \"{}\".", name);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn secret_command(store: &mut Store, command: SecretCommand) -> Result<ExitCode> {
    match command {
        SecretCommand::List => {
            for secret in store.list_secrets()? {
                println!(
                    "{}\t{} projects",
                    secret.key,
                    secret.assigned_project_ids.len()
                );
            }
        }
        SecretCommand::Add { key } => {
            store.add_secret(&key, None)?;
            println!("Added secret \"{}\".", key);
        }
        SecretCommand::Rename { old, new } => {
            store.rename_secret(&old, &new)?;
            println!("Renamed secret \"{}\" to \"{}\".", old, new);
        }
        SecretCommand::Remove { key, yes } => {
            require_yes(yes, "secret remove")?;
            store.remove_secret(&key)?;
            println!("Removed secret \"{}\".", key);
        }
        SecretCommand::Set { key, environment } => {
            let value = read_secret_value(&key, &environment)?;
            store.set_variant(&key, &environment, &value)?;
            println!("Set \"{}\" for environment \"{}\".", key, environment);
        }
        SecretCommand::Unset { key, environment } => {
            store.unset_variant(&key, &environment)?;
            println!("Removed \"{}\" variant for \"{}\".", key, environment);
        }
        SecretCommand::Assign { key, project } => {
            store.assign_secret(&key, &project)?;
            println!("Assigned \"{}\" to \"{}\".", key, project);
        }
        SecretCommand::Unassign { key, project } => {
            store.unassign_secret(&key, &project)?;
            println!("Unassigned \"{}\" from \"{}\".", key, project);
        }
        SecretCommand::Describe { key, description } => {
            store.set_secret_description(&key, description.as_deref())?;
            println!("Updated description for \"{}\".", key);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn import_dotenv(store: &mut Store, args: ImportDotenvArgs) -> Result<ExitCode> {
    store.get_project(&args.project)?;
    store.get_environment(&args.environment)?;

    let mut imported = 0_usize;
    let iter = dotenvy::from_path_iter(&args.path)
        .with_context(|| format!("failed to read {}", args.path.display()))?;

    for item in iter {
        let (key, value) = item
            .with_context(|| format!("failed to parse dotenv entry in {}", args.path.display()))?;

        if store.get_secret(&key).is_err() {
            store.add_secret(&key, None)?;
        }

        if store.get_variant(&key, &args.environment)?.is_some() && !args.yes {
            return Err(anyhow!(
                "Variant \"{}\" for environment \"{}\" already exists. Re-run with --yes to overwrite.",
                key,
                args.environment
            ));
        }

        store.set_variant(&key, &args.environment, &value)?;
        store.assign_secret(&key, &args.project)?;
        imported += 1;
    }

    println!(
        "Imported {} secret(s) into project \"{}\" / environment \"{}\".",
        imported, args.project, args.environment
    );
    Ok(ExitCode::SUCCESS)
}

fn sync_command(store: &mut Store, command: SyncCommand) -> Result<ExitCode> {
    match command {
        SyncCommand::Init(args) => {
            let key_file = sync_key_path(args.key_file)?;
            init_key_file(&key_file)?;
            let device = load_or_create_device(&device_path()?)?;
            println!("Initialized sync key: {}", key_file.display());
            println!("Device id: {}", device.id);
        }
        SyncCommand::Pair => {
            let device = load_or_create_device(&device_path()?)?;
            let ticket = create_pairing_ticket(&device.id);
            println!("Pairing code: {}", ticket.code);
            println!("Device id: {}", ticket.device_id);
            println!("Share this code with the joining device while this device is online.");
        }
        SyncCommand::Join(args) => {
            let key_file = sync_key_path(args.key_file)?;
            let key = read_key_file(&key_file)?;
            let device = load_or_create_device(&device_path()?)?;
            println!("Joined trusted sync set as device {}.", device.id);
            println!("Using sync key: {}", key_file.display());
            println!("Accepted pairing code: {}", args.pairing_code);
            println!("Loaded {} bytes of sync key material.", key.len());
        }
        SyncCommand::Status => print_sync_status(store)?,
        SyncCommand::Export(args) => {
            let key_file = sync_key_path(args.key_file)?;
            let key = read_key_file(&key_file)?;
            let device = load_or_create_device(&device_path()?)?;
            let operations = store
                .list_sync_operations()?
                .into_iter()
                .map(operation_to_wire)
                .collect();
            write_bundle(
                &args.path,
                &key,
                &SyncBundle {
                    version: 1,
                    device_id: device.id,
                    operations,
                },
            )?;
            println!("Exported encrypted sync bundle: {}", args.path.display());
        }
        SyncCommand::Import(args) => {
            let key_file = sync_key_path(args.key_file)?;
            let key = read_key_file(&key_file)?;
            let bundle = read_bundle(&args.path, &key)?;
            let operations = bundle
                .operations
                .iter()
                .map(wire_to_operation)
                .collect::<Result<Vec<_>>>()?;
            let imported = store.import_sync_operations(&operations)?;
            println!(
                "Imported {} operation(s) from device {}.",
                imported, bundle.device_id
            );
        }
        SyncCommand::Now => {
            let status = store.sync_status()?;
            println!(
                "No P2P peers configured in this build. Use sync export/import to move {} local operation(s).",
                status.operation_count
            );
        }
        SyncCommand::Daemon => loop {
            print_sync_status(store)?;
            thread::sleep(Duration::from_secs(30));
        },
    }
    Ok(ExitCode::SUCCESS)
}

fn k8s_command(store: &Store, command: K8sCommand) -> Result<ExitCode> {
    match command {
        K8sCommand::Render(args) => {
            let manifest = render_k8s_secret(store, args)?;
            print!("{manifest}");
        }
        K8sCommand::Apply(args) => {
            let manifest = render_k8s_secret(store, args)?;
            kubectl_apply(&manifest)?;
            println!("Applied Kubernetes Secret.");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn render_k8s_secret(store: &Store, args: K8sSecretArgs) -> Result<String> {
    render_secret(
        store,
        &args.project,
        &args.environment,
        &SecretManifestOptions {
            name: args.name,
            namespace: args.namespace,
        },
    )
}

fn print_sync_status(store: &Store) -> Result<()> {
    let status = store.sync_status()?;
    println!("Operations: {}", status.operation_count);
    if let Some(operation) = status.latest_operation {
        println!(
            "Latest: {}\t{}\t{}",
            operation.created_at, operation.kind, operation.id
        );
    } else {
        println!("Latest: none");
    }
    Ok(())
}

fn operation_to_wire(operation: SyncOperation) -> WireOperation {
    WireOperation {
        id: operation.id.to_string(),
        kind: operation.kind,
        payload: operation.payload,
        created_at: operation.created_at.to_rfc3339(),
    }
}

fn wire_to_operation(operation: &WireOperation) -> Result<SyncOperation> {
    let created_at = DateTime::parse_from_rfc3339(&operation.created_at)
        .with_context(|| format!("invalid operation timestamp {}", operation.created_at))?
        .with_timezone(&Utc);
    Ok(SyncOperation {
        id: Uuid::parse_str(&operation.id)
            .with_context(|| format!("invalid operation id {}", operation.id))?,
        kind: operation.kind.clone(),
        payload: operation.payload.clone(),
        created_at,
    })
}

fn sync_key_path(path: Option<PathBuf>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path),
        None => Ok(config_dir()?.join("sync-root.key")),
    }
}

fn device_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("device.json"))
}

fn config_dir() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("ENVCTL_HOME") {
        return Ok(PathBuf::from(home));
    }
    ProjectDirs::from("", "", "envctl")
        .map(|dirs| dirs.config_dir().to_path_buf())
        .ok_or_else(|| anyhow!("could not resolve envctl config directory"))
}

fn print_coverage(store: &Store, project: &str, environment: &str) -> Result<bool> {
    let report = coverage(store, project, environment)?;
    println!(
        "Project: {}\nEnvironment: {}\n",
        report.project.name, report.environment.name
    );
    for item in &report.items {
        let status = if item.resolved { "resolved" } else { "missing" };
        println!("{}\t{}", item.key, status);
    }
    if report.items.is_empty() {
        println!("No secrets assigned.");
    }
    Ok(report.is_complete())
}

fn exit_for_complete(complete: bool) -> ExitCode {
    if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn require_yes(yes: bool, command: &str) -> Result<()> {
    if yes {
        Ok(())
    } else {
        Err(anyhow!(
            "Destructive command requires --yes: envctl {} ... --yes",
            command
        ))
    }
}

fn read_secret_value(key: &str, environment: &str) -> Result<String> {
    if io::stdin().is_terminal() {
        rpassword::prompt_password(format!("Value for {} [{}]: ", key, environment))
            .context("failed to read secret value")
    } else {
        let mut value = String::new();
        io::stdin().read_to_string(&mut value)?;
        Ok(value.trim_end_matches(['\r', '\n']).to_string())
    }
}

fn print_error(err: &anyhow::Error) {
    if let Some(store_error) = err.downcast_ref::<StoreError>() {
        print_store_error(store_error);
        return;
    }
    if let Some(domain_error) = err.downcast_ref::<DomainError>() {
        print_domain_error(domain_error);
        return;
    }
    eprintln!("{err}");
}

fn print_store_error(err: &StoreError) {
    match err {
        StoreError::Domain(domain) => print_domain_error(domain),
        _ => eprintln!("{err}"),
    }
}

fn print_domain_error(err: &DomainError) {
    match err {
        DomainError::MissingVariants {
            project,
            environment,
            missing_keys,
        } => {
            eprintln!(
                "Cannot resolve secrets for project \"{}\" in environment \"{}\".\n",
                project, environment
            );
            eprintln!("Missing environment variants:");
            for key in missing_keys {
                eprintln!("- {key}");
            }
        }
        _ => eprintln!("{err}"),
    }
}

#[allow(dead_code)]
fn _mask_map(map: &BTreeMap<String, String>) -> Vec<(String, String)> {
    map.keys()
        .map(|key| (key.clone(), "********".to_string()))
        .collect()
}
