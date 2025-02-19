use clap::Parser;
use signature_prover_lib::LogFormat;
use std::path::PathBuf;

/// Server CLI args
#[derive(Parser, Debug)]
pub struct ServerArgs {
    #[arg(long, default_value = "127.0.0.1")]
    pub ip: String,

    #[arg(long, default_value_t = 8000)]
    pub port: u16,

    /// Directory that contains the proving keys and verifying keys.
    #[arg(long)]
    pub data_dir: PathBuf,

    /// Directory that must contain required KZG trusted setup files.
    #[arg(long)]
    pub params_dir: PathBuf,

    #[arg(long = "log-format", value_name = "FORMAT", default_value_t = LogFormat::Terminal)]
    pub log_format: LogFormat,

    /// Path to the config toml file
    #[arg(long)]
    pub config_path: PathBuf,
}
