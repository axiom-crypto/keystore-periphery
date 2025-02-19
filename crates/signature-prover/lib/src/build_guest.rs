use std::path::PathBuf;

use clap::Parser;
use eyre::Result;
use openvm_build::{GuestOptions, TargetFilter};
use openvm_sdk::Sdk;
use openvm_transpiler::elf::Elf;

/// Command line arguments for building an OpenVM guest program.
/// This is a subset of the functionality of `cargo-openvm`, provided
/// both for convenience and to ensure that the OpenVM version is consistent
/// between the guest and server.
#[derive(Clone, Parser)]
pub struct BuildGuestArgs {
    #[arg(
        long,
        help = "Path to the directory containing the Cargo.toml file for the guest code (relative to the current directory)"
    )]
    pub manifest_dir: PathBuf,

    #[arg(long, help = "Path to the target directory")]
    pub target_dir: Option<PathBuf>,

    #[arg(long, value_delimiter = ',', help = "Feature flags passed to cargo")]
    pub features: Vec<String>,

    /// Name of the binary to build
    pub bin: String,

    #[arg(long, default_value = "release", help = "Cargo build profile")]
    pub profile: String,
}

impl BuildGuestArgs {
    /// Builds the guest program and returns the path to the ELF file.
    pub fn build(&self) -> Result<Elf> {
        println!("[openvm] Building the package...");
        let target_filter = TargetFilter {
            name: self.bin.clone(),
            kind: "bin".to_string(),
        };
        let mut guest_options = GuestOptions::default()
            .with_features(self.features.clone())
            .with_profile(self.profile.clone());
        guest_options.target_dir = self.target_dir.clone();
        let sdk = Sdk;
        sdk.build(guest_options, &self.manifest_dir, &Some(target_filter))
    }
}
