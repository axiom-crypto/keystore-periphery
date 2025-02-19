use std::{
    env::temp_dir,
    path::{Path, PathBuf},
};

use openvm_native_recursion::halo2::EvmProof;
use openvm_sdk::{
    config::{
        SdkVmConfig, DEFAULT_APP_LOG_BLOWUP, DEFAULT_INTERNAL_LOG_BLOWUP, DEFAULT_LEAF_LOG_BLOWUP,
        DEFAULT_ROOT_LOG_BLOWUP,
    },
    Sdk, StdIn,
};
use openvm_stark_sdk::{
    bench::run_with_metric_collection, openvm_stark_backend::p3_field::PrimeField32,
};
use openvm_transpiler::elf::Elf;
use serde::Serialize;

use crate::{
    build_guest::BuildGuestArgs,
    keygen::{keygen, KeygenArgs, DEFAULT_HALO2_OUTER_K},
    ProverContext,
};

/// A tester where we use default configuration args whenever possible
pub struct SignatureProverTester {
    pub guest_manifest_dir: PathBuf,
    pub guest_program_name: String,
    pub app_vm_config: SdkVmConfig,
    pub guest_features: Vec<String>,
}

impl SignatureProverTester {
    pub fn new(
        guest_manifest_dir: PathBuf,
        guest_program_name: String,
        app_vm_config: SdkVmConfig,
    ) -> Self {
        Self {
            guest_manifest_dir,
            guest_program_name,
            app_vm_config,
            guest_features: vec![],
        }
    }

    pub fn build_guest_args(&self) -> BuildGuestArgs {
        BuildGuestArgs {
            manifest_dir: self.guest_manifest_dir.clone(),
            target_dir: None,
            features: self.guest_features.clone(),
            bin: self.guest_program_name.clone(),
            profile: "release".to_string(),
        }
    }

    pub fn keygen_args(&self, data_dir: PathBuf, params_dir: PathBuf) -> KeygenArgs {
        KeygenArgs {
            data_dir,
            params_dir,
            app_log_blowup: DEFAULT_APP_LOG_BLOWUP,
            leaf_log_blowup: DEFAULT_LEAF_LOG_BLOWUP,
            internal_log_blowup: DEFAULT_INTERNAL_LOG_BLOWUP,
            root_log_blowup: DEFAULT_ROOT_LOG_BLOWUP,
            halo2_outer_k: DEFAULT_HALO2_OUTER_K,
            profiling: false,
        }
    }

    fn get_elf(&self) -> eyre::Result<Elf> {
        let build_args = self.build_guest_args();
        build_args.build()
    }

    /// Test executing the program, without any proving.
    /// Returns the user public values, currently as u8 bytes.
    pub fn test_execute<I: Serialize>(&self, input: I) -> eyre::Result<Vec<u8>> {
        let sdk = Sdk;
        let elf = self.get_elf()?;
        let exe = sdk.transpile(elf, self.app_vm_config.transpiler())?;
        // Run the program
        let mut io = StdIn::default();
        io.write(&input);
        let public_values = sdk.execute(exe, self.app_vm_config.clone(), io.clone())?;
        let pvs = public_values
            .iter()
            .map(|x| x.as_canonical_u32().try_into().unwrap())
            .collect();
        Ok(pvs)
    }

    /// Test generating proof and verifying it on EVM verifier smart contract.
    pub fn test_evm<I: Serialize>(
        &self,
        input: I,
        kzg_params_dir: impl AsRef<Path>,
    ) -> eyre::Result<EvmProof> {
        let sdk = Sdk;
        let elf = self.get_elf()?;

        let mut io = StdIn::default();
        io.write(&input);

        let data_dir = temp_dir();
        let keygen_args = self.keygen_args(
            data_dir.to_path_buf(),
            kzg_params_dir.as_ref().to_path_buf(),
        );

        run_with_metric_collection("OUTPUT_PATH", || -> eyre::Result<_> {
            let total_start = std::time::Instant::now();

            let pk_data = keygen(elf, self.app_vm_config.clone(), &keygen_args)?;
            let evm_verifier = pk_data.evm_verifier.clone();
            pk_data.write(&keygen_args.data_dir)?;

            let ctx = ProverContext::read(keygen_args.data_dir, keygen_args.params_dir)?;
            let proof = ctx.prover.generate_proof_for_evm(io);

            sdk.verify_evm_proof(&evm_verifier, &proof)?;

            metrics::gauge!("host_total_time_ms").set(total_start.elapsed().as_millis() as f64);

            Ok(proof)
        })
    }
}
