use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use halo2_axiom::halo2curves::bn256::G1Affine;
use openvm_native_compiler::conversion::CompilerOptions;
use openvm_native_recursion::halo2::{utils::CacheHalo2ParamsReader, wrapper::EvmVerifier};
use openvm_sdk::{
    commit::AppExecutionCommit,
    config::{
        AggConfig, AggStarkConfig, AppConfig, Halo2Config, SdkVmConfig, DEFAULT_APP_LOG_BLOWUP,
        DEFAULT_INTERNAL_LOG_BLOWUP, DEFAULT_LEAF_LOG_BLOWUP, DEFAULT_ROOT_LOG_BLOWUP,
    },
    fs::{write_evm_verifier_to_file, write_object_to_file},
    keygen::{AggProvingKey, AppProvingKey},
    NonRootCommittedExe, Sdk,
};
use openvm_stark_sdk::config::FriParameters;
use openvm_transpiler::elf::Elf;
use signature_prover_guest::public_values::UpdateTxPublicValuesHandler;
use snark_utils::vkey::OnchainVerifyingKey;
use tracing::{debug, info, info_span};

use crate::{NUM_OUTPUT_PVS, NUM_USER_PUBLIC_VALUES_BYTES};

pub const DEFAULT_HALO2_OUTER_K: usize = 22;

#[derive(Clone)]
pub struct ProvingKeyData {
    pub app_committed_exe: NonRootCommittedExe,
    pub app_pk: AppProvingKey<SdkVmConfig>,
    pub agg_pk: AggProvingKey,
    pub onchain_vk: OnchainVerifyingKey<G1Affine>,
    pub evm_verifier: EvmVerifier,
}

/// Given the program RISC-V ELF, generates the
/// app and aggregation proving keys and the on-chain verifying key.
///
/// Default values can be provided for most fields in `app_config` and `agg_config` unless special tuning is necessary.
pub fn keygen(
    program_elf: Elf,
    app_vm_config: SdkVmConfig,
    args: &KeygenArgs,
) -> eyre::Result<ProvingKeyData> {
    let sdk = Sdk;

    let app_config = args.app_config(app_vm_config);
    let exe = sdk.transpile(program_elf, app_config.app_vm_config.transpiler())?;

    let committed_exe = sdk.commit_app_exe(app_config.app_fri_params.fri_params, exe)?;

    let app_pk = info_span!("App keygen").in_scope(|| sdk.app_keygen(app_config.clone()))?;

    // Check for required KZG parameter files before running
    let params_dir = &args.params_dir;
    for n in 10..=23 {
        let srs_path = params_dir.join(format!("kzg_bn254_{}.srs", n));
        if !srs_path.exists() {
            panic!("Missing KZG parameter file: {}\n", srs_path.display());
        }
    }
    let params_reader = CacheHalo2ParamsReader::new(params_dir);
    let commits = AppExecutionCommit::compute(
        &app_pk.app_vm_pk.vm_config,
        &committed_exe,
        &app_pk.leaf_committed_exe,
    );
    let pv_handler = UpdateTxPublicValuesHandler {
        exe_commit: commits.exe_commit_to_bn254(),
        leaf_verifier_commit: commits.app_config_commit_to_bn254(),
    };
    let agg_config = args.agg_config();
    let agg_pk = info_span!("Agg keygen")
        .in_scope(|| sdk.agg_keygen(agg_config, &params_reader, Some(&pv_handler)))?;

    let pinning_metadata = &agg_pk.halo2_pk.verifier.pinning.metadata;
    debug!(?pinning_metadata, "Pinning metadata");
    let wrapper_metadata = &agg_pk.halo2_pk.wrapper.pinning.metadata;
    debug!(?wrapper_metadata, "Wrapper metadata");

    info!("Generating verifier contract...");
    let verifier = sdk.generate_snark_verifier_contract(&params_reader, &agg_pk)?;

    let snark_vk = agg_pk.halo2_pk.wrapper.pinning.pk.get_vk();
    let onchain_vk = OnchainVerifyingKey::from_vk(snark_vk, NUM_OUTPUT_PVS, true)?;

    let app_committed_exe = Arc::unwrap_or_clone(committed_exe);
    info!("Keygen finished");
    let data = ProvingKeyData {
        app_committed_exe,
        app_pk,
        agg_pk,
        onchain_vk,
        evm_verifier: verifier,
    };
    Ok(data)
}

impl ProvingKeyData {
    /// Writes everything to file system in `data_dir`.
    pub fn write(self, data_dir: impl AsRef<Path>) -> eyre::Result<()> {
        let data_dir = data_dir.as_ref();

        write_object_to_file(data_dir.join("app.committed_exe"), self.app_committed_exe)?;
        // Currently can't find a unique identifier for agg pk, so use app.pk and agg.pk as file name
        let pk_path = data_dir.join("app.pk");
        info!(path = ?pk_path, "Writing app pk");
        write_object_to_file(pk_path, self.app_pk)?;

        let pk_path = data_dir.join("agg.pk");
        info!(path = ?pk_path, "Writing agg pk");
        write_object_to_file(pk_path, self.agg_pk)?;

        let sol_path = data_dir.join("verifier.sol");
        info!(path = ?sol_path, "Writing verifier contract");
        write_evm_verifier_to_file(self.evm_verifier, sol_path)?;

        // Write onchain vk to file and print it to console
        let vk_path = data_dir.join("zk_auth.vk");
        info!(path = ?vk_path, "Writing zk_auth vk");
        std::fs::write(vk_path, self.onchain_vk.write()?)?;
        info!("zk_auth vk: {:?}", hex::encode(self.onchain_vk.write()?));

        Ok(())
    }
}

#[derive(Parser, Clone, Debug)]
pub struct KeygenArgs {
    /// Directory where proving keys, verifying keys, and verifier contract will be written to.
    #[arg(long)]
    pub data_dir: PathBuf,

    /// Directory that must contain required KZG trusted setup files.
    #[arg(long)]
    pub params_dir: PathBuf,

    /// Application level log blowup
    #[arg(long, default_value_t = DEFAULT_APP_LOG_BLOWUP)]
    pub app_log_blowup: usize,

    /// Aggregation (leaf) level log blowup
    #[arg(long, default_value_t = DEFAULT_LEAF_LOG_BLOWUP)]
    pub leaf_log_blowup: usize,

    /// Internal level log blowup, default set by the benchmark
    #[arg(long, default_value_t = DEFAULT_INTERNAL_LOG_BLOWUP)]
    pub internal_log_blowup: usize,

    /// Root level log blowup
    #[arg(long, default_value_t = DEFAULT_ROOT_LOG_BLOWUP)]
    pub root_log_blowup: usize,

    /// Configures the halo2 outer circuit to have `2^halo2_outer_k` rows.
    #[arg(long, default_value_t = DEFAULT_HALO2_OUTER_K)]
    pub halo2_outer_k: usize,

    /// Circuits are built with additional instrumentation for profiling.
    /// **Note:** this changes the proving and verifying keys.
    #[arg(long)]
    pub profiling: bool,
}

impl KeygenArgs {
    pub fn app_config(&self, mut app_vm_config: SdkVmConfig) -> AppConfig<SdkVmConfig> {
        app_vm_config.system.config.profiling = self.profiling;
        AppConfig {
            app_fri_params: FriParameters::standard_with_100_bits_conjectured_security(
                self.app_log_blowup,
            )
            .into(),
            app_vm_config,
            leaf_fri_params: FriParameters::standard_with_100_bits_conjectured_security(
                self.leaf_log_blowup,
            )
            .into(),
            compiler_options: CompilerOptions {
                enable_cycle_tracker: self.profiling,
                ..Default::default()
            },
        }
    }

    pub fn agg_config(&self) -> AggConfig {
        let [leaf_fri_params, internal_fri_params, root_fri_params] = [
            self.leaf_log_blowup,
            self.internal_log_blowup,
            self.root_log_blowup,
        ]
        .map(FriParameters::standard_with_100_bits_conjectured_security);

        AggConfig {
            agg_stark_config: AggStarkConfig {
                leaf_fri_params,
                internal_fri_params,
                root_fri_params,
                profiling: self.profiling,
                compiler_options: CompilerOptions {
                    enable_cycle_tracker: self.profiling,
                    ..Default::default()
                },
                root_max_constraint_degree: root_fri_params.max_constraint_degree(),
                max_num_user_public_values: NUM_USER_PUBLIC_VALUES_BYTES,
            },
            halo2_config: Halo2Config {
                verifier_k: self.halo2_outer_k,
                wrapper_k: None,
                profiling: self.profiling,
            },
        }
    }
}
