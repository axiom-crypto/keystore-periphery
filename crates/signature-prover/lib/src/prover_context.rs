use std::{path::Path, sync::Arc};

use eyre::Ok;
use openvm_native_recursion::halo2::utils::CacheHalo2ParamsReader;
use openvm_sdk::{
    config::SdkVmConfig,
    fs::{read_agg_pk_from_file, read_app_pk_from_file, read_object_from_file},
    keygen::AppProvingKey,
    prover::ContinuationProver,
    NonRootCommittedExe,
};
use tracing::{debug, info, instrument};

/// This struct holds the data (proving keys, committed program exe) about the
/// signature prover circuit in memory for use to generate signature proofs.
pub struct ProverContext {
    pub prover: ContinuationProver<SdkVmConfig>,
}

// SAFETY: ContinuationProver is Send and Sync. The only use of
// Rc, which prevents automatic implementations of Send + Sync, is
// in PhantomData within Halo2VerifierProvingKey DslOperations
unsafe impl Send for ProverContext {}
unsafe impl Sync for ProverContext {}

impl ProverContext {
    /// Constructor for [ProverContext] that reads necessary data from disk.
    /// The file names much match those in [ProvingKeyData::write](super::keygen::ProvingKeyData::write).
    #[instrument(skip_all)]
    pub fn read(
        data_dir: impl AsRef<Path>,
        kzg_params_dir: impl AsRef<Path>,
    ) -> eyre::Result<Self> {
        let data_dir = data_dir.as_ref();
        let params_dir = kzg_params_dir.as_ref();
        debug!(?data_dir);
        debug!(?params_dir);

        let committed_exe_path = data_dir.join("app.committed_exe");
        let app_committed_exe: NonRootCommittedExe = read_object_from_file(&committed_exe_path)?;

        let app_pk_path = data_dir.join("app.pk");
        let app_pk: AppProvingKey<SdkVmConfig> = read_app_pk_from_file(app_pk_path)?;

        let halo2_params_reader = CacheHalo2ParamsReader::new(params_dir);

        info!("Loading aggregate proving key");
        let agg_pk_path = data_dir.join("agg.pk");
        let start = std::time::Instant::now();
        let agg_pk = read_agg_pk_from_file(agg_pk_path)?;
        info!(duration = ?start.elapsed(), "Finished loading aggregate proving key");

        let prover = ContinuationProver::new(
            &halo2_params_reader,
            Arc::new(app_pk),
            Arc::new(app_committed_exe),
            agg_pk,
        );

        Ok(Self { prover })
    }
}
