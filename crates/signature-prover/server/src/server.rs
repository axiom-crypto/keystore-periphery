use std::{
    collections::HashMap,
    marker::PhantomData,
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::{
    error::SignatureProverError,
    keystore_types::{KeystoreAccount, L2Transaction, RollupTx},
    parse_tx, tx_with_proofs, AccountAuthInputs, AuthInputs, AuthRequest, AuthRequestStatus,
    KeystoreAccountWithData, ServerArgs, SignatureProverApiServer, SponsorAuthState,
    SponsoredAuthInputs, SponsoredAuthRequest, TimestampedEntry,
};
use crate::{
    validator::{SignatureProverInputValidator, SignatureProverValidator},
    AuthInputsDecoder,
};
use alloy_primitives::{hex, keccak256, Bytes, FixedBytes, B256};
use jsonrpsee::{
    core::RpcResult,
    server::{middleware::http::ProxyGetRequestLayer, Server, ServerHandle},
};
use openvm_native_recursion::halo2::EvmProof;
use openvm_sdk::StdIn;
use serde::{Deserialize, Serialize};
use signature_prover_lib::ProverContext;
use snark_verifier_sdk::snark_verifier::halo2_base::utils::ScalarField;
use tracing::{debug, error, info, info_span, Instrument};

pub struct SignatureProverServer<I, D, V>
where
    I: Serialize + Send + Sync + 'static,
    D: AuthInputsDecoder<ServerAuthInput = I>,
    V: SignatureProverInputValidator<ServerAuthInput = I>,
{
    auth_requests: Arc<RwLock<HashMap<B256, TimestampedEntry<AuthRequestStatus>>>>,
    sponsor_auth_requests: Arc<RwLock<HashMap<B256, TimestampedEntry<SponsorAuthState>>>>,
    prover_context: Arc<ProverContext>,
    auth_inputs_decoder: D,
    validator: SignatureProverValidator<I, D, V>,
    sponsor: Option<KeystoreAccountWithData>,
    _marker: PhantomData<I>,
}

impl<I, D, V> SignatureProverServer<I, D, V>
where
    I: Serialize + Send + Sync + 'static,
    V: SignatureProverInputValidator<ServerAuthInput = I>,
    D: AuthInputsDecoder<ServerAuthInput = I>,
{
    fn start_cleanup_worker(
        auth_requests: Arc<RwLock<HashMap<B256, TimestampedEntry<AuthRequestStatus>>>>,
        sponsor_auth_requests: Arc<RwLock<HashMap<B256, TimestampedEntry<SponsorAuthState>>>>,
    ) {
        info!("Starting cleanup worker");
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // every hour
            loop {
                interval.tick().await;
                let max_age = Duration::from_secs(24 * 3600); // 1 day

                // Clean auth requests
                let mut requests = auth_requests.write().unwrap();
                requests.retain(|hash, entry| {
                    let keep = !entry.is_expired(max_age);
                    if !keep {
                        info!(request_hash = %hash, "Cleaning up old auth request");
                    }
                    keep
                });

                // Clean sponsor auth requests

                let mut requests = sponsor_auth_requests.write().unwrap();
                requests.retain(|hash, entry| {
                    let keep = !entry.is_expired(max_age);
                    if !keep {
                        info!(request_hash = %hash, "Cleaning up old sponsor auth request");
                    }
                    keep
                });
            }
        });
    }

    pub fn initialize(
        auth_inputs_decoder: D,
        validator: SignatureProverValidator<I, D, V>,
        args: &ServerArgs,
        sponsor: Option<KeystoreAccountWithData>,
    ) -> Self {
        info!(?args, "Initializing SignatureProverServer");

        let prover_context =
            ProverContext::read(&args.data_dir, &args.params_dir).expect("failed to set up prover");

        SignatureProverServer {
            auth_requests: Arc::new(RwLock::new(HashMap::new())),
            sponsor_auth_requests: Arc::new(RwLock::new(HashMap::new())),
            prover_context: Arc::new(prover_context),
            auth_inputs_decoder,
            validator,
            sponsor,
            _marker: PhantomData,
        }
    }

    pub async fn start(self, args: &ServerArgs) -> eyre::Result<ServerHandle> {
        let addr = format!("{}:{}", args.ip, args.port);

        let service_builder = tower::ServiceBuilder::new()
            // Proxy `GET /health` requests to internal `system_health` method.
            .layer(ProxyGetRequestLayer::new("/health", "system_health")?)
            .timeout(Duration::from_secs(2));

        let server = Server::builder()
            .set_http_middleware(service_builder)
            .build(addr.clone())
            .await?;

        let auth_requests = Arc::clone(&self.auth_requests);
        let sponsor_auth_requests = Arc::clone(&self.sponsor_auth_requests);

        let mut module = self.into_rpc();
        module.register_method("system_health", |_, _, _| serde_json::json!("ok"))?;
        let handle = server.start(module);

        info!(%addr, "RPC server running");

        Self::start_cleanup_worker(auth_requests, sponsor_auth_requests);

        Ok(handle)
    }

    fn handle_request<F, T>(&self, f: F) -> RpcResult<T>
    where
        F: FnOnce() -> Result<T, SignatureProverError>,
    {
        match catch_unwind(AssertUnwindSafe(f)) {
            Ok(result) => result.map_err(Into::into),
            Err(_) => Err(SignatureProverError::Internal("RPC handler panic".into()).into()),
        }
    }
}

#[async_trait::async_trait]
impl<I, D, V> SignatureProverApiServer for SignatureProverServer<I, D, V>
where
    I: Serialize + Send + Sync + 'static,
    D: AuthInputsDecoder<ServerAuthInput = I>,
    V: SignatureProverInputValidator<ServerAuthInput = I>,
{
    async fn authenticate_transaction(
        &self,
        unauthenticated_transaction: Bytes,
        auth_inputs: AuthInputs,
    ) -> RpcResult<B256> {
        self.handle_request(|| {
            let request_hash = get_request_hash(
                &unauthenticated_transaction,
                &serde_json::to_vec(&auth_inputs).unwrap(),
            );

            info!(
                method = "keystore_authenticateTransaction",
                %request_hash,
                ?unauthenticated_transaction,
                ?auth_inputs,
                "Starting request"
            );

            if self
                .auth_requests
                .read()
                .unwrap()
                .contains_key(&request_hash)
            {
                info!(
                    %request_hash,
                    "we have already received this request, skip generating a new proof"
                );
                return Ok(request_hash);
            }

            let auth_request = self
                .validator
                .validate_auth_request(unauthenticated_transaction, auth_inputs)
                .map_err(|e| SignatureProverError::ValidationFailed(e.to_string()))?;

            self.auth_requests
                .write()
                .unwrap()
                .insert(request_hash, TimestampedEntry::new(Default::default()));

            let start = std::time::Instant::now();
            let prover_context = self.prover_context.clone();
            debug!(duration=?start.elapsed(), "Cloning prover_context");

            let auth_inputs_decoder = self.auth_inputs_decoder.clone();
            let auth_requests = self.auth_requests.clone();

            tokio::spawn(async move {
                let AuthRequest { tx, auth } = auth_request;

                let proof = gen_proof(auth_inputs_decoder, auth, &prover_context);

                match proof {
                    Ok(proof) => {
                        let proof_bytes = evm_proof_to_bytes(proof);
                        if let Some(auth_request) =
                            auth_requests.write().unwrap().get_mut(&request_hash)
                        {
                            let authenticated_tx = tx_with_proofs(tx, Some(proof_bytes), None).unwrap();
                            auth_request
                                .entry
                                .set_completed(authenticated_tx.into_tx_bytes());
                            info!(%request_hash, "Authentication request completed successfully");
                        } else {
                            error!(%request_hash, "Request hash not found in auth_requests");
                        }
                    }
                    Err(e) => {
                        if let Some(auth_request) =
                            auth_requests.write().unwrap().get_mut(&request_hash)
                        {
                            auth_request.entry.set_failed(e.to_string());
                            error!(%request_hash, error=?e, "Authentication request failed");
                        } else {
                            error!(%request_hash, "Request hash not found in auth_requests");
                        }
                    }
                }
            }.instrument(info_span!("user_proof_gen", %request_hash)));

            Ok(request_hash)
        })
    }

    async fn get_authentication_status(
        &self,
        request_hash: B256,
    ) -> RpcResult<Option<AuthRequestStatus>> {
        Ok(self
            .auth_requests
            .read()
            .unwrap()
            .get(&request_hash)
            .map(|timestamped| timestamped.entry.clone()))
    }

    async fn authenticate_sponsored_transaction(
        &self,
        unauthenticated_transaction: Bytes,
        auth_inputs: SponsoredAuthInputs,
    ) -> RpcResult<B256> {
        self.handle_request(|| {
            let request_hash =
                get_request_hash(&unauthenticated_transaction, &serde_json::to_vec(&auth_inputs).unwrap());

            info!(
                method = "keystore_authenticateSponsoredTransaction",
                %request_hash,
                ?unauthenticated_transaction,
                ?auth_inputs,
                "Starting request"
            );

            if self.sponsor_auth_requests.read().unwrap().contains_key(&request_hash) {
                info!(
                    %request_hash,
                    "we have already received this request, skip generating a new proof"
                );
                return Ok(request_hash);
            }

            // here we update the sponsor information in unauthenticated_transaction first
            // then sponsor auth inputs are added in validator
            // we should combine these two updates in the future
            let unauthenticated_transaction = if let SponsoredAuthInputs::SponsorAndProve { .. } = auth_inputs {
                let tx = parse_tx(unauthenticated_transaction)?;
                if let L2Transaction::Update(mut tx) = tx {
                    let sponsor = self.sponsor.as_ref().ok_or(SignatureProverError::ServerSponsorshipNotSupported)?;
                    tx.set_sponsor(sponsor.account.clone());
                    tx.into_tx_bytes()
                } else {
                    return Err(SignatureProverError::UnsupportedTransactionType);
                }
            } else {
                unauthenticated_transaction
            };

            let auth_request = self
                .validator
                .validate_sponsored_auth_request(unauthenticated_transaction, auth_inputs.clone())
                .map_err(|e| SignatureProverError::ValidationFailed(e.to_string()))?;

            let SponsoredAuthRequest {
                tx,
                sponsor_auth,
                user_auth,
            } = auth_request;

            self.sponsor_auth_requests.write().unwrap().insert(
                request_hash,
                TimestampedEntry::new(SponsorAuthState::new(tx, user_auth.is_none())),
            );

            let start = std::time::Instant::now();
            let prover_context = self.prover_context.clone();
            debug!(duration=?start.elapsed(), "Cloning prover_context");

            let auth_inputs_decoder = self.auth_inputs_decoder.clone();
            let auth_requests = self.sponsor_auth_requests.clone();

            tokio::spawn(async move {
                // sponsor proof
                let proof = gen_proof(auth_inputs_decoder, sponsor_auth, &prover_context);
                match proof {
                    Ok(proof) => {
                        let proof_bytes = evm_proof_to_bytes(proof);
                        if let Some(auth_request) =
                            auth_requests.write().unwrap().get_mut(&request_hash)
                        {
                            auth_request.entry.set_sponsor_proof(proof_bytes);
                            info!(%request_hash, "Sponsor proof generation completed successfully");
                        } else {
                            error!(%request_hash, "Request hash not found in auth_requests");
                        }
                    }
                    Err(e) => {
                        if let Some(auth_request) =
                            auth_requests.write().unwrap().get_mut(&request_hash)
                        {
                            auth_request.entry.set_error(e.to_string());
                            info!(%request_hash, error=?e, "Sponsor proof generation failed");
                        } else {
                            error!(%request_hash, "Request hash not found in auth_requests");
                        }
                    }
                }
            }.instrument(info_span!("sponsor_proof_gen", %request_hash)));

            match user_auth {
                Some(user_auth) => {
                    let start = std::time::Instant::now();
                    let prover_context = self.prover_context.clone();
                    debug!(duration=?start.elapsed(), "Cloning prover_context");

                    let auth_requests = self.sponsor_auth_requests.clone();
                    let auth_inputs_decoder = self.auth_inputs_decoder.clone();

                    tokio::spawn(async move {
                        let proof = gen_proof(auth_inputs_decoder, user_auth, &prover_context);

                        match proof {
                            Ok(proof) => {
                                let proof_bytes = evm_proof_to_bytes(proof);
                                if let Some(auth_request) =
                                    auth_requests.write().unwrap().get_mut(&request_hash)
                                {
                                    auth_request.entry.set_user_proof(proof_bytes);
                                    info!(%request_hash, "User proof generation completed successfully");
                                } else {
                                    error!(%request_hash, "Request hash not found in auth_requests");
                                }
                            }
                            Err(e) => {
                                if let Some(auth_request) =
                                    auth_requests.write().unwrap().get_mut(&request_hash)
                                {
                                    auth_request.entry.set_error(e.to_string());
                                    info!(%request_hash, error=?e, "User proof generation failed");
                                } else {
                                    error!(%request_hash, "Request hash not found in auth_requests");
                                }
                            }
                        }
                    }.instrument(info_span!("user_proof_gen", %request_hash)));
                }
                None => {
                    let user_proof = match auth_inputs {
                        SponsoredAuthInputs::ProveOnlySponsored { user_proof, .. } => {
                            user_proof
                        }
                        _ => panic!("Expected ProveOnlySponsored variant"),
                    };

                    if let Some(auth_request) = self.sponsor_auth_requests.write().unwrap().get_mut(&request_hash) {
                        auth_request.entry.set_user_proof(user_proof.to_vec());
                    } else {
                        error!(%request_hash, "Request hash not found in auth_requests");
                    }
                }
            }

            Ok(request_hash)
        })
    }

    async fn get_sponsored_authentication_status(
        &self,
        request_hash: B256,
    ) -> RpcResult<Option<AuthRequestStatus>> {
        let auth_request_status = self
            .sponsor_auth_requests
            .read()
            .unwrap()
            .get(&request_hash)
            .map(|timestamped: &TimestampedEntry<SponsorAuthState>| {
                timestamped.entry.clone().try_into().unwrap()
            });
        Ok(auth_request_status)
    }
}

fn get_request_hash(unauthenticated_transaction: &[u8], auth_inputs: &[u8]) -> B256 {
    let request_hash = keccak256(
        [
            keccak256(unauthenticated_transaction),
            keccak256(auth_inputs),
        ]
        .concat(),
    );
    B256::from(request_hash)
}

fn gen_proof(
    decoder: impl AuthInputsDecoder<ServerAuthInput: Serialize>,
    inputs: AccountAuthInputs,
    prover_context: &ProverContext,
) -> Result<EvmProof, SignatureProverError> {
    // guest program can panic when it fails to generate proof
    catch_unwind(AssertUnwindSafe(|| {
        let inputs = decoder
            .decode(inputs.auth_inputs, inputs.msg_hash)
            .map_err(|_| SignatureProverError::ProofGenerationFailed)?;
        let mut io = StdIn::default();
        io.write(&inputs);

        let evm_proof = prover_context.prover.generate_proof_for_evm(io);
        Ok(evm_proof)
    }))
    .unwrap_or(Err(SignatureProverError::ProofGenerationFailed))
}

/// Converts an EvmProof to a byte vector
fn evm_proof_to_bytes(proof: EvmProof) -> Vec<u8> {
    let EvmProof { proof, instances } = proof;
    let capacity = proof.len() + instances[0].len() * 32;
    let mut proof_bytes = Vec::with_capacity(capacity);
    instances[0].iter().for_each(|instance| {
        let mut bytes = instance.to_bytes_le();
        bytes.reverse();
        proof_bytes.extend(bytes);
    });

    proof_bytes.extend(proof);
    assert_eq!(proof_bytes.len(), capacity);
    proof_bytes
}

#[derive(Deserialize)]
struct ServerConfig {
    vkey: VkeyConfig,
    sponsor: Option<SponsorConfig>,
}

#[derive(Deserialize)]
struct VkeyConfig {
    #[serde(with = "hex::serde")]
    vkey: Bytes,
}

/// Sponsor will only use the vkey supported by this server
#[derive(Deserialize)]
struct SponsorConfig {
    #[serde(with = "hex::serde")]
    data: Bytes,
    #[serde(with = "hex::serde")]
    keystore_address: FixedBytes<32>,
}

/// load server config
/// returns (vkey, sponsor)
pub fn load_server_config(
    path: impl AsRef<Path>,
) -> eyre::Result<(Bytes, Option<KeystoreAccountWithData>)> {
    let contents = std::fs::read_to_string(path)?;
    let config: ServerConfig = toml::from_str(&contents)?;

    let sponsor = config.sponsor.map(|sponsor| {
        let account = KeystoreAccount::with_keystore_address(
            sponsor.keystore_address,
            keccak256(&sponsor.data),
            config.vkey.vkey.clone(),
        );
        KeystoreAccountWithData {
            account,
            data: sponsor.data,
        }
    });

    Ok((config.vkey.vkey, sponsor))
}
