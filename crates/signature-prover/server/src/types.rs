use std::time::{Duration, Instant};

use crate::keystore_types::{
    KeystoreAccount, L2Transaction, RollupTx, TxDecode, UpdateTransaction,
};
use alloy_primitives::{Bytes, B256};
use serde::{Deserialize, Serialize};

use crate::error::SignatureProverError;

pub trait AuthInputsDecoder: Send + Sync + Clone + 'static {
    type Error: std::error::Error;

    type ServerAuthInput;

    fn decode(
        &self,
        auth_inputs: AuthInputs,
        msg_hash: B256,
    ) -> Result<Self::ServerAuthInput, Self::Error>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthInputs {
    /// Encoded `data`
    pub key_data: Bytes,
    /// Just authentication-related data
    pub auth_data: Bytes,
}

pub struct TimestampedEntry<T> {
    pub start_time: Instant,
    pub entry: T,
}

impl<T> TimestampedEntry<T> {
    pub fn new(entry: T) -> Self {
        Self {
            start_time: Instant::now(),
            entry,
        }
    }

    pub fn is_expired(&self, max_age: Duration) -> bool {
        Instant::now().duration_since(self.start_time) >= max_age
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SponsoredAuthInputs {
    #[serde(rename_all = "camelCase")]
    ProveSponsored {
        user_auth_inputs: AuthInputs,
        sponsor_auth_inputs: AuthInputs,
    },
    #[serde(rename_all = "camelCase")]
    ProveOnlySponsored {
        user_proof: Bytes,
        sponsor_auth_inputs: AuthInputs,
    },
    #[serde(rename_all = "camelCase")]
    SponsorAndProve { user_auth_inputs: AuthInputs },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub auth: AccountAuthInputs,
    pub tx: L2Transaction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsoredAuthRequest {
    pub sponsor_auth: AccountAuthInputs,
    pub user_auth: Option<AccountAuthInputs>,
    pub tx: L2Transaction,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub enum Status {
    #[default]
    Pending,
    Completed,
    Failed,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRequestStatus {
    status: Status,
    authenticated_transaction: Option<Bytes>,
    error: Option<String>,
}

impl AuthRequestStatus {
    fn new(
        status: Status,
        authenticated_transaction: Option<Bytes>,
        error: Option<String>,
    ) -> Self {
        Self {
            status,
            authenticated_transaction,
            error,
        }
    }

    pub fn status(&self) -> &Status {
        &self.status
    }

    pub fn into_authenticated_transaction(self) -> Option<Bytes> {
        self.authenticated_transaction
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn pending() -> Self {
        Self::new(Status::Pending, None, None)
    }

    pub fn completed(tx: Bytes) -> Self {
        Self::new(Status::Completed, Some(tx), None)
    }

    pub fn failed(error: impl Into<String>) -> Self {
        Self::new(Status::Failed, None, Some(error.into()))
    }

    pub fn set_pending(&mut self) {
        self.status = Status::Pending;
        self.authenticated_transaction = None;
        self.error = None;
    }

    pub fn set_completed(&mut self, tx: Bytes) {
        self.status = Status::Completed;
        self.authenticated_transaction = Some(tx);
        self.error = None;
    }

    pub fn set_failed(&mut self, error: impl Into<String>) {
        self.status = Status::Failed;
        self.authenticated_transaction = None;
        self.error = Some(error.into());
    }
}

#[derive(Clone)]
pub struct SponsorAuthState {
    tx: L2Transaction,
    sponsor_proof_only: bool,
    user_proof: Option<Vec<u8>>,
    sponsor_proof: Option<Vec<u8>>,
    error: Option<String>,
}

impl SponsorAuthState {
    pub fn new(tx: L2Transaction, sponsor_proof_only: bool) -> Self {
        Self {
            tx,
            sponsor_proof_only,
            user_proof: None,
            sponsor_proof: None,
            error: None,
        }
    }

    pub fn set_user_proof(&mut self, proof: Vec<u8>) {
        self.user_proof = Some(proof);
    }

    pub fn set_sponsor_proof(&mut self, proof: Vec<u8>) {
        self.sponsor_proof = Some(proof);
    }

    pub fn set_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
    }
}

impl TryFrom<SponsorAuthState> for AuthRequestStatus {
    type Error = SignatureProverError;

    fn try_from(state: SponsorAuthState) -> Result<Self, Self::Error> {
        if let Some(error) = state.error {
            return Err(SignatureProverError::Internal(error));
        }
        if state.sponsor_proof_only {
            if let Some(sponsor_proof) = state.sponsor_proof {
                let new_tx = tx_with_proofs(state.tx, None, Some(sponsor_proof))?;
                Ok(Self::completed(new_tx.into_tx_bytes()))
            } else {
                Ok(Self::pending())
            }
        } else if let (Some(sponsor_proof), Some(user_proof)) =
            (state.sponsor_proof, state.user_proof)
        {
            let new_tx = tx_with_proofs(state.tx, Some(user_proof), Some(sponsor_proof))?;
            Ok(Self::completed(new_tx.into_tx_bytes()))
        } else {
            Ok(Self::pending())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountAuthInputs {
    pub keystore_address: B256,
    pub account_data_hash: B256,
    pub msg_hash: B256,
    pub auth_inputs: AuthInputs,
}

impl AccountAuthInputs {
    pub fn new(account: KeystoreAccount, msg_hash: B256, auth_inputs: AuthInputs) -> Self {
        Self {
            keystore_address: account.keystore_address,
            account_data_hash: account.data_hash,
            msg_hash,
            auth_inputs,
        }
    }
}

pub fn tx_with_proofs(
    tx: L2Transaction,
    user_proof: Option<Vec<u8>>,
    sponsor_proof: Option<Vec<u8>>,
) -> Result<L2Transaction, SignatureProverError> {
    match tx {
        L2Transaction::Deposit(_tx) => Err(SignatureProverError::UnsupportedTransactionType),
        L2Transaction::Withdraw(_tx) => Err(SignatureProverError::UnsupportedTransactionType),
        L2Transaction::Update(tx) => {
            let user_proof = if let Some(user_proof) = user_proof {
                user_proof.into()
            } else {
                tx.user_proof().clone()
            };

            let sponsor_proof = if let Some(sponsor_proof) = sponsor_proof {
                sponsor_proof.into()
            } else {
                tx.sponsor_proof().clone()
            };

            let new_tx = UpdateTransaction::new(
                tx.is_l1_initiated(),
                tx.nonce(),
                tx.fee_per_gas().clone(),
                tx.l1_initiated_nonce().clone(),
                tx.new_user_data().clone(),
                tx.new_user_vkey().clone(),
                tx.user_acct().clone(),
                user_proof,
                tx.sponsor_acct_bytes().clone(),
                sponsor_proof,
            );
            Ok(L2Transaction::Update(new_tx))
        }
    }
}

pub(crate) fn parse_tx(raw_tx: Bytes) -> Result<L2Transaction, SignatureProverError> {
    let tx = L2Transaction::decode_tx_bytes(raw_tx)
        .map_err(|_| SignatureProverError::TransactionDecodeFailed)?;
    Ok(tx)
}

#[derive(Clone, Debug)]
pub struct KeystoreAccountWithData {
    pub account: KeystoreAccount,
    pub data: Bytes,
}
