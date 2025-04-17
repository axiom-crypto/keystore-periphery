use std::sync::OnceLock;

use alloy_primitives::{keccak256, Bytes, FixedBytes, U256};
use alloy_sol_types::SolValue;

use super::KeystoreTxType;
use crate::keystore_types::{contract, L2TransactionHash};

/// Transfer deposit transaction type for transfer purposes.
pub struct TransferDepositTransaction {
    pub l1_initiated_nonce: U256,
    pub amt: U256,
    pub keystore_address: FixedBytes<32>,
}

impl From<DepositTransaction> for TransferDepositTransaction {
    fn from(tx: DepositTransaction) -> Self {
        Self {
            l1_initiated_nonce: tx.l1_initiated_nonce,
            amt: tx.amt,
            keystore_address: tx.keystore_address,
        }
    }
}

impl From<DepositTransaction> for contract::AxiomKeystoreRollup::L1InitiatedTransaction {
    fn from(deposit_tx: DepositTransaction) -> Self {
        Self {
            txType: KeystoreTxType::Deposit as u8,
            data: deposit_tx.keystore_address().into(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DepositTransaction {
    l1_initiated_nonce: U256,
    amt: U256,
    keystore_address: FixedBytes<32>,

    #[serde(skip)]
    tx_bytes: OnceLock<Bytes>,
    #[serde(skip)]
    tx_hash: OnceLock<L2TransactionHash>,
}

impl DepositTransaction {
    pub fn new(l1_initiated_nonce: U256, amt: U256, keystore_address: FixedBytes<32>) -> Self {
        Self {
            l1_initiated_nonce,
            amt,
            keystore_address,
            tx_bytes: OnceLock::new(),
            tx_hash: OnceLock::new(),
        }
    }

    pub fn l1_initiated_nonce(&self) -> U256 {
        self.l1_initiated_nonce
    }

    pub fn amt(&self) -> U256 {
        self.amt
    }

    pub fn keystore_address(&self) -> FixedBytes<32> {
        self.keystore_address
    }

    // TODO: add tests to ensure the impl matches the spec
    pub fn tx_bytes(&self) -> &Bytes {
        self.tx_bytes.get_or_init(|| {
            // bytes transaction = abi.encodePacked(
            //     KeystoreTxType.DEPOSIT,
            //     l1InitiatedNonce,
            //     amt,
            //     keystoreAddress
            // );
            (
                Bytes::from([KeystoreTxType::Deposit as u8]),
                self.l1_initiated_nonce,
                self.amt,
                self.keystore_address,
            )
                .abi_encode_packed()
                .into()
        })
    }

    pub fn into_tx_bytes(self) -> Bytes {
        let _ = self.tx_bytes(); // initializes self.tx_bytes
        self.tx_bytes.into_inner().unwrap()
    }

    // TODO: add tests to ensure the impl matches the spec
    pub fn tx_hash(&self) -> L2TransactionHash {
        // bytes32 transactionHash = keccak256(transaction);
        *self.tx_hash.get_or_init(|| keccak256(self.tx_bytes()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("deposit tx builder error: {msg}")]
pub struct DepositTransactionBuilderError {
    pub msg: &'static str,
}

impl DepositTransactionBuilderError {
    pub fn new(msg: &'static str) -> Self {
        Self { msg }
    }
}

#[derive(Debug, Default, Clone)]
pub struct DepositTransactionBuilder {
    l1_initiated_nonce: Option<U256>,
    amt: Option<U256>,
    keystore_address: Option<FixedBytes<32>>,
}

impl From<DepositTransaction> for DepositTransactionBuilder {
    fn from(deposit_tx: DepositTransaction) -> Self {
        Self {
            l1_initiated_nonce: Some(deposit_tx.l1_initiated_nonce),
            amt: Some(deposit_tx.amt),
            keystore_address: Some(deposit_tx.keystore_address),
        }
    }
}

impl DepositTransactionBuilder {
    pub fn l1_initiated_nonce(mut self, l1_initiated_nonce: U256) -> Self {
        self.l1_initiated_nonce = Some(l1_initiated_nonce);
        self
    }

    pub fn amt(mut self, amt: U256) -> Self {
        self.amt = Some(amt);
        self
    }

    pub fn keystore_address(mut self, keystore_address: FixedBytes<32>) -> Self {
        self.keystore_address = Some(keystore_address);
        self
    }

    pub fn build(self) -> Result<DepositTransaction, DepositTransactionBuilderError> {
        let l1_initiated_nonce =
            self.l1_initiated_nonce
                .ok_or(DepositTransactionBuilderError::new(
                    "l1_initiated_nonce is required",
                ))?;
        let amt = self
            .amt
            .ok_or(DepositTransactionBuilderError::new("amt is required"))?;
        let keystore_address = self
            .keystore_address
            .ok_or(DepositTransactionBuilderError::new(
                "keystore_address is required",
            ))?;

        Ok(DepositTransaction::new(
            l1_initiated_nonce,
            amt,
            keystore_address,
        ))
    }
}
