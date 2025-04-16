use std::sync::OnceLock;

use alloy_primitives::{bytes, keccak256, Address, Bytes, FixedBytes, U256};
use alloy_rlp::Encodable;
use alloy_sol_types::SolValue;

use super::{gen_tx_mock_proof, KeystoreAccount, KeystoreTxType, OptionBytes};
use crate::keystore_types::{contract, withdraw_user_msg_hash, L2TransactionHash};

/// RLP encoded portion of the [`WithdrawTransaction`]. Defined as the following
/// in the spec:
///
/// ```solidity
/// rlp.encode([
///     nonce,
///     feePerGas,
///     to,
///     amt,
///     userAcct.keystoreAddress,
///     userAcct.salt,
///     userAcct.dataHash,
///     userAcct.vkey,
///     userProof
/// ])
/// ```
#[derive(Debug, Clone, alloy_rlp::RlpDecodable, alloy_rlp::RlpEncodable)]
pub(crate) struct RlpWithdrawTransaction {
    pub nonce: U256,
    pub fee_per_gas: Bytes,
    pub to: Address,
    pub amt: U256,
    pub user_acct_keystore_address: FixedBytes<32>,
    pub user_acct_salt: FixedBytes<32>,
    pub user_acct_data_hash: FixedBytes<32>,
    pub user_acct_vkey: Bytes,
    pub user_proof: Bytes,
}

/// Transfer withdraw transaction type for transfer purposes.
pub struct TransferWithdrawTransaction {
    pub is_l1_initiated: bool,
    pub nonce: U256,
    pub fee_per_gas: Bytes,
    pub l1_initiated_nonce: Bytes,
    pub to: Address,
    pub amt: U256,
    pub user_acct: KeystoreAccount,
    pub user_proof: Bytes,
}

impl From<WithdrawTransaction> for TransferWithdrawTransaction {
    fn from(tx: WithdrawTransaction) -> Self {
        Self {
            is_l1_initiated: tx.is_l1_initiated,
            nonce: tx.nonce,
            fee_per_gas: tx.fee_per_gas.into_bytes(),
            l1_initiated_nonce: tx.l1_initiated_nonce.into_bytes(),
            to: tx.to,
            amt: tx.amt,
            user_acct: tx.user_acct,
            user_proof: tx.user_proof,
        }
    }
}

impl From<WithdrawTransaction> for contract::AxiomKeystoreRollup::L1InitiatedTransaction {
    fn from(withdraw_tx: WithdrawTransaction) -> Self {
        let mut data = Vec::<u8>::new();
        RlpWithdrawTransaction {
            nonce: withdraw_tx.nonce,
            fee_per_gas: withdraw_tx.fee_per_gas.into_bytes(),
            to: withdraw_tx.to,
            amt: withdraw_tx.amt,
            user_acct_keystore_address: withdraw_tx.user_acct.keystore_address,
            user_acct_salt: withdraw_tx.user_acct.salt,
            user_acct_data_hash: withdraw_tx.user_acct.data_hash,
            user_acct_vkey: withdraw_tx.user_acct.vkey,
            user_proof: withdraw_tx.user_proof,
        }
        .encode(&mut data);
        Self {
            txType: KeystoreTxType::Withdraw as u8,
            data: data.into(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WithdrawTransaction {
    is_l1_initiated: bool,
    nonce: U256,
    fee_per_gas: OptionBytes<U256>,
    l1_initiated_nonce: OptionBytes<U256>,
    to: Address,
    amt: U256,
    user_acct: KeystoreAccount,
    user_proof: Bytes,

    #[serde(skip)]
    tx_bytes: OnceLock<Bytes>,
    #[serde(skip)]
    tx_hash: OnceLock<L2TransactionHash>,
}

impl WithdrawTransaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        is_l1_initiated: bool,
        nonce: U256,
        fee_per_gas: OptionBytes<U256>,
        l1_initiated_nonce: OptionBytes<U256>,
        to: Address,
        amt: U256,
        user_acct: KeystoreAccount,
        user_proof: Bytes,
    ) -> Self {
        Self {
            is_l1_initiated,
            nonce,
            fee_per_gas,
            l1_initiated_nonce,
            to,
            amt,
            user_acct,
            user_proof,
            tx_bytes: OnceLock::new(),
            tx_hash: OnceLock::new(),
        }
    }

    pub fn is_l1_initiated(&self) -> bool {
        self.is_l1_initiated
    }

    pub fn nonce(&self) -> U256 {
        self.nonce
    }

    pub fn fee_per_gas(&self) -> &OptionBytes<U256> {
        &self.fee_per_gas
    }

    pub fn l1_initiated_nonce(&self) -> &OptionBytes<U256> {
        &self.l1_initiated_nonce
    }

    pub fn to(&self) -> Address {
        self.to
    }

    pub fn amt(&self) -> U256 {
        self.amt
    }

    pub fn user_acct(&self) -> &KeystoreAccount {
        &self.user_acct
    }

    pub fn user_proof(&self) -> &Bytes {
        &self.user_proof
    }

    // TODO: add tests to ensure the impl matches the spec
    pub fn tx_bytes(&self) -> &Bytes {
        self.tx_bytes.get_or_init(|| {
            // rlp.encode([
            //     nonce,
            //     feePerGas,
            //     to,
            //     amt,
            //     userAcct.keystoreAddress,
            //     userAcct.salt,
            //     userAcct.dataHash,
            //     userAcct.vkey,
            //     userProof
            // ])
            let to_encode: [&dyn alloy_rlp::Encodable; 9] = [
                &self.nonce,
                &self.fee_per_gas.bytes(),
                &self.to,
                &self.amt,
                &self.user_acct.keystore_address,
                &self.user_acct.salt,
                &self.user_acct.data_hash,
                &self.user_acct.vkey,
                &self.user_proof,
            ];
            let mut rlp_encoded = Vec::<u8>::new();
            alloy_rlp::encode_list::<_, dyn Encodable>(&to_encode, &mut rlp_encoded);

            // bytes transaction = abi.encodePacked(
            //     KeystoreTxType.WITHDRAW,
            //     isL1Initiated,
            //     l1InitiatedNonce,
            //     rlp.encode(...)
            // );
            (
                Bytes::from([KeystoreTxType::Withdraw as u8]),
                self.is_l1_initiated,
                self.l1_initiated_nonce.bytes(),
                rlp_encoded,
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
        *self.tx_hash.get_or_init(|| keccak256(self.tx_bytes()))
    }

    pub fn user_msg_hash(&self) -> FixedBytes<32> {
        withdraw_user_msg_hash(
            self.user_acct().keystore_address,
            self.nonce(),
            self.fee_per_gas().bytes(),
            self.to(),
            self.amt(),
        )
    }
}

#[derive(thiserror::Error, Debug)]
#[error("withdraw tx builder error: {msg}")]
pub struct WithdrawTransactionBuilderError {
    pub msg: &'static str,
}

impl WithdrawTransactionBuilderError {
    fn new(msg: &'static str) -> Self {
        Self { msg }
    }
}

#[derive(Debug, Default)]
pub struct WithdrawTransactionBuilder {
    nonce: Option<U256>,
    fee_per_gas: Option<U256>,
    l1_initiated_nonce: Option<U256>,
    to: Option<Address>,
    amt: Option<U256>,
    user_acct: Option<KeystoreAccount>,
    user_proof: Option<Bytes>,

    mock_user_proof: bool,
}

impl WithdrawTransactionBuilder {
    pub fn l1_initiated_nonce(mut self, l1_initiated_nonce: U256) -> Self {
        self.l1_initiated_nonce = Some(l1_initiated_nonce);
        self
    }

    pub fn fee_per_gas(mut self, fee_per_gas: U256) -> Self {
        self.fee_per_gas = Some(fee_per_gas);
        self
    }

    pub fn nonce(mut self, nonce: U256) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn to(mut self, to: Address) -> Self {
        self.to = Some(to);
        self
    }

    pub fn amt(mut self, amt: U256) -> Self {
        self.amt = Some(amt);
        self
    }

    pub fn user_acct(mut self, user_acct: KeystoreAccount) -> Self {
        self.user_acct = Some(user_acct);
        self
    }

    pub fn user_proof(mut self, user_proof: Bytes) -> Self {
        self.user_proof = Some(user_proof);
        self
    }

    pub fn mock_user_proof(mut self) -> Self {
        self.user_proof = None;
        self.mock_user_proof = true;
        self
    }

    fn user_msg_hash(&self) -> FixedBytes<32> {
        let fee_per_gas = OptionBytes::from(self.fee_per_gas);

        withdraw_user_msg_hash(
            self.user_acct.as_ref().unwrap().keystore_address,
            self.nonce.unwrap(),
            fee_per_gas.bytes(),
            self.to.unwrap(),
            self.amt.unwrap(),
        )
    }

    fn gen_mock_user_proof(&self) -> Bytes {
        let user_msg_hash = self.user_msg_hash();
        gen_tx_mock_proof(self.user_acct.as_ref().unwrap().data_hash, user_msg_hash)
    }

    pub fn build(mut self) -> Result<WithdrawTransaction, WithdrawTransactionBuilderError> {
        let is_l1_initiated = self.l1_initiated_nonce.is_some();
        if is_l1_initiated && self.fee_per_gas.is_some() {
            return Err(WithdrawTransactionBuilderError::new(
                "L1-initiated transaction cannot have fee_per_gas",
            ));
        }
        if !is_l1_initiated && self.fee_per_gas.is_none() {
            return Err(WithdrawTransactionBuilderError::new(
                "fee_per_gas is required for sequencer transaction",
            ));
        }

        self.nonce
            .as_ref()
            .ok_or(WithdrawTransactionBuilderError::new("nonce is required"))?;

        self.to
            .as_ref()
            .ok_or(WithdrawTransactionBuilderError::new("to is required"))?;

        self.amt
            .as_ref()
            .ok_or(WithdrawTransactionBuilderError::new("amt is required"))?;

        self.user_acct
            .as_ref()
            .ok_or(WithdrawTransactionBuilderError::new(
                "user_acct is required",
            ))?;

        let user_proof = {
            match self.user_proof.take() {
                Some(user_proof) => user_proof,
                None => {
                    if self.mock_user_proof {
                        self.gen_mock_user_proof()
                    } else {
                        bytes!("")
                    }
                }
            }
        };

        Ok(WithdrawTransaction::new(
            is_l1_initiated,
            self.nonce.unwrap(),
            self.fee_per_gas.into(),
            self.l1_initiated_nonce.into(),
            self.to.unwrap(),
            self.amt.unwrap(),
            self.user_acct.unwrap(),
            user_proof,
        ))
    }
}
