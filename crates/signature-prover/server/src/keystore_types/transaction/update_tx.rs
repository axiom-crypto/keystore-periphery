use std::sync::OnceLock;

use alloy_primitives::{bytes, keccak256, Bytes, FixedBytes, U256};
use alloy_rlp::Encodable;
use alloy_sol_types::SolValue;

use super::{gen_tx_mock_proof, KeystoreAccount, KeystoreTxType, OptionBytes};
use crate::keystore_types::{contract, sponsor_msg_hash, update_user_msg_hash, L2TransactionHash};

/// RLP encoded portion of the [`UpdateTransaction`]. Defined as the following
/// in the spec:
///
/// ```solidity
/// rlp.encode([
///     nonce,
///     feePerGas,
///     newUserData,
///     newUserVkey,
///     userAcct.keystoreAddress,
///     userAcct.salt,
///     userAcct.dataHash,
///     userAcct.vkey,
///     userProof,
///     sponsorAcctBytes,
///     sponsorProof
/// ])
/// ```
#[derive(Debug, Clone, alloy_rlp::RlpDecodable, alloy_rlp::RlpEncodable)]
pub(crate) struct RlpUpdateTransaction {
    pub nonce: U256,
    pub fee_per_gas: Bytes,
    pub new_user_data: Bytes,
    pub new_user_vkey: Bytes,
    pub user_acct_keystore_address: FixedBytes<32>,
    pub user_acct_salt: FixedBytes<32>,
    pub user_acct_data_hash: FixedBytes<32>,
    pub user_acct_vkey: Bytes,
    pub user_proof: Bytes,
    pub sponsor_acct_bytes: Bytes,
    pub sponsor_proof: Bytes,
}

/// Transfer update transaction type for transfer purposes.
#[derive(Clone, Debug)]
pub struct TransferUpdateTransaction {
    pub is_l1_initiated: bool,
    pub nonce: U256,
    pub fee_per_gas: Bytes,
    pub l1_initiated_nonce: Bytes,
    pub new_user_data: Bytes,
    pub new_user_vkey: Bytes,
    pub user_acct: KeystoreAccount,
    pub user_proof: Bytes,
    pub sponsor_acct_bytes: Bytes,
    pub sponsor_proof: Bytes,
}

impl From<UpdateTransaction> for TransferUpdateTransaction {
    fn from(tx: UpdateTransaction) -> Self {
        Self {
            is_l1_initiated: tx.is_l1_initiated,
            nonce: tx.nonce,
            fee_per_gas: tx.fee_per_gas.into_bytes(),
            l1_initiated_nonce: tx.l1_initiated_nonce.into_bytes(),
            new_user_data: tx.new_user_data,
            new_user_vkey: tx.new_user_vkey,
            user_acct: tx.user_acct,
            user_proof: tx.user_proof,
            sponsor_acct_bytes: tx.sponsor_acct_bytes.into_bytes(),
            sponsor_proof: tx.sponsor_proof,
        }
    }
}

impl From<UpdateTransaction> for contract::AxiomKeystoreRollup::L1InitiatedTransaction {
    fn from(update_tx: UpdateTransaction) -> Self {
        let mut data = Vec::<u8>::new();
        RlpUpdateTransaction {
            nonce: update_tx.nonce,
            fee_per_gas: update_tx.fee_per_gas.into_bytes(),
            new_user_data: update_tx.new_user_data,
            new_user_vkey: update_tx.new_user_vkey,
            user_acct_keystore_address: update_tx.user_acct.keystore_address,
            user_acct_salt: update_tx.user_acct.salt,
            user_acct_data_hash: update_tx.user_acct.data_hash,
            user_acct_vkey: update_tx.user_acct.vkey,
            user_proof: update_tx.user_proof,
            sponsor_acct_bytes: update_tx.sponsor_acct_bytes.into_bytes(),
            sponsor_proof: update_tx.sponsor_proof,
        }
        .encode(&mut data);
        Self {
            txType: KeystoreTxType::Update as u8,
            data: data.into(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UpdateTransaction {
    is_l1_initiated: bool,
    nonce: U256,
    fee_per_gas: OptionBytes<U256>,
    l1_initiated_nonce: OptionBytes<U256>,
    new_user_data: Bytes,
    new_user_vkey: Bytes,
    user_acct: KeystoreAccount,
    user_proof: Bytes,
    sponsor_acct_bytes: OptionBytes<KeystoreAccount>,
    sponsor_proof: Bytes,

    #[serde(skip)]
    tx_bytes: OnceLock<Bytes>,
    #[serde(skip)]
    tx_hash: OnceLock<L2TransactionHash>,
}

impl UpdateTransaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        is_l1_initiated: bool,
        nonce: U256,
        fee_per_gas: OptionBytes<U256>,
        l1_initiated_nonce: OptionBytes<U256>,
        new_user_data: Bytes,
        new_user_vkey: Bytes,
        user_acct: KeystoreAccount,
        user_proof: Bytes,
        sponsor_acct_bytes: OptionBytes<KeystoreAccount>,
        sponsor_proof: Bytes,
    ) -> Self {
        Self {
            is_l1_initiated,
            nonce,
            fee_per_gas,
            l1_initiated_nonce,
            new_user_data,
            new_user_vkey,
            user_acct,
            user_proof,
            sponsor_acct_bytes,
            sponsor_proof,
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

    pub fn new_user_data(&self) -> &Bytes {
        &self.new_user_data
    }

    pub fn new_user_vkey(&self) -> &Bytes {
        &self.new_user_vkey
    }

    pub fn user_acct(&self) -> &KeystoreAccount {
        &self.user_acct
    }

    pub fn user_proof(&self) -> &Bytes {
        &self.user_proof
    }

    pub fn sponsor_acct_bytes(&self) -> &OptionBytes<KeystoreAccount> {
        &self.sponsor_acct_bytes
    }

    pub fn sponsor_proof(&self) -> &Bytes {
        &self.sponsor_proof
    }

    // TODO: add tests to ensure the impl matches the spec
    pub fn tx_bytes(&self) -> &Bytes {
        self.tx_bytes.get_or_init(|| {
            // rlp.encode([
            //     nonce,
            //     feePerGas,
            //     newUserData,
            //     newUserVkey,
            //     userAcct.keystoreAddress,
            //     userAcct.salt,
            //     userAcct.dataHash,
            //     userAcct.vkey,
            //     userProof,
            //     sponsorAcctBytes,
            //     sponsorProof
            // ])
            let to_encode: [&dyn alloy_rlp::Encodable; 11] = [
                &self.nonce,
                &self.fee_per_gas.bytes(),
                &self.new_user_data,
                &self.new_user_vkey,
                &self.user_acct.keystore_address,
                &self.user_acct.salt,
                &self.user_acct.data_hash,
                &self.user_acct.vkey,
                &self.user_proof,
                &self.sponsor_acct_bytes.bytes(),
                &self.sponsor_proof,
            ];
            let mut rlp_encoded = Vec::<u8>::new();
            alloy_rlp::encode_list::<_, dyn Encodable>(&to_encode, &mut rlp_encoded);

            // bytes transaction = abi.encodePacked(
            //     KeystoreTxType.UPDATE,
            //     isL1Initiated,
            //     l1InitiatedNonce,
            //     rlp.encode(...)
            // );
            (
                Bytes::from([KeystoreTxType::Update as u8]),
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
        update_user_msg_hash(
            self.user_acct.keystore_address,
            self.nonce(),
            self.fee_per_gas.bytes(),
            &self.new_user_data,
            &self.new_user_vkey,
        )
    }

    pub fn sponsor_msg_hash(&self) -> Option<FixedBytes<32>> {
        let sponsor_acct = self.sponsor_acct_bytes.option()?;
        Some(sponsor_msg_hash(
            sponsor_acct.keystore_address,
            self.user_msg_hash(),
            self.user_acct().keystore_address,
        ))
    }
}

#[derive(thiserror::Error, Debug)]
#[error("update tx builder error: {msg}")]
pub struct UpdateTransactionBuilderError {
    pub msg: &'static str,
}

impl UpdateTransactionBuilderError {
    pub fn new(message: &'static str) -> Self {
        Self { msg: message }
    }
}

#[derive(Debug, Default)]
pub struct UpdateTransactionBuilder {
    nonce: Option<U256>,
    fee_per_gas: Option<U256>,
    l1_initiated_nonce: Option<U256>,
    new_user_data: Option<Bytes>,
    new_user_vkey: Option<Bytes>,
    user_acct: Option<KeystoreAccount>,
    user_proof: Option<Bytes>,
    sponsor_acct: Option<KeystoreAccount>,
    sponsor_proof: Option<Bytes>,

    mock_user_proof: bool,
    mock_sponsor_proof: bool,
}

impl From<UpdateTransaction> for UpdateTransactionBuilder {
    fn from(update_tx: UpdateTransaction) -> Self {
        Self {
            nonce: Some(update_tx.nonce),
            fee_per_gas: update_tx.fee_per_gas.into_option(),
            l1_initiated_nonce: update_tx.l1_initiated_nonce.into_option(),
            new_user_data: Some(update_tx.new_user_data),
            new_user_vkey: Some(update_tx.new_user_vkey),
            user_acct: Some(update_tx.user_acct),
            user_proof: Some(update_tx.user_proof),
            sponsor_acct: update_tx.sponsor_acct_bytes.into_option(),
            sponsor_proof: Some(update_tx.sponsor_proof),
            mock_user_proof: false,
            mock_sponsor_proof: false,
        }
    }
}

impl UpdateTransactionBuilder {
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

    pub fn new_user_data(mut self, new_user_data: Bytes) -> Self {
        self.new_user_data = Some(new_user_data);
        self
    }

    pub fn new_user_vkey(mut self, new_user_vkey: Bytes) -> Self {
        self.new_user_vkey = Some(new_user_vkey);
        self
    }

    pub fn user_acct(mut self, user_acct: KeystoreAccount) -> Self {
        self.user_acct = Some(user_acct);
        self
    }

    pub fn user_proof(mut self, user_proof: Bytes) -> Self {
        self.user_proof = Some(user_proof);
        self.mock_user_proof = false;
        self
    }

    pub fn mock_user_proof(mut self) -> Self {
        self.user_proof = None;
        self.mock_user_proof = true;
        self
    }

    pub fn sponsor_acct(mut self, sponsor_acct: Option<KeystoreAccount>) -> Self {
        self.sponsor_acct = sponsor_acct;
        self
    }

    pub fn sponsor_proof(mut self, sponsor_proof: Bytes) -> Self {
        self.sponsor_proof = Some(sponsor_proof);
        self.mock_sponsor_proof = false;
        self
    }

    pub fn mock_sponsor_proof(mut self) -> Self {
        self.sponsor_proof = None;
        self.mock_sponsor_proof = true;
        self
    }

    fn user_msg_hash(&self) -> FixedBytes<32> {
        let fee_per_gas = OptionBytes::from(self.fee_per_gas);

        update_user_msg_hash(
            self.user_acct.as_ref().unwrap().keystore_address,
            self.nonce.unwrap(),
            fee_per_gas.bytes(),
            self.new_user_data.as_ref().unwrap(),
            self.new_user_vkey.as_ref().unwrap(),
        )
    }

    fn sponsor_msg_hash(&self) -> FixedBytes<32> {
        sponsor_msg_hash(
            self.sponsor_acct.as_ref().unwrap().keystore_address,
            self.user_msg_hash(),
            self.user_acct.as_ref().unwrap().keystore_address,
        )
    }

    fn gen_mock_user_proof(&self) -> Bytes {
        let user_msg_hash = self.user_msg_hash();
        gen_tx_mock_proof(self.user_acct.as_ref().unwrap().data_hash, user_msg_hash)
    }

    fn gen_mock_sponsor_proof(&self) -> Bytes {
        let sponsor_msg_hash = self.sponsor_msg_hash();
        gen_tx_mock_proof(
            self.sponsor_acct.as_ref().unwrap().data_hash,
            sponsor_msg_hash,
        )
    }

    pub fn build(mut self) -> Result<UpdateTransaction, UpdateTransactionBuilderError> {
        let is_l1_initiated = self.l1_initiated_nonce.is_some();
        if is_l1_initiated && self.fee_per_gas.is_some() {
            return Err(UpdateTransactionBuilderError::new(
                "L1-initiated transaction cannot have fee_per_gas",
            ));
        }
        if !is_l1_initiated && self.fee_per_gas.is_none() {
            return Err(UpdateTransactionBuilderError::new(
                "fee_per_gas is required for sequencer transaction",
            ));
        }

        self.nonce
            .as_ref()
            .ok_or(UpdateTransactionBuilderError::new("nonce is required"))?;

        self.new_user_vkey
            .as_ref()
            .ok_or(UpdateTransactionBuilderError::new(
                "new user vkey is required",
            ))?;
        self.new_user_data
            .as_ref()
            .ok_or(UpdateTransactionBuilderError::new(
                "new user data is required",
            ))?;

        self.user_acct
            .as_ref()
            .ok_or(UpdateTransactionBuilderError::new(
                "user account is required",
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

        let sponsor_proof = {
            match self.sponsor_proof.take() {
                Some(sponsor_proof) => sponsor_proof,
                None => {
                    if self.mock_sponsor_proof {
                        self.sponsor_acct
                            .as_ref()
                            .ok_or(UpdateTransactionBuilderError::new(
                                "sponsor account is required to generate mock sponsor proof",
                            ))?;
                        self.gen_mock_sponsor_proof()
                    } else {
                        bytes!("")
                    }
                }
            }
        };

        Ok(UpdateTransaction::new(
            is_l1_initiated,
            self.nonce.unwrap(),
            self.fee_per_gas.into(),
            self.l1_initiated_nonce.into(),
            self.new_user_data.unwrap(),
            self.new_user_vkey.unwrap(),
            self.user_acct.unwrap(),
            user_proof,
            self.sponsor_acct.into(),
            sponsor_proof,
        ))
    }
}
