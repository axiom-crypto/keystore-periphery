use std::sync::OnceLock;

use alloy_dyn_abi::Eip712Domain;
use alloy_primitives::{bytes, keccak256, Address, Bytes, FixedBytes, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_sol_types::SolValue;
use lazy_static::lazy_static;

use super::{
    sponsor_msg_hash, update_user_msg_hash, withdraw_user_msg_hash, L2TransactionHash, RollupTx,
};

lazy_static! {
    pub static ref CHAIN_ID: U256 = U256::from(999999999);
    pub static ref EIP712_REVISION: Bytes = Bytes::from_static(b"1");
    pub static ref EIP712_DOMAIN: Eip712Domain = Eip712Domain::new(
        Some("AxiomKeystore".into()),
        Some("1".into()),
        Some(*CHAIN_ID),
        None,
        None
    );

    pub static ref WITHDRAW_TYPEHASH: FixedBytes<32> =
        keccak256("Withdraw(bytes32 userKeystoreAddress,uint256 nonce,bytes feePerGas,address to,uint256 amt)");

    pub static ref UPDATE_TYPEHASH: FixedBytes<32> = keccak256("Update(bytes32 userKeystoreAddress,uint256 nonce,bytes feePerGas,bytes newUserData,bytes newUserVkey)");

    pub static ref SPONSOR_TYPEHASH: FixedBytes<32> = keccak256("Sponsor(bytes32 sponsorKeystoreAddress,bytes32 userMsgHash,bytes32 userKeystoreAddress)");

    pub static ref WITHDRAW_GAS: U256 = U256::from(100_000);
    pub static ref UPDATE_GAS: U256 = U256::from(100_000);
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OptionBytes<T> {
    bytes: Bytes,
    option: Option<T>,
}

impl<T> OptionBytes<T> {
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    pub fn option(&self) -> Option<&T> {
        self.option.as_ref()
    }

    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}

impl OptionBytes<U256> {
    pub fn u256(&self) -> U256 {
        self.option.unwrap_or(U256::ZERO)
    }
}

#[derive(thiserror::Error, Debug)]
pub struct OptionBytesError(#[from] eyre::Report);

impl std::fmt::Display for OptionBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid option bytes: {}", self.0)
    }
}

impl From<Option<U256>> for OptionBytes<U256> {
    fn from(option: Option<U256>) -> Self {
        let bytes = match option {
            Some(value) => value.to_be_bytes_vec().into(),
            None => bytes!(""),
        };

        Self { bytes, option }
    }
}

impl TryFrom<Bytes> for OptionBytes<U256> {
    type Error = OptionBytesError;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        let option = if bytes == bytes!("") {
            None
        } else {
            let value = U256::try_from_be_slice(bytes.to_vec().as_slice());
            if value.is_none() {
                return Err(OptionBytesError(eyre::eyre!(
                    "failed to convert Bytes into U256"
                )));
            }
            value
        };
        Ok(Self { bytes, option })
    }
}

impl From<Option<KeystoreAccount>> for OptionBytes<KeystoreAccount> {
    fn from(option: Option<KeystoreAccount>) -> Self {
        let bytes = match &option {
            Some(value) => {
                let mut buffer = Vec::<u8>::new();
                value.encode(&mut buffer);
                buffer.into()
            }
            None => bytes!(""),
        };
        Self { bytes, option }
    }
}

impl TryFrom<Bytes> for OptionBytes<KeystoreAccount> {
    type Error = OptionBytesError;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        let option = if bytes == bytes!("") {
            None
        } else {
            let decoded = KeystoreAccount::decode(&mut bytes.to_vec().as_slice())
                .map_err(|err| OptionBytesError(err.into()))?;
            Some(decoded)
        };
        Ok(Self { bytes, option })
    }
}

#[derive(
    Debug,
    Clone,
    alloy_rlp::RlpDecodable,
    alloy_rlp::RlpEncodable,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct KeystoreAccount {
    pub keystore_address: FixedBytes<32>,
    pub salt: FixedBytes<32>,
    pub data_hash: FixedBytes<32>,
    pub vkey: Bytes,
}

impl KeystoreAccount {
    pub fn with_keystore_address(
        keystore_address: FixedBytes<32>,
        data_hash: FixedBytes<32>,
        vkey: Bytes,
    ) -> Self {
        Self {
            keystore_address,
            salt: FixedBytes::ZERO,
            data_hash,
            vkey,
        }
    }

    pub fn with_salt(salt: FixedBytes<32>, data_hash: FixedBytes<32>, vkey: Bytes) -> Self {
        let keystore_address = calculate_keystore_address(salt, data_hash, keccak256(&vkey));
        Self {
            keystore_address,
            salt,
            data_hash,
            vkey,
        }
    }
}

/// Corresponds to the `KeystoreTxType` enum in the AxiomKeystoreRollup3
/// contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeystoreTxType {
    Deposit = 0,
    Withdraw = 1,
    Update = 2,
}

#[derive(thiserror::Error, Debug)]
#[error("invalid keystore tx type")]
pub struct InvalidKeystoreTxType;

impl TryFrom<u8> for KeystoreTxType {
    type Error = InvalidKeystoreTxType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Deposit),
            1 => Ok(Self::Withdraw),
            2 => Ok(Self::Update),
            _ => Err(InvalidKeystoreTxType),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum L2Transaction {
    Deposit(DepositTransaction),
    Withdraw(WithdrawTransaction),
    Update(UpdateTransaction),
}

impl From<DepositTransaction> for L2Transaction {
    fn from(tx: DepositTransaction) -> Self {
        Self::Deposit(tx)
    }
}

impl From<WithdrawTransaction> for L2Transaction {
    fn from(tx: WithdrawTransaction) -> Self {
        Self::Withdraw(tx)
    }
}

impl From<UpdateTransaction> for L2Transaction {
    fn from(tx: UpdateTransaction) -> Self {
        Self::Update(tx)
    }
}

impl L2Transaction {
    pub fn as_deposit_tx(&self) -> Option<&DepositTransaction> {
        match self {
            L2Transaction::Deposit(tx) => Some(tx),
            _ => None,
        }
    }

    pub fn as_withdraw_tx(&self) -> Option<&WithdrawTransaction> {
        match self {
            L2Transaction::Withdraw(tx) => Some(tx),
            _ => None,
        }
    }

    pub fn as_update_tx(&self) -> Option<&UpdateTransaction> {
        match self {
            L2Transaction::Update(tx) => Some(tx),
            _ => None,
        }
    }

    pub fn tx_type(&self) -> KeystoreTxType {
        match self {
            L2Transaction::Deposit(_) => KeystoreTxType::Deposit,
            L2Transaction::Withdraw(_) => KeystoreTxType::Withdraw,
            L2Transaction::Update(_) => KeystoreTxType::Update,
        }
    }

    pub fn user_keystore_address(&self) -> FixedBytes<32> {
        match self {
            L2Transaction::Deposit(tx) => tx.keystore_address(),
            L2Transaction::Withdraw(tx) => tx.user_acct().keystore_address,
            L2Transaction::Update(tx) => tx.user_acct().keystore_address,
        }
    }
}

impl RollupTx for L2Transaction {
    fn tx_bytes(&self) -> &Bytes {
        match self {
            L2Transaction::Deposit(tx) => tx.tx_bytes(),
            L2Transaction::Withdraw(tx) => tx.tx_bytes(),
            L2Transaction::Update(tx) => tx.tx_bytes(),
        }
    }

    fn into_tx_bytes(self) -> Bytes {
        match self {
            L2Transaction::Deposit(tx) => tx.into_tx_bytes(),
            L2Transaction::Withdraw(tx) => tx.into_tx_bytes(),
            L2Transaction::Update(tx) => tx.into_tx_bytes(),
        }
    }

    fn tx_hash(&self) -> L2TransactionHash {
        match self {
            L2Transaction::Deposit(tx) => tx.tx_hash(),
            L2Transaction::Withdraw(tx) => tx.tx_hash(),
            L2Transaction::Update(tx) => tx.tx_hash(),
        }
    }
}

impl PartialEq for L2Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.tx_hash() == other.tx_hash()
    }
}
impl Eq for L2Transaction {}

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

    pub fn tx_hash(&self) -> L2TransactionHash {
        // bytes32 transactionHash = keccak256(transaction);
        *self.tx_hash.get_or_init(|| keccak256(self.tx_bytes()))
    }
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
            fee_per_gas: tx.fee_per_gas.bytes,
            l1_initiated_nonce: tx.l1_initiated_nonce.bytes,
            to: tx.to,
            amt: tx.amt,
            user_acct: tx.user_acct,
            user_proof: tx.user_proof,
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
pub struct RlpUpdateTransaction {
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
            fee_per_gas: tx.fee_per_gas.bytes,
            l1_initiated_nonce: tx.l1_initiated_nonce.bytes,
            new_user_data: tx.new_user_data,
            new_user_vkey: tx.new_user_vkey,
            user_acct: tx.user_acct,
            user_proof: tx.user_proof,
            sponsor_acct_bytes: tx.sponsor_acct_bytes.bytes,
            sponsor_proof: tx.sponsor_proof,
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

    pub fn set_sponsor(&mut self, sponsor_acct: KeystoreAccount) {
        self.sponsor_acct_bytes = Some(sponsor_acct).into();
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

pub fn gen_tx_proof(data_hash: FixedBytes<32>, msg_hash: FixedBytes<32>) -> Bytes {
    let gen_public_inputs = |input: FixedBytes<32>| -> Bytes {
        let hi = &input[0..16];
        let lo = &input[16..];
        let padded_hi = FixedBytes::<32>::left_padding_from(hi);
        let padded_lo = FixedBytes::<32>::left_padding_from(lo);

        Bytes::from([padded_hi, padded_lo].concat())
    };

    let mut proof = vec![0u8; 384];

    proof.append(&mut gen_public_inputs(data_hash).to_vec());
    proof.append(&mut gen_public_inputs(msg_hash).to_vec());

    Bytes::from(proof)
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

#[derive(Clone, Debug)]
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

impl UpdateTransactionBuilder {
    pub fn l1_initiated_tx(l1_initiated_nonce: U256) -> Self {
        Self {
            nonce: None,
            fee_per_gas: None,
            l1_initiated_nonce: Some(l1_initiated_nonce),
            new_user_data: None,
            new_user_vkey: None,
            user_acct: None,
            user_proof: None,
            sponsor_acct: None,
            sponsor_proof: None,
            mock_user_proof: false,
            mock_sponsor_proof: false,
        }
    }

    pub fn sequencer_tx(fee_per_gas: U256) -> Self {
        Self {
            nonce: None,
            fee_per_gas: Some(fee_per_gas),
            l1_initiated_nonce: None,
            new_user_data: None,
            new_user_vkey: None,
            user_acct: None,
            user_proof: None,
            sponsor_acct: None,
            sponsor_proof: None,
            mock_user_proof: false,
            mock_sponsor_proof: false,
        }
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
        update_user_msg_hash(
            self.user_acct.as_ref().unwrap().keystore_address,
            self.nonce.unwrap(),
            &self.fee_per_gas.unwrap().to_be_bytes::<32>().into(),
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
        gen_tx_proof(self.user_acct.as_ref().unwrap().data_hash, user_msg_hash)
    }

    fn gen_mock_sponsor_proof(&self) -> Bytes {
        let sponsor_msg_hash = self.sponsor_msg_hash();
        gen_tx_proof(
            self.sponsor_acct.as_ref().unwrap().data_hash,
            sponsor_msg_hash,
        )
    }

    pub fn build(self) -> Result<UpdateTransaction, UpdateTransactionBuilderError> {
        let user_proof = {
            match self.user_proof.as_ref() {
                Some(user_proof) => user_proof.clone(),
                None => {
                    if self.mock_user_proof {
                        self.gen_mock_user_proof()
                    } else {
                        return Err(UpdateTransactionBuilderError::new("user proof is required"));
                    }
                }
            }
        };
        let sponsor_proof = {
            match self.sponsor_proof {
                Some(sponsor_proof) => sponsor_proof,
                None => {
                    if self.mock_sponsor_proof {
                        self.gen_mock_sponsor_proof()
                    } else {
                        bytes!("")
                    }
                }
            }
        };

        let is_l1_initiated = self.l1_initiated_nonce.is_some();
        let nonce = self
            .nonce
            .ok_or(UpdateTransactionBuilderError::new("nonce is required"))?;
        let fee_per_gas = self.fee_per_gas;
        let l1_initiated_nonce = self.l1_initiated_nonce;
        let new_user_vkey = self
            .new_user_vkey
            .ok_or(UpdateTransactionBuilderError::new(
                "new user vkey is required",
            ))?;
        let new_user_data = self
            .new_user_data
            .ok_or(UpdateTransactionBuilderError::new(
                "new user data is required",
            ))?;
        let user_acct = self.user_acct.ok_or(UpdateTransactionBuilderError::new(
            "user account is required",
        ))?;
        let sponsor_acct = self.sponsor_acct;

        Ok(UpdateTransaction::new(
            is_l1_initiated,
            nonce,
            fee_per_gas.into(),
            l1_initiated_nonce.into(),
            new_user_data,
            new_user_vkey,
            user_acct,
            user_proof,
            sponsor_acct.into(),
            sponsor_proof,
        ))
    }
}

pub fn calculate_keystore_address(
    salt: FixedBytes<32>,
    data_hash: FixedBytes<32>,
    vk_hash: FixedBytes<32>,
) -> FixedBytes<32> {
    keccak256([&salt[..], &data_hash[..], &vk_hash[..]].concat())
}
