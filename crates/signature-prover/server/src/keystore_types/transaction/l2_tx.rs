use alloy_primitives::{Bytes, FixedBytes, U256};

use crate::keystore_types::{contract, L2TransactionHash, RollupTx};

use super::{DepositTransaction, UpdateTransaction, WithdrawTransaction};

/// Corresponds to the `KeystoreTxType` enum in the AxiomKeystoreRollup
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

// "update" is 680 bytes (vs 472 for second largest "withdraw").
// The difference is not that large and update seems to be more common.
#[allow(clippy::large_enum_variant)]
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

    pub fn l1_initiated_nonce(&self) -> Option<U256> {
        match self {
            L2Transaction::Deposit(tx) => Some(tx.l1_initiated_nonce()),
            L2Transaction::Withdraw(tx) => tx.l1_initiated_nonce().option().cloned(),
            L2Transaction::Update(tx) => tx.l1_initiated_nonce().option().cloned(),
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

impl From<L2Transaction> for contract::AxiomKeystoreRollup::L1InitiatedTransaction {
    fn from(l2_tx: L2Transaction) -> Self {
        match l2_tx {
            L2Transaction::Deposit(deposit_tx) => deposit_tx.into(),
            L2Transaction::Withdraw(withdraw_tx) => withdraw_tx.into(),
            L2Transaction::Update(update_tx) => update_tx.into(),
        }
    }
}
