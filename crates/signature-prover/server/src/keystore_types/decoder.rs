use alloy_primitives::Bytes;
use alloy_rlp::Decodable;

use super::{
    DepositTransaction, KeystoreAccount, KeystoreTxType, L2Transaction, OptionBytes,
    OptionBytesError, RlpUpdateTransaction, UpdateTransaction, WithdrawTransaction,
};

pub trait TxDecode: Sized {
    type Error: std::error::Error;

    fn decode_tx_bytes(tx_bytes: Bytes) -> Result<Self, Self::Error>;
}

#[derive(thiserror::Error, Debug)]
pub enum TxDecodeError {
    #[error("invalid tx_bytes length")]
    InvalidLength,
    #[error("invalid keystore tx type")]
    InvalidKeystoreTxType,
    #[error("rlp decode failed: {0}")]
    RlpDecodeFailed(#[from] alloy_rlp::Error),
    #[error("{field_name} option bytes decode failed: {err}")]
    OptionBytesDecodeFailed {
        field_name: &'static str,
        err: OptionBytesError,
    },
    #[error("sequencer tx must have is_l1_initiated = false")]
    IsL1Initiated,
}

impl TxDecode for DepositTransaction {
    type Error = TxDecodeError;

    fn decode_tx_bytes(_tx_bytes: Bytes) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl TxDecode for WithdrawTransaction {
    type Error = TxDecodeError;

    fn decode_tx_bytes(_tx_bytes: Bytes) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl TxDecode for UpdateTransaction {
    type Error = TxDecodeError;

    fn decode_tx_bytes(tx_bytes: Bytes) -> Result<Self, Self::Error> {
        if tx_bytes.len() < 2 {
            return Err(TxDecodeError::InvalidLength);
        }

        let tx_type = KeystoreTxType::try_from(tx_bytes[0])
            .map_err(|_| TxDecodeError::InvalidKeystoreTxType)?;
        if tx_type != KeystoreTxType::Update {
            return Err(TxDecodeError::InvalidKeystoreTxType);
        }

        let is_l1_initiated = tx_bytes[1] != 0;
        if is_l1_initiated {
            return Err(TxDecodeError::IsL1Initiated);
        }

        let rlp_encoded = &mut &tx_bytes[2..];
        let rlp_update_tx = RlpUpdateTransaction::decode(rlp_encoded)?;

        let fee_per_gas = OptionBytes::try_from(rlp_update_tx.fee_per_gas).map_err(|err| {
            TxDecodeError::OptionBytesDecodeFailed {
                field_name: "fee_per_gas",
                err,
            }
        })?;
        let l1_initiated_nonce = OptionBytes::from(None);
        let sponsor_acct_bytes =
            OptionBytes::try_from(rlp_update_tx.sponsor_acct_bytes).map_err(|err| {
                TxDecodeError::OptionBytesDecodeFailed {
                    field_name: "sponsor_acct_bytes",
                    err,
                }
            })?;

        let user_acct = KeystoreAccount {
            keystore_address: rlp_update_tx.user_acct_keystore_address,
            salt: rlp_update_tx.user_acct_salt,
            data_hash: rlp_update_tx.user_acct_data_hash,
            vkey: rlp_update_tx.user_acct_vkey,
        };

        let update_tx = UpdateTransaction::new(
            is_l1_initiated,
            rlp_update_tx.nonce,
            fee_per_gas,
            l1_initiated_nonce,
            rlp_update_tx.new_user_data,
            rlp_update_tx.new_user_vkey,
            user_acct,
            rlp_update_tx.user_proof,
            sponsor_acct_bytes,
            rlp_update_tx.sponsor_proof,
        );

        Ok(update_tx)
    }
}

impl TxDecode for L2Transaction {
    type Error = TxDecodeError;

    fn decode_tx_bytes(tx_bytes: Bytes) -> Result<Self, Self::Error> {
        let first_byte = tx_bytes.first().ok_or(TxDecodeError::InvalidLength)?;
        let tx_type = KeystoreTxType::try_from(*first_byte)
            .map_err(|_| TxDecodeError::InvalidKeystoreTxType)?;

        match tx_type {
            KeystoreTxType::Deposit => {
                let tx = DepositTransaction::decode_tx_bytes(tx_bytes)?;
                Ok(tx.into())
            }
            KeystoreTxType::Withdraw => {
                let tx = WithdrawTransaction::decode_tx_bytes(tx_bytes)?;
                Ok(tx.into())
            }
            KeystoreTxType::Update => {
                let tx = UpdateTransaction::decode_tx_bytes(tx_bytes)?;
                Ok(tx.into())
            }
        }
    }
}
