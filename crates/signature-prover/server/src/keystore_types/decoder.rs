use alloy_primitives::{Bytes, FixedBytes, U256};
use alloy_rlp::Decodable;

use super::{
    DepositTransaction, KeystoreAccount, KeystoreTxType, L2Transaction, OptionBytes,
    OptionBytesError, RlpUpdateTransaction, RlpWithdrawTransaction, UpdateTransaction,
    WithdrawTransaction,
};

pub trait TxDecode: Sized {
    type Error: std::error::Error;

    fn decode_l1_initiated_tx_bytes(
        tx_type: u8,
        l1_initiated_nonce: U256,
        amt: U256, // only relevant to deposit transaction
        bytes: Bytes,
    ) -> Result<Self, Self::Error>;

    fn decode_sequencer_batch_tx_bytes(tx_bytes: Bytes) -> Result<Self, Self::Error>;
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
    #[error("invalid keystore address")]
    InvalidKeystoreAddress,
}

impl DepositTransaction {
    fn decode_l1_initiated_tx_bytes(
        l1_initiated_nonce: U256,
        amt: U256,
        bytes: Bytes,
    ) -> Result<Self, TxDecodeError> {
        let keystore_address = FixedBytes::<32>::try_from(bytes.as_ref())
            .map_err(|_| TxDecodeError::InvalidKeystoreAddress)?;
        Ok(DepositTransaction::new(
            l1_initiated_nonce,
            amt,
            keystore_address,
        ))
    }

    // TODO: This method might be confusing because deposit transactions are always
    // L1-initiated. In essence, this method decode the
    // [`DepositTransaction::tx_bytes()`].
    //
    // The confusion will be resolved once we introduce the transaction request
    // abstraction.
    fn decode_sequencer_batch_tx_bytes(tx_bytes: Bytes) -> Result<Self, TxDecodeError> {
        // bytes tx_bytes = abi.encodePacked(
        //     KeystoreTxType.DEPOSIT, // 1 byte
        //     l1InitiatedNonce, // 32 bytes
        //     amt, // 32 bytes
        //     keystoreAddress // 32 bytes
        // );

        let expected_tx_bytes_len = 1 + 32 + 32 + 32;

        if tx_bytes.len() != expected_tx_bytes_len {
            return Err(TxDecodeError::InvalidLength);
        }

        let tx_type = KeystoreTxType::try_from(tx_bytes[0])
            .map_err(|_| TxDecodeError::InvalidKeystoreTxType)?;
        if tx_type != KeystoreTxType::Deposit {
            return Err(TxDecodeError::InvalidKeystoreTxType);
        }

        let l1_initiated_nonce = U256::from_be_slice(&tx_bytes[1..33]);
        let amt = U256::from_be_slice(&tx_bytes[33..65]);
        let keystore_address = FixedBytes::<32>::from_slice(&tx_bytes[65..]);

        Ok(DepositTransaction::new(
            l1_initiated_nonce,
            amt,
            keystore_address,
        ))
    }
}

impl WithdrawTransaction {
    fn decode_rlp_portion(
        is_l1_initiated: bool,
        l1_initiated_nonce: Option<U256>,
        rlp_bytes: &mut &[u8],
    ) -> Result<Self, TxDecodeError> {
        let rlp_withdraw_tx = RlpWithdrawTransaction::decode(rlp_bytes)?;

        let fee_per_gas = OptionBytes::try_from(rlp_withdraw_tx.fee_per_gas).map_err(|err| {
            TxDecodeError::OptionBytesDecodeFailed {
                field_name: "fee_per_gas",
                err,
            }
        })?;

        let user_acct = KeystoreAccount {
            keystore_address: rlp_withdraw_tx.user_acct_keystore_address,
            salt: rlp_withdraw_tx.user_acct_salt,
            data_hash: rlp_withdraw_tx.user_acct_data_hash,
            vkey: rlp_withdraw_tx.user_acct_vkey,
        };

        let withdraw_tx = WithdrawTransaction::new(
            is_l1_initiated,
            rlp_withdraw_tx.nonce,
            fee_per_gas,
            l1_initiated_nonce.into(),
            rlp_withdraw_tx.to,
            rlp_withdraw_tx.amt,
            user_acct,
            rlp_withdraw_tx.user_proof,
        );
        Ok(withdraw_tx)
    }

    fn decode_l1_initiated_tx_bytes(
        l1_initiated_nonce: U256,
        bytes: Bytes,
    ) -> Result<Self, TxDecodeError> {
        Self::decode_rlp_portion(true, Some(l1_initiated_nonce), &mut bytes.as_ref())
    }

    fn decode_sequencer_batch_tx_bytes(tx_bytes: Bytes) -> Result<Self, TxDecodeError> {
        if tx_bytes.len() < 2 {
            return Err(TxDecodeError::InvalidLength);
        }

        let tx_type = KeystoreTxType::try_from(tx_bytes[0])
            .map_err(|_| TxDecodeError::InvalidKeystoreTxType)?;
        if tx_type != KeystoreTxType::Withdraw {
            return Err(TxDecodeError::InvalidKeystoreTxType);
        }

        let is_l1_initiated = tx_bytes[1] != 0;
        if is_l1_initiated {
            return Err(TxDecodeError::IsL1Initiated);
        }

        let rlp_bytes = &mut &tx_bytes[2..];
        let withdraw_tx = Self::decode_rlp_portion(is_l1_initiated, None, rlp_bytes)?;
        Ok(withdraw_tx)
    }
}

impl UpdateTransaction {
    fn decode_rlp_portion(
        is_l1_initiated: bool,
        l1_initiated_nonce: Option<U256>,
        rlp_bytes: &mut &[u8],
    ) -> Result<Self, TxDecodeError> {
        let rlp_update_tx = RlpUpdateTransaction::decode(rlp_bytes)?;

        let fee_per_gas = OptionBytes::try_from(rlp_update_tx.fee_per_gas).map_err(|err| {
            TxDecodeError::OptionBytesDecodeFailed {
                field_name: "fee_per_gas",
                err,
            }
        })?;
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
            l1_initiated_nonce.into(),
            rlp_update_tx.new_user_data,
            rlp_update_tx.new_user_vkey,
            user_acct,
            rlp_update_tx.user_proof,
            sponsor_acct_bytes,
            rlp_update_tx.sponsor_proof,
        );
        Ok(update_tx)
    }

    fn decode_l1_initiated_tx_bytes(
        l1_initiated_nonce: U256,
        bytes: Bytes,
    ) -> Result<Self, TxDecodeError> {
        Self::decode_rlp_portion(true, Some(l1_initiated_nonce), &mut bytes.as_ref())
    }

    fn decode_sequencer_batch_tx_bytes(tx_bytes: Bytes) -> Result<Self, TxDecodeError> {
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

        let rlp_bytes = &mut &tx_bytes[2..];
        let update_tx = Self::decode_rlp_portion(is_l1_initiated, None, rlp_bytes)?;
        Ok(update_tx)
    }
}

impl TxDecode for L2Transaction {
    type Error = TxDecodeError;

    fn decode_l1_initiated_tx_bytes(
        tx_type: u8,
        l1_initiated_nonce: U256,
        amt: U256,
        bytes: Bytes,
    ) -> Result<Self, Self::Error> {
        let decoded_tx_type =
            KeystoreTxType::try_from(tx_type).map_err(|_| TxDecodeError::InvalidKeystoreTxType)?;
        let tx = match decoded_tx_type {
            KeystoreTxType::Deposit => {
                DepositTransaction::decode_l1_initiated_tx_bytes(l1_initiated_nonce, amt, bytes)?
                    .into()
            }
            KeystoreTxType::Withdraw => {
                WithdrawTransaction::decode_l1_initiated_tx_bytes(l1_initiated_nonce, bytes)?.into()
            }
            KeystoreTxType::Update => {
                UpdateTransaction::decode_l1_initiated_tx_bytes(l1_initiated_nonce, bytes)?.into()
            }
        };
        Ok(tx)
    }

    fn decode_sequencer_batch_tx_bytes(tx_bytes: Bytes) -> Result<Self, Self::Error> {
        let first_byte = tx_bytes.first().ok_or(TxDecodeError::InvalidLength)?;
        let tx_type = KeystoreTxType::try_from(*first_byte)
            .map_err(|_| TxDecodeError::InvalidKeystoreTxType)?;

        match tx_type {
            KeystoreTxType::Deposit => {
                let tx = DepositTransaction::decode_sequencer_batch_tx_bytes(tx_bytes)?;
                Ok(tx.into())
            }
            KeystoreTxType::Withdraw => {
                let tx = WithdrawTransaction::decode_sequencer_batch_tx_bytes(tx_bytes)?;
                Ok(tx.into())
            }
            KeystoreTxType::Update => {
                let tx = UpdateTransaction::decode_sequencer_batch_tx_bytes(tx_bytes)?;
                Ok(tx.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, Bytes, FixedBytes, U256};

    use crate::keystore_types::{
        contract, DepositTransactionBuilder, KeystoreAccount, L2Transaction, RollupTx, TxDecode,
        UpdateTransactionBuilder, WithdrawTransactionBuilder,
    };

    fn random_keystore_account() -> KeystoreAccount {
        KeystoreAccount {
            keystore_address: FixedBytes::<32>::random(),
            salt: FixedBytes::<32>::random(),
            data_hash: FixedBytes::<32>::random(),
            vkey: FixedBytes::<20>::random().into(),
        }
    }

    #[test]
    fn test_decode_update_tx_successful() -> eyre::Result<()> {
        // sequencer tx without sponsor
        {
            let user_acct = random_keystore_account();
            let tx1: L2Transaction = UpdateTransactionBuilder::default()
                .fee_per_gas(U256::from(5))
                .nonce(U256::from(10))
                .new_user_data(Bytes::from(FixedBytes::<20>::random()))
                .new_user_vkey(Bytes::from(FixedBytes::<20>::random()))
                .user_acct(user_acct.clone())
                .mock_user_proof()
                .build()
                .unwrap()
                .into();
            let tx_bytes = tx1.tx_bytes().clone();
            let tx2 = L2Transaction::decode_sequencer_batch_tx_bytes(tx_bytes)?;

            assert_eq!(tx1, tx2);
        }

        // sequencer tx with sponsor
        {
            let user_acct = random_keystore_account();
            let sponsor_acct = random_keystore_account();
            let tx1: L2Transaction = UpdateTransactionBuilder::default()
                .fee_per_gas(U256::from(5))
                .nonce(U256::from(10))
                .new_user_data(Bytes::from(FixedBytes::<20>::random()))
                .new_user_vkey(Bytes::from(FixedBytes::<20>::random()))
                .user_acct(user_acct.clone())
                .mock_user_proof()
                .sponsor_acct(Some(sponsor_acct))
                .mock_sponsor_proof()
                .build()
                .unwrap()
                .into();
            let tx_bytes = tx1.tx_bytes().clone();
            let tx2 = L2Transaction::decode_sequencer_batch_tx_bytes(tx_bytes)?;

            assert_eq!(tx1, tx2);
        }

        // L1 initiated tx
        {
            let user_acct = random_keystore_account();
            let sponsor_acct = random_keystore_account();

            let l1_initiated_nonce = U256::from(8);
            let tx1: L2Transaction = UpdateTransactionBuilder::default()
                .l1_initiated_nonce(l1_initiated_nonce)
                .nonce(U256::from(10))
                .new_user_data(Bytes::from(FixedBytes::<20>::random()))
                .new_user_vkey(Bytes::from(FixedBytes::<20>::random()))
                .user_acct(user_acct.clone())
                .mock_user_proof()
                .sponsor_acct(Some(sponsor_acct))
                .mock_sponsor_proof()
                .build()
                .unwrap()
                .into();
            let l1_initiated_tx =
                contract::AxiomKeystoreRollup::L1InitiatedTransaction::from(tx1.clone());

            let tx2 = L2Transaction::decode_l1_initiated_tx_bytes(
                l1_initiated_tx.txType,
                l1_initiated_nonce,
                U256::ZERO,
                l1_initiated_tx.data,
            )?;

            assert_eq!(tx1, tx2);
        }

        Ok(())
    }

    #[test]
    fn test_decode_withdraw_tx_successful() -> eyre::Result<()> {
        // sequencer tx
        {
            let user_acct = random_keystore_account();
            let tx1: L2Transaction = WithdrawTransactionBuilder::default()
                .fee_per_gas(U256::from(5))
                .nonce(U256::from(4))
                .to(Address::random())
                .amt(U256::from(12345))
                .user_acct(user_acct)
                .mock_user_proof()
                .build()
                .unwrap()
                .into();
            let tx_bytes = tx1.tx_bytes().clone();
            let tx2 = L2Transaction::decode_sequencer_batch_tx_bytes(tx_bytes)?;

            assert_eq!(tx1, tx2);
        }

        // L1-initiated tx
        {
            let user_acct = random_keystore_account();
            let l1_initiated_nonce = U256::from(5);
            let tx1: L2Transaction = WithdrawTransactionBuilder::default()
                .l1_initiated_nonce(l1_initiated_nonce)
                .nonce(U256::from(4))
                .to(Address::random())
                .amt(U256::from(12345))
                .user_acct(user_acct)
                .mock_user_proof()
                .build()
                .unwrap()
                .into();
            let l1_initiated_tx =
                contract::AxiomKeystoreRollup::L1InitiatedTransaction::from(tx1.clone());
            let tx2 = L2Transaction::decode_l1_initiated_tx_bytes(
                tx1.tx_type() as u8,
                l1_initiated_nonce,
                U256::ZERO,
                l1_initiated_tx.data,
            )?;

            assert_eq!(tx1, tx2);
        }

        Ok(())
    }

    #[test]
    fn test_decode_deposit_tx_successful() -> eyre::Result<()> {
        // sequencer tx
        {
            let l1_initiated_nonce = U256::from(123);
            let tx1: L2Transaction = DepositTransactionBuilder::default()
                .l1_initiated_nonce(l1_initiated_nonce)
                .amt(U256::from(2345))
                .keystore_address(FixedBytes::random())
                .build()
                .unwrap()
                .into();
            let tx_bytes = tx1.tx_bytes().clone();
            let tx2 = L2Transaction::decode_sequencer_batch_tx_bytes(tx_bytes)?;

            assert_eq!(tx1, tx2);
        }

        // L1-initiated tx
        {
            let l1_initiated_nonce = U256::from(123);
            let amt = U256::from(2345);
            let tx1: L2Transaction = DepositTransactionBuilder::default()
                .l1_initiated_nonce(l1_initiated_nonce)
                .amt(U256::from(2345))
                .keystore_address(FixedBytes::random())
                .build()
                .unwrap()
                .into();
            let l1_initiated_tx =
                contract::AxiomKeystoreRollup::L1InitiatedTransaction::from(tx1.clone());
            let tx2 = L2Transaction::decode_l1_initiated_tx_bytes(
                tx1.tx_type() as u8,
                l1_initiated_nonce,
                amt,
                l1_initiated_tx.data,
            )?;

            assert_eq!(tx1, tx2);
        }

        Ok(())
    }
}
