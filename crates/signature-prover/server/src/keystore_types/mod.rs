use alloy_primitives::{Bytes, B256};

mod hash;
pub use hash::*;

mod decoder;
pub use decoder::*;

mod transaction;
pub use transaction::*;

pub mod contract;

pub type L2TransactionHash = B256;

pub trait RollupTx {
    fn tx_bytes(&self) -> &Bytes;

    fn into_tx_bytes(self) -> Bytes;

    fn tx_hash(&self) -> L2TransactionHash;
}
