#![no_std]

use alloy_primitives::{Bytes, B256};
use serde::{Deserialize, Serialize};

use openvm::io::reveal;
use openvm_keccak256_guest::keccak256;

extern crate alloc;

/// This module specifies the format of the public values in the final
/// SNARK proof to be verified onchain. It will only be compiled on
/// host machines, but affects the final SNARK resulting from the guest
/// program.
#[cfg(not(target_os = "zkvm"))]
pub mod public_values;

#[derive(Clone, Serialize, Deserialize)]
pub struct SignatureProverInput<K: KeyData, A> {
    pub msg_hash: B256,
    pub key_data: K,
    pub auth_data: A,
}

pub trait KeyData {
    fn encode(&self) -> Bytes;

    fn data_hash(&self) -> B256 {
        keccak256(&self.encode()).into()
    }
}

/// Formats the `msg_hash` and `data_hash` into concatenated hi-lo format in the circuit public values
pub fn set_public_values(data_hash: B256, msg_hash: B256) {
    let data_hash_u32_repr =
        unsafe { core::mem::transmute::<[u8; 32], [u32; 8]>(data_hash.into()) };
    let msg_hash_u32_repr = unsafe { core::mem::transmute::<[u8; 32], [u32; 8]>(msg_hash.into()) };
    [data_hash_u32_repr, msg_hash_u32_repr]
        .concat()
        .iter()
        .enumerate()
        .for_each(|(i, val)| {
            reveal(*val, i);
        });
}
