use alloy_primitives::{keccak256, Bytes, FixedBytes};

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
        let keystore_address = keccak256([salt, data_hash, keccak256(&vkey)].concat());
        Self {
            keystore_address,
            salt,
            data_hash,
            vkey,
        }
    }
}
