use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolStruct};
use serde::Serialize;

use super::EIP712_DOMAIN;

sol! {
    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct Withdraw {
        bytes32 userKeystoreAddress;
        uint256 nonce;
        bytes feePerGas;
        address to;
        uint256 amt;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct Update {
        bytes32 userKeystoreAddress;
        uint256 nonce;
        bytes feePerGas;
        bytes newUserData;
        bytes newUserVkey;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct Sponsor {
        bytes32 sponsorKeystoreAddress;
        bytes32 userMsgHash;
        bytes32 userKeystoreAddress;
    }
}

pub fn withdraw_user_msg_hash(
    user_keystore_address: FixedBytes<32>,
    nonce: U256,
    fee_per_gas: &Bytes,
    to: Address,
    amt: U256,
) -> FixedBytes<32> {
    let withdraw = Withdraw {
        userKeystoreAddress: user_keystore_address,
        nonce,
        feePerGas: fee_per_gas.clone(),
        to,
        amt,
    };
    withdraw.eip712_signing_hash(&EIP712_DOMAIN)
}

pub fn update_user_msg_hash(
    user_keystore_address: FixedBytes<32>,
    nonce: U256,
    fee_per_gas: &Bytes,
    new_user_data: &Bytes,
    new_user_vkey: &Bytes,
) -> FixedBytes<32> {
    let update = Update {
        userKeystoreAddress: user_keystore_address,
        nonce,
        feePerGas: fee_per_gas.clone(),
        newUserData: new_user_data.clone(),
        newUserVkey: new_user_vkey.clone(),
    };
    update.eip712_signing_hash(&EIP712_DOMAIN)
}

pub fn sponsor_msg_hash(
    sponsor_keystore_address: FixedBytes<32>,
    user_msg_hash: FixedBytes<32>,
    user_keystore_address: FixedBytes<32>,
) -> FixedBytes<32> {
    let sponsor = Sponsor {
        sponsorKeystoreAddress: sponsor_keystore_address,
        userMsgHash: user_msg_hash,
        userKeystoreAddress: user_keystore_address,
    };
    sponsor.eip712_signing_hash(&EIP712_DOMAIN)
}
