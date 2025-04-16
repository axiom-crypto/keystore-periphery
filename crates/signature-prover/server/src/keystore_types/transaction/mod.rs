mod l2_tx;
pub use l2_tx::*;

mod update_tx;
pub use update_tx::*;

mod deposit_tx;
pub use deposit_tx::*;

mod withdraw_tx;
pub use withdraw_tx::*;

mod option_bytes;
pub use option_bytes::*;

mod account;
pub use account::*;

mod constants {
    use std::sync::LazyLock;

    use alloy_dyn_abi::Eip712Domain;
    use alloy_primitives::{keccak256, utils::parse_ether, Bytes, FixedBytes, U256};
    use alloy_sol_types::eip712_domain;

    pub const EIP712_REVISION: Bytes = Bytes::from_static(b"1");
    pub const EIP712_DOMAIN: Eip712Domain = eip712_domain!(
        name: "AxiomKeystore",
        version: "1",
        chain_id: 999999999,
    );

    pub static WITHDRAW_TYPEHASH: LazyLock<FixedBytes<32>> = LazyLock::new(|| {
        keccak256("Withdraw(bytes32 userKeystoreAddress,uint256 nonce,bytes feePerGas,address to,uint256 amt)")
    });

    pub static UPDATE_TYPEHASH: LazyLock<FixedBytes<32>> = LazyLock::new(|| {
        keccak256("Update(bytes32 userKeystoreAddress,uint256 nonce,bytes feePerGas,bytes newUserData,bytes newUserVkey)")
    });

    pub static SPONSOR_TYPEHASH: LazyLock<FixedBytes<32>> = LazyLock::new(|| {
        keccak256(
        "Sponsor(bytes32 sponsorKeystoreAddress,bytes32 userMsgHash,bytes32 userKeystoreAddress)",
    )
    });

    pub static WITHDRAW_GAS: LazyLock<U256> = LazyLock::new(|| U256::from(100_000));
    pub static UPDATE_GAS: LazyLock<U256> = LazyLock::new(|| U256::from(100_000));

    pub static DEPOSIT_L1_COST: LazyLock<U256> = LazyLock::new(|| parse_ether("0.001").unwrap());
    pub static WITHDRAW_L1_COST: LazyLock<U256> = LazyLock::new(|| parse_ether("0.005").unwrap());
    pub static UPDATE_L1_COST: LazyLock<U256> = LazyLock::new(|| parse_ether("0.005").unwrap());
}
pub use constants::*;

mod utils {
    use alloy_primitives::{Bytes, FixedBytes};

    pub fn gen_tx_mock_proof(data_hash: FixedBytes<32>, msg_hash: FixedBytes<32>) -> Bytes {
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
}
pub use utils::*;
