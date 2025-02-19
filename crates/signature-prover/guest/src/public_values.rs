use alloc::vec::Vec;
use openvm_native_compiler::ir::{Builder, SymbolicVar, Var};
use openvm_native_recursion::{config::outer::OuterConfig, vars::StarkProofVariable};
use openvm_sdk::{
    keygen::RootVerifierProvingKey,
    static_verifier::StaticVerifierPvHandler,
    verifier::{
        common::types::SpecialAirIds, root::types::RootVmVerifierPvs,
        utils::compress_babybear_var_to_bn254,
    },
};
use openvm_stark_sdk::{openvm_stark_backend::p3_field::FieldAlgebra, p3_bn254_fr::Bn254Fr};

/// A custom handler to format the public values of the EVM proof
/// into the format required by the keystore update transaction format.
pub struct UpdateTxPublicValuesHandler {
    pub exe_commit: Bn254Fr,
    pub leaf_verifier_commit: Bn254Fr,
}

impl StaticVerifierPvHandler for UpdateTxPublicValuesHandler {
    fn handle_public_values(
        &self,
        builder: &mut Builder<OuterConfig>,
        input: &StarkProofVariable<OuterConfig>,
        _root_verifier_pk: &RootVerifierProvingKey,
        special_air_ids: &SpecialAirIds,
    ) -> usize {
        let pv_air = builder.get(&input.per_air, special_air_ids.public_values_air_id);
        let public_values: Vec<_> = pv_air
            .public_values
            .vec()
            .into_iter()
            .map(|x| builder.cast_felt_to_var(x))
            .collect();
        let pvs = RootVmVerifierPvs::from_flatten(public_values);
        let exe_commit = compress_babybear_var_to_bn254(builder, pvs.exe_commit);
        let leaf_commit = compress_babybear_var_to_bn254(builder, pvs.leaf_verifier_commit);

        let expected_exe_commit: Var<Bn254Fr> = builder.constant(self.exe_commit);
        let expected_leaf_commit: Var<Bn254Fr> = builder.constant(self.leaf_verifier_commit);

        builder.assert_var_eq(exe_commit, expected_exe_commit);
        builder.assert_var_eq(leaf_commit, expected_leaf_commit);

        // Chunk public values into little-endian arrays of size 16
        let pvs_chunks_le: Vec<[Var<Bn254Fr>; 16]> = pvs
            .public_values
            .chunks(16)
            .map(|x| {
                let mut x_le = x.to_vec();
                x_le.reverse();
                x_le.try_into().unwrap()
            })
            .collect::<Vec<_>>();
        let pvs_chunks_bn254fr = pvs_chunks_le
            .iter()
            .enumerate()
            .map(|(i, &x)| {
                let var = pack_bn254fr_u8(builder, x);
                builder.static_commit_public_value(i, var);
                var
            })
            .collect::<Vec<_>>();
        pvs_chunks_bn254fr.len()
    }
}

/// Packs 16 Bn254Fr, each representing a single u8, into a single Bn254Fr.
/// Used for packing to hi-lo.
fn pack_bn254fr_u8(builder: &mut Builder<OuterConfig>, var: [Var<Bn254Fr>; 16]) -> Var<Bn254Fr> {
    let step = Bn254Fr::from_canonical_u32(0x100);
    let mut ret = SymbolicVar::ZERO;
    let mut base = Bn254Fr::ONE;
    var.iter().for_each(|&x| {
        ret += x * base;
        base *= step;
    });
    builder.eval(ret)
}
