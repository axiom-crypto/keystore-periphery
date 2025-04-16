use alloy_sol_types::sol;

sol!(
    #[derive(Debug)]
    #[sol(rpc)]
    #[allow(clippy::too_many_arguments)]
    AxiomKeystoreRollup,
    "src/keystore_types/abi/AxiomKeystoreRollup.json"
);
