// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IAxiomKeystoreRollup {
    struct OutputRootPreimage {
        bytes32 stateRoot;
        bytes32 withdrawalsRoot;
        bytes32 lastValidBlockhash;
    }

    function latestOutputRoot() external view returns (bytes32);
}
