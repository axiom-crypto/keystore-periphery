// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IKeystoreStateOracle {
    struct OutputRootPreimage {
        bytes32 stateRoot;
        bytes32 withdrawalsRoot;
        bytes32 lastValidBlockhash;
    }

    function keystoreStateRoots(bytes32 keystoreStateRoot) external view returns (uint48 l1BlockTimestamp);
}
