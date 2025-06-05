// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IKeystoreStateOracle {
    function keystoreStateRoots(bytes32 keystoreStateRoot) external view returns (uint48 l1BlockTimestamp);
}
