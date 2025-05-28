// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IArbitrumStateOracle {
    function cacheKeystoreStateRoot(bytes32 stateRoot, uint48 l1BlockTimestamp) external;
}
