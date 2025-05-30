// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IKeystoreStateOracle } from "../interfaces/IKeystoreStateOracle.sol";

abstract contract KeystoreStateOracle is IKeystoreStateOracle {
    error TimestampTooOld();

    bytes32 public latestStateRoot;
    mapping(bytes32 keystoreStateRoot => uint48 l1BlockTimestamp) public keystoreStateRoots;

    function _cacheKeystoreStateRoot(bytes32 stateRoot, uint48 l1BlockTimestamp) internal {
        // We don't want to allow older timestamps to prevent frontrunning
        // of would-be-valid userOps ending up as expired.
        uint48 currentTimestamp = keystoreStateRoots[stateRoot];
        if (l1BlockTimestamp < currentTimestamp) revert TimestampTooOld();

        // If caching a state root that has already been cached, we'll want to
        // update its associated blockTimestamp first
        keystoreStateRoots[stateRoot] = l1BlockTimestamp;

        // The first time a state root is cached, `latestTimestamp` will be 0.
        uint48 latestTimestamp = keystoreStateRoots[latestStateRoot];
        if (l1BlockTimestamp > latestTimestamp) latestStateRoot = stateRoot;
    }
}
