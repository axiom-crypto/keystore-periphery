// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IKeystoreStateOracle } from "../interfaces/IKeystoreStateOracle.sol";

abstract contract KeystoreStateOracle is IKeystoreStateOracle {
    error InvalidOutputRoot(bytes32 derivedOutputRoot, bytes32 keystoreOutputRoot);

    bytes32 public latestStateRoot;
    mapping(bytes32 keystoreStateRoot => uint48 l1BlockTimestamp) public keystoreStateRoots;

    address public immutable KEYSTORE_BRIDGE_ADDRESS;
    bytes32 public immutable KEYSTORE_STATE_ROOT_STORAGE_SLOT;

    // We probably won't want to use `msg.sender` if using a factory for deployment
    constructor(address keystoreBridgeAddress, bytes32 keystoreStateRootStorageSlot) {
        KEYSTORE_BRIDGE_ADDRESS = keystoreBridgeAddress;
        KEYSTORE_STATE_ROOT_STORAGE_SLOT = keystoreStateRootStorageSlot;
    }

    // TODO: Add this back in with check on msg.sender == canonicalBridge and l1Sender == broadcaster
    // function cacheKeystoreStateRootNative(
    //     bytes32 keystoreOutputRoot,
    //     uint48 l1BlockTimestamp,
    //     OutputRootPreimage calldata outputRootPreimage
    // ) external {
    // }
}
