// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IKeyDataConsumer {
    /// @param authData needs to be valid against the `keyData`
    function consumeKeyData(bytes calldata keyData, bytes calldata authData, bytes32 userOpHash) external view;
}
