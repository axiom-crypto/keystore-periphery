// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { KeystoreStateOracle } from "./KeystoreStateOracle.sol";

/// @dev This contract is expected to be paired with an `ArbitrumBroadcaster`.
contract ArbitrumStateOracle is KeystoreStateOracle {
    address public immutable BROADCASTER;

    error InvalidL1Sender(address l1Sender);

    constructor(address broadcaster) {
        BROADCASTER = broadcaster;
    }

    /// @notice Caches the state root for the given L1 block timestamp.
    /// @dev This function is expected to be called by the `ArbitrumBroadcaster` from L1.
    ///
    /// This function is resistant to out of order execution by enforcing an
    /// always-increasing timestamp.
    ///
    /// @param stateRoot The state root to cache.
    /// @param l1BlockTimestamp The L1 block timestamp from which the state root was read.
    function cacheStateRoot(bytes32 stateRoot, uint48 l1BlockTimestamp) external {
        if (_l1Sender() != BROADCASTER) revert InvalidL1Sender(_l1Sender());

        _cacheKeystoreStateRoot(stateRoot, l1BlockTimestamp);
    }

    function _l1Sender() internal view returns (address out) {
        // Underflow desirable
        assembly {
            out := sub(caller(), 0x1111000000000000000000000000000000001111)
        }
    }
}
