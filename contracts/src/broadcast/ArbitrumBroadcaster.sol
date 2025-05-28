// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IAxiomKeystoreRollup } from "../interfaces/IAxiomKeystoreRollup.sol";
import { IArbitrumStateOracle } from "../interfaces/IArbitrumStateOracle.sol";
import { IArbitrumL1Inbox } from "../interfaces/IArbitrumL1Inbox.sol";

/// @dev This contract is expected to be paired with an `ArbitrumStateOracle`.
contract ArbitrumBroadcaster {
    IAxiomKeystoreRollup public immutable KEYSTORE_ROLLUP;

    IArbitrumL1Inbox public immutable ARBITRUM_INBOX;

    address public immutable L2_KEYSTORE_STATE_ORACLE;

    error InvalidOutputRoot(bytes32 derivedOutputRoot, bytes32 keystoreOutputRoot);

    constructor(address arbitrumInbox, address keystoreRollup, address l2KeystoreStateOracle) {
        ARBITRUM_INBOX = IArbitrumL1Inbox(arbitrumInbox);
        KEYSTORE_ROLLUP = IAxiomKeystoreRollup(keystoreRollup);
        L2_KEYSTORE_STATE_ORACLE = l2KeystoreStateOracle;
    }

    /// @notice Broadcast a keystore state root to the L2 Keystore State Oracle.
    ///
    /// @dev There are two types of fees that the creator of a retryable ticket must pay for.
    ///
    /// 1. The submission fee which is computed as a function of the calldata
    ///    length of the L2 call and the L1 `block.basefee` at the time of ticket
    ///    creation. This is upper-bounded by `maxSubmissionCost`.
    /// 2. The execution fee on L2 which is charged at the time of L2 execution.
    /// This is upper-bounded by `maxFeePerGas * gasLimit`.
    ///
    /// During redemption on L2, the specified call will be front-run with a transaction that:
    /// - Mints the entire `msg.value` of this call to this contract's alias address.
    /// - Charges the exact submission fee.
    /// - Refunds `maxSubmissionCost - submissionCost` to `excessFeeRefundAddress`.
    /// - Charges the exact execution fee as `feePerGas * gasLimit`.
    /// - Refunds `(maxFeePerGas - feePerGas) * gasLimit` to `excessFeeRefundAddress`.
    ///
    /// This contract is expected to be paired with an `ArbitrumStateOracle`. If
    /// the `gasLimit` is chosen properly, the redemption of the ticket is
    /// expected to never fail. In the case of failure, the
    /// `ArbitrumStateOracle` is resistant to out of order execution by
    /// enforcing an always-increasing timestamp.
    ///
    /// @param outputRootPreimage The preimage of the output root, used for decommitting the state root.
    /// @param gasLimit The gas limit for the L2 call.
    /// @param maxFeePerGas The maximum amount to pay for one unit of L2 gas.
    /// @param maxSubmissionCost The maximum amount to pay for the submission fee.
    /// @param excessFeeRefundAddress The address to refund excess fees to.
    function broadcast(
        IAxiomKeystoreRollup.OutputRootPreimage calldata outputRootPreimage,
        uint32 gasLimit,
        uint256 maxFeePerGas,
        uint256 maxSubmissionCost,
        address excessFeeRefundAddress
    ) public payable {
        bytes32 outputRoot = KEYSTORE_ROLLUP.latestOutputRoot();
        uint48 l1BlockTimestamp = uint48(block.timestamp);

        bytes32 derivedOutputRoot;
        /// @solidity memory-safe-assembly
        assembly {
            let fmp := mload(0x40)
            calldatacopy(fmp, outputRootPreimage, 0x60)
            derivedOutputRoot := keccak256(fmp, 0x60)
        }

        if (derivedOutputRoot != outputRoot) revert InvalidOutputRoot(derivedOutputRoot, outputRoot);

        bytes memory _calldata = abi.encodeCall(
            IArbitrumStateOracle.cacheKeystoreStateRoot, (outputRootPreimage.stateRoot, l1BlockTimestamp)
        );

        ARBITRUM_INBOX.createRetryableTicket{ value: msg.value }({
            to: address(L2_KEYSTORE_STATE_ORACLE),
            l2CallValue: 0,
            maxSubmissionCost: maxSubmissionCost,
            excessFeeRefundAddress: excessFeeRefundAddress,
            // We can just set to address(0) since there is no `l2CallValue`
            callValueRefundAddress: address(0),
            gasLimit: gasLimit,
            maxFeePerGas: maxFeePerGas,
            data: _calldata
        });
    }
}
