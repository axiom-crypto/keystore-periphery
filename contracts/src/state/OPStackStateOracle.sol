// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IStorageProofVerifier } from "../interfaces/IStorageProofVerifier.sol";
import { IL1Block } from "../interfaces/IL1Block.sol";
import { RLPReader } from "../vendor/optimism-mpt/rlp/RLPReader.sol";
import { KeystoreStateOracle } from "./KeystoreStateOracle.sol";

import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract OPStackStateOracle is Ownable2Step, KeystoreStateOracle {
    address internal constant L1BLOCK = 0x4200000000000000000000000000000000000015;

    event BlockhashCached(bytes32 _blockhash);

    error StorageProofTooOld();

    error BlockhashNotFound(bytes32 _blockhash);

    mapping(bytes32 _blockhash => bool) public blockhashes;

    IStorageProofVerifier public storageProofVerifier;

    // TODO: We need to move away from `msg.sender` as the owner of the contract
    // to support factory deployment
    constructor(
        IStorageProofVerifier _storageProofVerifier,
        address keystoreBridgeAddress,
        bytes32 keystoreStateRootStorageSlot
    ) Ownable(msg.sender) KeystoreStateOracle(keystoreBridgeAddress, keystoreStateRootStorageSlot) {
        storageProofVerifier = _storageProofVerifier;
    }

    function updateStorageProofVerifier(IStorageProofVerifier _newVerifier) external onlyOwner {
        storageProofVerifier = _newVerifier;
    }

    /// @notice Cache an L1 blockhash in storage
    function cacheBlockhash() external {
        bytes4 hashSelector = IL1Block.hash.selector;
        bytes32 _blockhash;

        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, hashSelector)
            // TODO: revert with error selector
            if iszero(call(gas(), L1BLOCK, 0, 0x00, 0x20, 0x00, 0x20)) { revert(0, 0) }

            _blockhash := mload(0x00)
        }

        emit BlockhashCached(_blockhash);

        blockhashes[_blockhash] = true;
    }

    function cacheKeystoreStateRootWithProof(
        IStorageProofVerifier.StorageProof calldata storageProof,
        OutputRootPreimage calldata outputRootPreimage
    ) external {
        (bytes32 keystoreOutputRoot, bytes32 _blockhash) = storageProofVerifier.verifyStorageSlot({
            storageProof: storageProof,
            _address: KEYSTORE_BRIDGE_ADDRESS,
            storageSlot: KEYSTORE_STATE_ROOT_STORAGE_SLOT
        });
        if (!blockhashes[_blockhash]) revert BlockhashNotFound(_blockhash);

        bytes32 derivedOutputRoot = keccak256(
            abi.encodePacked(
                outputRootPreimage.stateRoot, outputRootPreimage.withdrawalsRoot, outputRootPreimage.lastValidBlockhash
            )
        );
        if (derivedOutputRoot != keystoreOutputRoot) revert InvalidOutputRoot(derivedOutputRoot, keystoreOutputRoot);
        bytes32 keystoreStateRoot = outputRootPreimage.stateRoot;

        bytes calldata blockHeader = storageProof.blockHeader;
        // TODO: Replace with efficient RLP reader
        RLPReader.RLPItem[] memory blockHeaderRlp = RLPReader.readList(blockHeader);

        // TODO: This needs to be revisited. The blockTimestamp appears to be a right-padded uint32 value.
        uint48 blockTimestamp = uint32(bytes4(bytes32(RLPReader.readBytes(blockHeaderRlp[11]))));

        // We don't want to allow older storage proofs to prevent frontrunning
        // of would-be-valid userOps ending up as expired.
        uint48 currentTimestamp = keystoreStateRoots[keystoreStateRoot];
        if (blockTimestamp < currentTimestamp) revert StorageProofTooOld();

        // If caching a state root that has already been cached, we'll want to
        // update its associated blockTimestamp first
        keystoreStateRoots[keystoreStateRoot] = blockTimestamp;

        // For the first state root being cached, `latestTimestamp` will be 0.
        uint48 latestTimestamp = keystoreStateRoots[latestStateRoot];
        if (blockTimestamp > latestTimestamp) latestStateRoot = keystoreStateRoot;
    }
}
