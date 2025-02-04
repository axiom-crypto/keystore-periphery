// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IL1Block } from "./interfaces/IL1Block.sol";
import { IStorageProofVerifier } from "./interfaces/IStorageProofVerifier.sol";

import { UserOperationLib } from "account-abstraction/core/UserOperationLib.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IAggregator } from "account-abstraction/interfaces/IAggregator.sol";

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract KeystoreAggregator is IAggregator, Ownable2Step {
    address internal constant L1BLOCK = 0x4200000000000000000000000000000000000015;

    event BlockhashCached(bytes32 _blockhash);

    struct KeyDataMerkleProof {
        bool isExclusion;
        // Only parsed if `isExclusion` is true
        // abi.encodePacked(prevDummyByte, prevImtKey, salt, valueHash)
        bytes exclusionExtraData;
        bytes1 nextDummyByte;
        bytes32 nextImtKey;
        bytes32 vkeyHash;
        bytes32 keystoreAddress;
        uint256 requiredSigners;
        address[] allowedSignersList;
        bytes32[] proof;
        uint256 isLeft;
    }

    struct AggregatedSignatureData {
        IStorageProofVerifier.StorageProof[] storageProofs;
        uint256[] derivedStateRootIndices;
    }

    /// @dev Per userOp. The expected structure of the `signature` field in
    /// `PackedUserOperation`
    struct UnaggregatedSignatureData {
        IStorageProofVerifier.StorageProof storageProof;
        KeyDataMerkleProof keyDataProof;
        bytes signatures;
    }

    IStorageProofVerifier public storageProofVerifier;

    mapping(bytes32 _blockhash => bool) public blockhashes;

    error BlockhashNotFound();

    error LengthMismatch();

    error InvalidSignatureLength();

    error InvalidSignature();

    error InvalidKeyDataMerkleProof();

    bytes1 internal constant NON_DUMMY_BYTE = 0x01;
    bytes1 internal constant ACTIVE_LEAF_BYTE = 0x01;

    address public immutable KEYSTORE_BRIDGE_ADDRESS = 0xfcF29D0bC588277984c6e1d00ba2f149E516a74D;
    bytes32 public immutable KEYSTORE_STATE_ROOT_STORAGE_SLOT = 0;

    bytes2 internal constant SILOING_BYTES = bytes2(0x0000);

    constructor(IStorageProofVerifier _storageProofVerifier) Ownable(msg.sender) {
        storageProofVerifier = _storageProofVerifier;
    }

    /**
     * @notice This does not completely validate the `userOp`s. It only
     * validates the key data. It is assumed that the smart account itself will
     * use this key data to fully validate its respective `userOp`.
     *
     * Validate aggregated signature.
     * Revert if the aggregated signature does not match the given list of operations.
     * @param userOps   - Array of UserOperations to validate the signature for.
     * @param signature - The aggregated signature.
     */
    function validateSignatures(PackedUserOperation[] calldata userOps, bytes calldata signature) external view {
        AggregatedSignatureData calldata data = _decode(signature);

        // Verify all the storage proofs for the relevant keystore state roots
        bytes32[] memory keystoreStateRoots = _verifyKeystoreStateRoots(data.storageProofs);

        uint256 userOpsLength = userOps.length;

        for (uint256 i = 0; i != userOpsLength; ++i) {
            PackedUserOperation calldata userOp = userOps[i];
            UnaggregatedSignatureData calldata decodedData = _decodeUserOpSignature(userOp.signature);

            KeyDataMerkleProof calldata keyDataProof = decodedData.keyDataProof;
            uint256[] calldata derivedStateRootIndices = data.derivedStateRootIndices;
            _validateKeyData(keyDataProof, keystoreStateRoots[derivedStateRootIndices[i]]);
        }
    }

    /// @dev Verifies a set of storage proofs verifying the keystore storage
    /// slot at various blocks (committing into various blockhashes).
    ///
    /// @param storageProofs - The storage proofs to verify.
    /// @return keystoreStateRoots - The keystore state roots corresponding to
    /// the storage proofs.
    function _verifyKeystoreStateRoots(IStorageProofVerifier.StorageProof[] calldata storageProofs)
        internal
        view
        returns (bytes32[] memory)
    {
        uint256 length = storageProofs.length;
        bytes32[] memory keystoreStateRoots = new bytes32[](length);
        for (uint256 i = 0; i != length; ++i) {
            (bytes32 keystoreStateRoot, bytes32 _blockhash) = storageProofVerifier.verifyStorageSlot({
                storageProof: storageProofs[i],
                _address: KEYSTORE_BRIDGE_ADDRESS,
                storageSlot: KEYSTORE_STATE_ROOT_STORAGE_SLOT
            });

            if (!blockhashes[_blockhash]) revert BlockhashNotFound();

            keystoreStateRoots[i] = keystoreStateRoot;
        }

        return keystoreStateRoots;
    }

    function _decode(bytes calldata signature) internal pure returns (AggregatedSignatureData calldata out) {
        /// @solidity memory-safe-assembly
        assembly {
            out := signature.offset
        }
    }

    /**
     * @notice This does not completely validate the `userOp`. It only
     * validates the key data. It is assumed that the smart account itself will
     * use this key data to fully validate its respective `userOp`.
     *
     * Validate signature of a single userOp.
     * This method should be called by bundler after EntryPointSimulation.simulateValidation() returns
     * the aggregator this account uses.
     * First it validates the signature over the userOp. Then it returns data to be used when creating the handleOps.
     * @param userOp        - The userOperation received from the user.
     * @return sigForUserOp - The value to put into the signature field of the userOp when calling handleOps.
     *                        (usually empty, unless account and aggregator support some kind of "multisig".
     */
    function validateUserOpSignature(PackedUserOperation calldata userOp)
        external
        view
        returns (bytes memory sigForUserOp)
    {
        UnaggregatedSignatureData calldata data = _decodeUserOpSignature(userOp.signature);

        // Verify the keystore state root into the blockhash
        (bytes32 keystoreStateRoot, bytes32 _blockhash) = storageProofVerifier.verifyStorageSlot({
            storageProof: data.storageProof,
            _address: KEYSTORE_BRIDGE_ADDRESS,
            storageSlot: KEYSTORE_STATE_ROOT_STORAGE_SLOT
        });
        if (!blockhashes[_blockhash]) revert BlockhashNotFound();

        // Verify the key data into the keystore state root
        _validateKeyData(data.keyDataProof, keystoreStateRoot);

        return userOp.signature;
    }

    /// @dev Validates the key data into the keystore state root.
    /// @param keyDataProof - The key data proof to validate.
    function _validateKeyData(KeyDataMerkleProof calldata keyDataProof, bytes32 imtRoot) internal pure {
        bytes32 dataHash = keccak256(abi.encode(keyDataProof.requiredSigners, keyDataProof.allowedSignersList));

        if (keyDataProof.isExclusion) {
            (bytes1 prevDummyByte, bytes32 prevImtKey, bytes32 salt, bytes32 valueHash) =
                _parseExclusionExtraData(keyDataProof.exclusionExtraData);

            bytes32 derivedKeystoreAddress = keccak256(abi.encodePacked(salt, dataHash, keyDataProof.vkeyHash));
            require(keyDataProof.keystoreAddress == derivedKeystoreAddress, "Invalid keystore address");

            bytes32 imtKey = keccak256(abi.encodePacked(SILOING_BYTES, derivedKeystoreAddress));
            // TODO: Right now DUMMY byte represents both highest and lowest. May be a vuln here.
            require(
                (imtKey > prevImtKey || prevDummyByte == 0x00)
                    && (imtKey < keyDataProof.nextImtKey || keyDataProof.nextDummyByte == 0x00),
                "Not an exclusion proof"
            );

            bytes32 leafNode = _constructImtLeafNode({
                dummyByte: prevDummyByte,
                imtKey: prevImtKey,
                nextDummyByte: keyDataProof.nextDummyByte,
                nextImtKey: keyDataProof.nextImtKey,
                valueHash: valueHash
            });

            _verifyMerkleProof(keyDataProof.proof, imtRoot, leafNode, keyDataProof.isLeft);
        } else {
            bytes32 valueHash = keccak256(abi.encodePacked(dataHash, keyDataProof.vkeyHash));
            bytes32 imtKey = keccak256(abi.encodePacked(SILOING_BYTES, keyDataProof.keystoreAddress));
            bytes32 leafNode = _constructImtLeafNode({
                dummyByte: NON_DUMMY_BYTE,
                imtKey: imtKey,
                nextDummyByte: keyDataProof.nextDummyByte,
                nextImtKey: keyDataProof.nextImtKey,
                valueHash: valueHash
            });

            _verifyMerkleProof(keyDataProof.proof, imtRoot, leafNode, keyDataProof.isLeft);
        }
    }

    function _parseExclusionExtraData(bytes calldata extraData)
        internal
        pure
        returns (bytes1 prevDummyByte, bytes32 prevImtKey, bytes32 salt, bytes32 valueHash)
    {
        /// @solidity memory-safe-assembly
        assembly {
            salt := calldataload(add(extraData.offset, 0x21))
            valueHash := calldataload(add(extraData.offset, 0x41))
            calldatacopy(0x1f, extraData.offset, 0x21)
            prevDummyByte := mload(0x1f)
            prevImtKey := mload(0x20)
        }
    }

    function _constructImtLeafNode(
        bytes1 dummyByte,
        bytes32 imtKey,
        bytes1 nextDummyByte,
        bytes32 nextImtKey,
        bytes32 valueHash
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                ACTIVE_LEAF_BYTE, // Should be active
                dummyByte,
                imtKey,
                nextDummyByte,
                nextImtKey,
                valueHash
            )
        );
    }

    function _verifyMerkleProof(bytes32[] calldata proof, bytes32 root, bytes32 leafNode, uint256 isLeft)
        internal
        pure
    {
        uint256 length = proof.length;
        bytes32 currentNode = leafNode;
        for (uint256 i = 0; i != length; ++i) {
            bool _isLeft = isLeft >> i & 1 == 1;

            if (_isLeft) currentNode = _efficientHash(proof[i], currentNode);
            else currentNode = _efficientHash(currentNode, proof[i]);
        }

        require(root == currentNode, "Invalid merkle proof");
    }

    function _efficientHash(bytes32 left, bytes32 right) internal pure returns (bytes32 out) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, left)
            mstore(0x20, right)
            out := keccak256(0x00, 0x40)
        }
    }

    /**
     * @notice This function is quite expensive to operate on-chain. This is acceptable
     * since it is designed for off-chain querying.
     *
     * Aggregate multiple signatures into a single value.
     * This method is called off-chain to calculate the signature to pass with handleOps()
     * bundler MAY use optimized custom code perform this aggregation.
     * @param userOps              - Array of UserOperations to collect the signatures from.
     * @return aggregatedSignature - The aggregated signature.
     */
    function aggregateSignatures(PackedUserOperation[] calldata userOps) external pure returns (bytes memory) {
        uint256 length = userOps.length;

        // Allocate more than what is necessary.
        bytes32[] memory _blockhashes = new bytes32[](length);
        IStorageProofVerifier.StorageProof[] memory uniqueStorageProofs =
            new IStorageProofVerifier.StorageProof[](length);

        uint256 uniqueStorageProofCount = 0;
        uint256[] memory derivedStateRootIndices = new uint256[](length);
        for (uint256 i = 0; i != length; ++i) {
            PackedUserOperation calldata userOp = userOps[i];
            UnaggregatedSignatureData calldata data = _decodeUserOpSignature(userOp.signature);

            // Uniquely identify each storage proof by the blockhash
            bytes32 _blockhash = keccak256(data.storageProof.blockHeader);

            bool existsInArray;
            for (uint256 j = 0; j != length; ++j) {
                if (_blockhashes[j] != _blockhash) continue;

                derivedStateRootIndices[i] = j;
                existsInArray = true;
                break;
            }

            if (!existsInArray) {
                _blockhashes[uniqueStorageProofCount] = _blockhash;
                uniqueStorageProofs[uniqueStorageProofCount] = data.storageProof;
                derivedStateRootIndices[i] = uniqueStorageProofCount++;
            }
        }

        assembly {
            // Alter the length of the uniqueStorageProofs array
            mstore(uniqueStorageProofs, uniqueStorageProofCount)
        }

        return abi.encode(uniqueStorageProofs, derivedStateRootIndices);
    }

    function _decodeUserOpSignature(bytes calldata signature)
        internal
        pure
        returns (UnaggregatedSignatureData calldata out)
    {
        /// @solidity memory-safe-assembly
        assembly {
            out := signature.offset
        }
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
}
