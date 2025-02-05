// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IValidationModule, IModule as IERC6900Module } from "./IValidationModule.sol";

import { IL1Block } from "./interfaces/IL1Block.sol";
import { IKeyDataConsumer } from "./interfaces/IKeyDataConsumer.sol";
import { IStorageProofVerifier } from "./interfaces/IStorageProofVerifier.sol";
import { RLPReader } from "./vendor/optimism-mpt/rlp/RLPReader.sol";

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { ValidationData as ValidationData4337 } from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";
import { ERC7579ValidatorBase } from "modulekit/module-bases/ERC7579ValidatorBase.sol";
import { IModule as IERC7579Module } from "modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { _packValidationData as _packValidationData4337 } from "modulekit/external/ERC4337.sol";

import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract KeystoreValidator is ERC7579ValidatorBase, IValidationModule, Ownable2Step {
    address internal constant L1BLOCK = 0x4200000000000000000000000000000000000015;

    struct KeyDataMerkleProof {
        bool isExclusion;
        // Only parsed if `isExclusion` is true
        // abi.encodePacked(prevDummyByte, prevImtKey, salt, valueHash)
        bytes exclusionExtraData;
        bytes1 nextDummyByte;
        bytes32 nextImtKey;
        bytes32 vkeyHash;
        bytes keyData;
        bytes32[] proof;
        uint256 isLeft;
    }

    /// @dev Per userOp. The expected structure of the `signature` field in
    /// `PackedUserOperation`
    struct SignatureData {
        KeyDataMerkleProof keyDataProof;
        bytes signatures;
    }

    struct InstallationData {
        bool initialized;
        uint48 invalidationTime;
        bytes32 keystoreAddress;
    }

    error AlreadyInitialized(address smartAccount);

    event BlockhashCached(bytes32 _blockhash);

    event ConsumerRegistered(bytes32 creationCodehash, address consumer);

    error BlockhashNotFound(bytes32 _blockhash);

    error StateRootNotFound(bytes32 stateRoot);

    error InvalidKeystoreAddress();

    error NotAnExclusionProof();

    error UnsupportedOperation();

    error AlreadyRegistered(bytes32 creationCodehash);

    error UnregisteredCodehash(bytes32 creationCodehash);

    error InvalidKeyDataValidator();

    error StorageProofTooOld();

    bytes32 public latestStateRoot;
    mapping(bytes32 keystoreStateRoot => uint256 l1BlockTimestamp) public keystoreStateRoots;
    mapping(bytes32 _blockhash => bool) public blockhashes;
    mapping(bytes32 creationCodehash => IKeyDataConsumer consumer) public consumers;
    mapping(address account => InstallationData) public accountData;

    bytes1 internal constant NON_DUMMY_BYTE = 0x01;
    bytes1 internal constant ACTIVE_LEAF_BYTE = 0x01;

    IStorageProofVerifier public storageProofVerifier;
    address public immutable KEYSTORE_BRIDGE_ADDRESS;
    bytes32 public immutable KEYSTORE_STATE_ROOT_STORAGE_SLOT;

    bytes2 internal constant SILOING_BYTES = bytes2(0x0000);

    constructor(
        IStorageProofVerifier _storageProofVerifier,
        address keystoreBridgeAddress,
        bytes32 keystoreStateRootStorageSlot
    ) Ownable(msg.sender) {
        storageProofVerifier = _storageProofVerifier;
        KEYSTORE_BRIDGE_ADDRESS = keystoreBridgeAddress;
        KEYSTORE_STATE_ROOT_STORAGE_SLOT = keystoreStateRootStorageSlot;
    }

    /**
     * @dev This function is called by the smart account during installation of the module
     *
     * @param data We expect the data to be formatted as `abi.encode(uint248)`
     * MUST revert on error (i.e. if module is already enabled)
     */
    function onInstall(bytes calldata data) external override(IERC6900Module, IERC7579Module) {
        InstallationData storage $ = accountData[msg.sender];
        if ($.initialized) revert AlreadyInitialized(msg.sender);

        (uint48 invalidationTime, bytes32 keystoreAddress) = abi.decode(data, (uint48, bytes32));

        $.initialized = true;
        $.invalidationTime = invalidationTime;
        $.keystoreAddress = keystoreAddress;
    }

    /**
     * @dev This function is called by the smart account during uninstallation of the module
     *
     * MUST revert on error
     */
    function onUninstall(bytes calldata) external override(IERC6900Module, IERC7579Module) {
        if (!accountData[msg.sender].initialized) revert NotInitialized(msg.sender);
        delete accountData[msg.sender];
    }

    /**
     * @dev Returns boolean value if module is a certain type
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     *
     * MUST return true if the module is of the given type and false otherwise
     */
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == TYPE_VALIDATOR;
    }

    /**
     * @dev Returns if the module was already initialized for a provided smart account
     */
    function isInitialized(address smartAccount) external view returns (bool) {
        InstallationData storage $ = accountData[smartAccount];

        return $.initialized;
    }

    function validateUserOp(uint32, PackedUserOperation calldata userOp, bytes32 userOpHash)
        public
        view
        override
        returns (uint256)
    {
        return ValidationData.unwrap(validateUserOp(userOp, userOpHash));
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        public
        view
        override
        returns (ValidationData)
    {
        SignatureData calldata data = _decodeUserOpSignature(userOp.signature);

        bytes32 dataHash = keccak256(data.keyDataProof.keyData);

        bytes32 derivedImtRoot = _processImtKeyData(data.keyDataProof, dataHash);

        bytes32 keyDataConsumerCodehash = _getKeyDataConsumerCodehash(data.keyDataProof.keyData);
        IKeyDataConsumer keyDataConsumer = consumers[keyDataConsumerCodehash];
        if (address(keyDataConsumer) == address(0)) revert UnregisteredCodehash(keyDataConsumerCodehash);

        keyDataConsumer.consumeKeyData(data.keyDataProof.keyData, data.signatures, userOpHash);

        InstallationData storage $ = accountData[userOp.sender];

        // Unsafe cast OK
        uint48 blockTimestamp = uint48(keystoreStateRoots[derivedImtRoot]);
        if (blockTimestamp == 0) revert StateRootNotFound(derivedImtRoot);

        return ValidationData.wrap(
            _packValidationData4337(
                ValidationData4337({
                    aggregator: address(0),
                    validUntil: blockTimestamp + $.invalidationTime,
                    validAfter: blockTimestamp
                })
            )
        );
    }

    function _decodeUserOpSignature(bytes calldata signature) internal pure returns (SignatureData calldata out) {
        /// @solidity memory-safe-assembly
        assembly {
            out := signature.offset
        }
    }

    /// @dev Validates the key data into the keystore state root.
    /// @param keyDataProof - The key data proof to validate.
    function _processImtKeyData(KeyDataMerkleProof calldata keyDataProof, bytes32 dataHash)
        internal
        view
        returns (bytes32)
    {
        InstallationData storage $ = accountData[msg.sender];

        bytes32 leafNode;
        if (keyDataProof.isExclusion) {
            (bytes1 prevDummyByte, bytes32 prevImtKey, bytes32 salt, bytes32 valueHash) =
                _parseExclusionExtraData(keyDataProof.exclusionExtraData);

            bytes32 derivedKeystoreAddress = keccak256(abi.encodePacked(salt, dataHash, keyDataProof.vkeyHash));
            if ($.keystoreAddress != derivedKeystoreAddress) revert InvalidKeystoreAddress();

            bytes32 imtKey = keccak256(abi.encodePacked(SILOING_BYTES, derivedKeystoreAddress));
            if (
                !(imtKey > prevImtKey || prevDummyByte == 0x00)
                    && !(imtKey < keyDataProof.nextImtKey || keyDataProof.nextDummyByte == 0x00)
            ) revert NotAnExclusionProof();

            leafNode = _constructImtLeafNode({
                dummyByte: prevDummyByte,
                imtKey: prevImtKey,
                nextDummyByte: keyDataProof.nextDummyByte,
                nextImtKey: keyDataProof.nextImtKey,
                valueHash: valueHash
            });
        } else {
            bytes32 valueHash = keccak256(abi.encodePacked(dataHash, keyDataProof.vkeyHash));
            bytes32 imtKey = keccak256(abi.encodePacked(SILOING_BYTES, $.keystoreAddress));
            leafNode = _constructImtLeafNode({
                dummyByte: NON_DUMMY_BYTE,
                imtKey: imtKey,
                nextDummyByte: keyDataProof.nextDummyByte,
                nextImtKey: keyDataProof.nextImtKey,
                valueHash: valueHash
            });
        }

        return _processMerkleProof(keyDataProof.proof, leafNode, keyDataProof.isLeft);
    }

    /// @dev Codehash is expected to be the first `keyData[1:33]`
    function _getKeyDataConsumerCodehash(bytes calldata keyData) internal pure returns (bytes32 creationCodehash) {
        if (bytes1(keyData) != 0x00) revert InvalidKeyDataValidator();
        assembly {
            creationCodehash := calldataload(add(keyData.offset, 1))
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

    function _processMerkleProof(bytes32[] calldata proof, bytes32 leafNode, uint256 isLeft)
        internal
        pure
        returns (bytes32)
    {
        uint256 length = proof.length;
        bytes32 currentNode = leafNode;
        for (uint256 i = 0; i != length; ++i) {
            bool _isLeft = isLeft >> i & 1 == 1;

            if (_isLeft) currentNode = _efficientHash(proof[i], currentNode);
            else currentNode = _efficientHash(currentNode, proof[i]);
        }

        return currentNode;
    }

    function _efficientHash(bytes32 left, bytes32 right) internal pure returns (bytes32 out) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, left)
            mstore(0x20, right)
            out := keccak256(0x00, 0x40)
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

    function cacheKeystoreStateRoot(IStorageProofVerifier.StorageProof calldata storageProof) external {
        (bytes32 keystoreStateRoot, bytes32 _blockhash) = storageProofVerifier.verifyStorageSlot({
            storageProof: storageProof,
            _address: KEYSTORE_BRIDGE_ADDRESS,
            storageSlot: KEYSTORE_STATE_ROOT_STORAGE_SLOT
        });
        if (!blockhashes[_blockhash]) revert BlockhashNotFound(_blockhash);

        bytes calldata blockHeader = storageProof.blockHeader;
        // TODO: Replace with efficient RLP reader
        RLPReader.RLPItem[] memory blockHeaderRlp = RLPReader.readList(blockHeader);

        // TODO: This needs to be revisited. The blockTimestamp appears to be a right-padded uint32 value.
        uint48 blockTimestamp = uint32(bytes4(bytes32(RLPReader.readBytes(blockHeaderRlp[11]))));

        // We don't want to allow older storage proofs to prevent frontrunning
        // of would-be-valid userOps ending up as expired.
        uint256 currentTimestamp = keystoreStateRoots[keystoreStateRoot];
        if (blockTimestamp < currentTimestamp) revert StorageProofTooOld();

        // If caching a state root that has already been cached, we'll want to
        // update its associated blockTimestamp first
        keystoreStateRoots[keystoreStateRoot] = blockTimestamp;

        // For the first state root being cached, `latestTimestamp` will be 0.
        uint256 latestTimestamp = keystoreStateRoots[latestStateRoot];
        if (blockTimestamp > latestTimestamp) latestStateRoot = keystoreStateRoot;
    }

    function deployAndRegisterKeyDataConsumer(bytes memory bytecode) external {
        bytes32 creationCodehash = keccak256(bytecode);
        if (address(consumers[creationCodehash]) != address(0)) revert AlreadyRegistered(creationCodehash);

        IKeyDataConsumer consumer;
        /// @solidity memory-safe-assembly
        assembly {
            consumer := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        consumers[creationCodehash] = consumer;

        emit ConsumerRegistered(creationCodehash, address(consumer));
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        revert UnsupportedOperation();
    }

    function validateRuntime(address, uint32, address, uint256, bytes calldata, bytes calldata) external pure {
        revert UnsupportedOperation();
    }

    function validateSignature(address, uint32, address, bytes32, bytes calldata) external pure returns (bytes4) {
        revert UnsupportedOperation();
    }

    function moduleId() external pure returns (string memory) {
        return "axiom.ecdsa.v0.1.0";
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IValidationModule).interfaceId || interfaceId == type(IERC6900Module).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }
}
