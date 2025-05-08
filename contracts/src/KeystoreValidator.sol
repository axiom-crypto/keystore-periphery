// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {
    IValidationModule as IERC6900ValidationModule,
    IModule as IERC6900Module
} from "./interfaces/IERC6900ValidationModule.sol";
import { IKeyDataConsumer } from "./interfaces/IKeyDataConsumer.sol";
import { RLPReader } from "./vendor/optimism-mpt/rlp/RLPReader.sol";
import { IKeystoreStateOracle } from "./interfaces/IKeystoreStateOracle.sol";
import { KeystoreIMT } from "./libraries/KeystoreIMT.sol";

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { ValidationData as ValidationData4337 } from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";
import { ERC7579ValidatorBase } from "modulekit/module-bases/ERC7579ValidatorBase.sol";
import { IModule as IERC7579Module } from "modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { _packValidationData as _packValidationData4337 } from "modulekit/external/ERC4337.sol";

import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";

contract KeystoreValidator is ERC7579ValidatorBase, IERC6900ValidationModule {
    /// @dev Per userOp. The expected structure of the `signature` field in
    /// `PackedUserOperation`
    struct AuthenticationData {
        // Parsed as KeystoreIMT.KeyDataMerkleProof. If empty, key data will be
        // read from local cache, skipping the need for a state root read
        bytes keyDataProof;
        IKeyDataConsumer keyDataConsumer;
        bytes authData;
    }

    struct AccountData {
        // The address on the keystore rollup storing signing data.
        //
        // This value is set by the smart account.
        bytes32 keystoreAddress;
        // If a keystore state root was read from an L1 block with timestamp
        // `x`, then key data reads from this keystore state root via Merkle
        // proofs are valid until `x + stateRootValidityWindow`.
        //
        // Since this value is added to an `l1BlockTimestamp` which is allocated
        // 48 bits of space, there are no concerns of overflow until the L1
        // block timestamp hits 2 ^ 48 - 2 ^ 32.
        //
        // This value is set by the smart account.
        uint32 stateRootValidityWindow;
        // If a key data read was cached from a keystore state root which was
        // read from an L1 block with timestamp `x`, then the cached key data is
        // valid until `x + cacheInvalidationTime`.
        //
        // Since this value is added to an `l1BlockTimestamp` which is allocated
        // 48 bits of space, there are no concerns of overflow until the L1
        // block timestamp hits 2 ^ 48 - 2 ^ 32.
        //
        // This value is set by the smart account.
        uint32 cacheInvalidationTime;
        // The timestamp at which the cache is invalidated.
        uint48 cacheInvalidationTimestamp;
        // If key data was read (and cached) from a keystore state root which
        // was read from an L1 block with timestamp `x`, then
        // `cachedStateRootTimestamp` is equal to `x`.
        uint48 cachedStateRootTimestamp;
        bytes cachedKeyData;
    }

    error AlreadyInitialized(address smartAccount);

    error StateRootNotFound(bytes32 stateRoot);

    error InvalidKeystoreAddress();

    error UnsupportedOperation();

    error UnexpectedCodehash(bytes32 expectedCodehash, bytes32 actualCodehash);

    error UnexpectedDomainSeparator();

    error InvalidKeyDataLength();

    error InvalidKeystoreStateOracle();

    error NoCachedKeyData();

    mapping(address account => AccountData) public accountData;

    IKeystoreStateOracle public immutable KEYSTORE_STATE_ORACLE;

    constructor(IKeystoreStateOracle keystoreStateOracle) {
        if (address(keystoreStateOracle) == address(0)) revert InvalidKeystoreStateOracle();

        KEYSTORE_STATE_ORACLE = keystoreStateOracle;
    }

    /// @dev This function is called by the smart account during installation of the module
    ///
    /// @param data We expect the data to be formatted as `abi.encode(uint248)`
    /// MUST revert on error (i.e. if module is already enabled)
    function onInstall(bytes calldata data) external override(IERC6900Module, IERC7579Module) {
        AccountData storage $ = accountData[msg.sender];
        if ($.keystoreAddress != bytes32(0)) revert AlreadyInitialized(msg.sender);

        (uint32 stateRootValidityWindow, uint32 cacheInvalidationTime, bytes32 keystoreAddress) =
            abi.decode(data, (uint32, uint32, bytes32));

        if (keystoreAddress == bytes32(0)) revert InvalidKeystoreAddress();

        $.stateRootValidityWindow = stateRootValidityWindow;
        $.cacheInvalidationTime = cacheInvalidationTime;
        $.keystoreAddress = keystoreAddress;
    }

    /// @dev This function is called by the smart account during uninstallation of the module
    ///
    /// MUST revert on error
    function onUninstall(bytes calldata) external override(IERC6900Module, IERC7579Module) {
        if (accountData[msg.sender].keystoreAddress == bytes32(0)) revert NotInitialized(msg.sender);
        delete accountData[msg.sender];
    }

    /// @dev Returns boolean value if module is a certain type
    /// @param moduleTypeId the module type ID according the ERC-7579 spec
    ///
    /// MUST return true if the module is of the given type and false otherwise
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == TYPE_VALIDATOR;
    }

    /// @dev Returns if the module was already initialized for a provided smart account
    function isInitialized(address smartAccount) external view returns (bool) {
        AccountData storage $ = accountData[smartAccount];

        return $.keystoreAddress != bytes32(0);
    }

    function validateUserOp(uint32, PackedUserOperation calldata userOp, bytes32 userOpHash)
        public
        override
        returns (uint256)
    {
        return ValidationData.unwrap(validateUserOp(userOp, userOpHash));
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        public
        override
        returns (ValidationData)
    {
        AuthenticationData calldata data = _decodeUserOpSignature(userOp.signature);
        AccountData storage $ = accountData[userOp.sender];

        bytes memory keyData;
        uint48 validAfter;
        uint48 validUntil;

        if (data.keyDataProof.length > 0) {
            // Read key data from state root via Merkle proof

            KeystoreIMT.KeyDataMerkleProof calldata keyDataProof = _decodeKeyDataProof(data.keyDataProof);
            keyData = keyDataProof.keyData;

            // Key data being used with the KeystoreValidator must be at least 33
            // bytes. 1 byte for the domain separator, 32 bytes for the codehash
            if (keyData.length < 33) revert InvalidKeyDataLength();
            if (bytes1(keyData) != 0x00) revert UnexpectedDomainSeparator();

            bytes32 derivedImtRoot = KeystoreIMT.processImtKeyData(keyDataProof, keccak256(keyData), $.keystoreAddress);

            // Unsafe cast OK
            uint48 blockTimestamp = uint48(KEYSTORE_STATE_ORACLE.keystoreStateRoots(derivedImtRoot));
            if (blockTimestamp == 0) revert StateRootNotFound(derivedImtRoot);

            uint48 stateRootValidityWindow = $.stateRootValidityWindow;

            validAfter = blockTimestamp;
            validUntil = blockTimestamp + stateRootValidityWindow;

            // The cache is only updated if the state from which the key data is
            // read is fresher than the previous cache.
            uint48 cachedStateRootTimestamp = $.cachedStateRootTimestamp;
            if (validUntil > cachedStateRootTimestamp + stateRootValidityWindow || cachedStateRootTimestamp == 0) {
                $.cachedKeyData = keyData;
                $.cachedStateRootTimestamp = blockTimestamp;
                $.cacheInvalidationTimestamp = blockTimestamp + $.cacheInvalidationTime;
            }
        } else {
            // Read key data from cache, skipping the need for a Merkle proof
            //
            // This branch does not validate the key data since it was already
            // validated before being cached

            uint48 cachedStateRootTimestamp = $.cachedStateRootTimestamp;
            if (cachedStateRootTimestamp == 0) revert NoCachedKeyData();

            // Cached data is guaranteed to be at least 33 bytes
            keyData = $.cachedKeyData;

            validAfter = cachedStateRootTimestamp;
            validUntil = $.cacheInvalidationTimestamp;
        }

        bytes32 authorizedCodehash = _getKDCCodehash(keyData);
        IKeyDataConsumer keyDataConsumer = data.keyDataConsumer;
        bytes32 deployedCodehash = address(keyDataConsumer).codehash;
        if (authorizedCodehash != deployedCodehash) revert UnexpectedCodehash(authorizedCodehash, deployedCodehash);

        keyDataConsumer.consumeKeyData(keyData, data.authData, userOpHash);

        return ValidationData.wrap(
            _packValidationData4337(
                ValidationData4337({ aggregator: address(0), validUntil: validUntil, validAfter: validAfter })
            )
        );
    }

    function _decodeUserOpSignature(bytes calldata signature) internal pure returns (AuthenticationData calldata out) {
        /// @solidity memory-safe-assembly
        assembly {
            out := signature.offset
        }
    }

    function _decodeKeyDataProof(bytes calldata keyDataProof)
        internal
        pure
        returns (KeystoreIMT.KeyDataMerkleProof calldata proof)
    {
        /// @solidity memory-safe-assembly
        assembly {
            proof := keyDataProof.offset
        }
    }

    /// @dev Assumes `keyData` is at least 33 bytes
    function _getKDCCodehash(bytes memory keyData) internal pure returns (bytes32 authorizedCodehash) {
        /// @solidity memory-safe-assembly
        assembly {
            // add 0x20 to skip the length and 0x01 to skip the domain
            // separator
            authorizedCodehash := mload(add(keyData, 0x21))
        }
    }

    /// @notice Update the state root invalidation time for the smart account
    ///
    /// @param newStateRootValidityWindow The new state root validity window
    function setStateRootValidityWindow(uint32 newStateRootValidityWindow) external {
        AccountData storage $ = accountData[msg.sender];
        if ($.keystoreAddress == bytes32(0)) revert NotInitialized(msg.sender);

        $.stateRootValidityWindow = newStateRootValidityWindow;
    }

    /// @notice Update the cache invalidation time for the smart account
    ///
    /// @param newCacheInvalidationTime The new cache invalidation time
    function setCacheInvalidationTime(uint32 newCacheInvalidationTime) external {
        AccountData storage $ = accountData[msg.sender];
        if ($.keystoreAddress == bytes32(0)) revert NotInitialized(msg.sender);

        $.cacheInvalidationTime = newCacheInvalidationTime;
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
        return "axiom.keystore.v0.2.4";
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC6900ValidationModule).interfaceId
            || interfaceId == type(IERC6900Module).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
