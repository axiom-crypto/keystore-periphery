// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { RLPReader } from "./vendor/optimism-mpt/rlp/RLPReader.sol";
import { SecureMerkleTrie } from "./vendor/optimism-mpt/trie/SecureMerkleTrie.sol";
import { IStorageProofVerifier } from "./interfaces/IStorageProofVerifier.sol";

contract StorageProofVerifier is IStorageProofVerifier {
    error InvalidBlockHeader();

    error InvalidStorageValue();

    error InvalidBlockNumber();

    error CannotVerifyExclusionProof();

    function verifyStorageSlot(StorageProof calldata storageProof, address _address, bytes32 storageSlot)
        external
        pure
        returns (bytes32, bytes32)
    {
        _verifyStorageSlot(
            _address,
            storageSlot,
            storageProof.storageValue,
            storageProof.blockHeader,
            storageProof.accountProof,
            storageProof.storageProof
        );

        return (storageProof.storageValue, keccak256(storageProof.blockHeader));
    }

    function _decodeStorageProof(bytes calldata storageProof) internal pure returns (StorageProof calldata out) {
        /// @solidity memory-safe-assembly
        assembly {
            out := storageProof.offset
        }
    }

    function _verifyStorageSlot(
        address _address,
        bytes32 storageSlot,
        bytes32 storageValue,
        bytes calldata blockHeader,
        bytes[] calldata accountProof,
        bytes[] calldata storageProof
    ) internal pure {
        if (storageValue == bytes32(0)) revert CannotVerifyExclusionProof();

        RLPReader.RLPItem[] memory blockHeaderRlp = RLPReader.readList(blockHeader);

        // stateRoot is at index 3 in the block header
        bytes32 stateRoot = bytes32(RLPReader.readBytes(blockHeaderRlp[3]));

        // check account proof with relevant address
        bytes memory account = SecureMerkleTrie.get(abi.encodePacked(_address), accountProof, stateRoot);
        RLPReader.RLPItem[] memory accountRlp = RLPReader.readList(account);

        bytes32 storageRoot = bytes32(RLPReader.readBytes(accountRlp[2]));

        // check storage proof with relevant slot
        bytes memory rlpSlotValue = SecureMerkleTrie.get(abi.encodePacked(storageSlot), storageProof, storageRoot);
        bytes memory bytesSlotValue = RLPReader.readBytes(rlpSlotValue);

        // We need to add padding to the slot value since they are encoded as
        // uint256
        bytes32 provenStorageValue = bytes32(uint256(bytes32(bytesSlotValue)) >> (8 * (32 - bytesSlotValue.length)));

        if (provenStorageValue != storageValue) revert InvalidStorageValue();
    }
}
