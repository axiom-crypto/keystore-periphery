// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IStorageProofVerifier {
    struct StorageProof {
        bytes32 storageValue;
        bytes blockHeader;
        bytes[] accountProof;
        bytes[] storageProof;
    }

    function verifyStorageSlot(StorageProof calldata storageProof, address _address, bytes32 storageSlot)
        external
        view
        returns (bytes32 storageValue, bytes32 _blockhash);
}
