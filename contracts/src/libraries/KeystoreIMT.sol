// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

library KeystoreIMT {
    bytes1 internal constant NON_DUMMY_BYTE = 0x01;

    bytes1 internal constant ACTIVE_LEAF_BYTE = 0x01;

    bytes2 internal constant SILOING_BYTES = bytes2(0x0000);

    error InvalidKeystoreAddress();

    error NotAnExclusionProof();

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

    /// @dev Validates the key data into the keystore state root.
    /// @param keyDataProof - The key data proof to validate.
    function processImtKeyData(KeyDataMerkleProof calldata keyDataProof, bytes32 dataHash, bytes32 keystoreAddress)
        internal
        pure
        returns (bytes32)
    {
        bytes32 leafNode;
        if (keyDataProof.isExclusion) {
            (bytes1 prevDummyByte, bytes32 prevImtKey, bytes32 salt, bytes32 valueHash) =
                parseExclusionExtraData(keyDataProof.exclusionExtraData);

            bytes32 derivedKeystoreAddress = keccak256(abi.encodePacked(salt, dataHash, keyDataProof.vkeyHash));
            if (keystoreAddress != derivedKeystoreAddress) revert InvalidKeystoreAddress();

            bytes32 imtKey = keccak256(abi.encodePacked(SILOING_BYTES, derivedKeystoreAddress));
            if (
                !(imtKey > prevImtKey || prevDummyByte == 0x00)
                    && !(imtKey < keyDataProof.nextImtKey || keyDataProof.nextDummyByte == 0x00)
            ) revert NotAnExclusionProof();

            leafNode = constructImtLeafNode({
                dummyByte: prevDummyByte,
                imtKey: prevImtKey,
                nextDummyByte: keyDataProof.nextDummyByte,
                nextImtKey: keyDataProof.nextImtKey,
                valueHash: valueHash
            });
        } else {
            bytes32 valueHash = keccak256(abi.encodePacked(dataHash, keyDataProof.vkeyHash));
            bytes32 imtKey = keccak256(abi.encodePacked(SILOING_BYTES, keystoreAddress));

            leafNode = constructImtLeafNode({
                dummyByte: NON_DUMMY_BYTE,
                imtKey: imtKey,
                nextDummyByte: keyDataProof.nextDummyByte,
                nextImtKey: keyDataProof.nextImtKey,
                valueHash: valueHash
            });
        }

        return processMerkleProof(keyDataProof.proof, leafNode, keyDataProof.isLeft);
    }

    function constructImtLeafNode(
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

    function parseExclusionExtraData(bytes calldata extraData)
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

    function processMerkleProof(bytes32[] calldata proof, bytes32 leaf, uint256 isLeft)
        internal
        pure
        returns (bytes32)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let offset := proof.offset
            let length := proof.length

            for { let i := 0 } iszero(eq(i, length)) { i := add(i, 1) } {
                let isLeftBit := and(shr(i, isLeft), 1)

                switch isLeftBit
                case 0 {
                    mstore(0x00, leaf)
                    mstore(0x20, calldataload(offset))
                }
                case 1 {
                    mstore(0x00, calldataload(offset))
                    mstore(0x20, leaf)
                }

                offset := add(offset, 0x20)
                leaf := keccak256(0x00, 0x40)
            }
        }

        return leaf;
    }
}
