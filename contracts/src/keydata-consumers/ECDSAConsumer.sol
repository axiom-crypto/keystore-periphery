// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { IKeyDataConsumer } from "../interfaces/IKeyDataConsumer.sol";

contract ECDSAConsumer is IKeyDataConsumer {
    struct ECDSAKeyData {
        bytes32 codehash;
        uint256 requiredSigners;
        address[] allowedSignersList;
    }

    error InvalidSignatureLength();

    error InvalidSignature();

    error InvalidSignersLength();

    function consumeKeyData(bytes calldata keyData, bytes calldata walletSignatures, bytes32 userOpHash)
        external
        view
    {
        ECDSAKeyData calldata _keyData = _decodeECDSAKeyData(keyData);

        if (walletSignatures.length % 65 != 0) revert InvalidSignatureLength();

        uint256 signatureCount = walletSignatures.length / 65;
        uint256 validSignatures = 0;

        // We assume that there are NO duplicate addresses in this list
        address[] calldata allowedSignersList = _keyData.allowedSignersList;
        for (uint256 j = 0; j != signatureCount; ++j) {
            bytes calldata _signature = walletSignatures[j * 65:(j + 1) * 65];

            address signer;
            {
                (bytes32 r, bytes32 s, uint8 v) = _parseSignature(_signature);
                // TODO: Invalid signature gets reverted. Is this desired?
                signer = ECDSA.recover(userOpHash, v, r, s);
            }

            uint256 signersListLength = allowedSignersList.length;
            if (signersListLength > 256) revert InvalidSignersLength();

            uint256 bitmap;
            for (uint256 k = 0; k != signersListLength; ++k) {
                if (allowedSignersList[k] != signer) continue;

                if (get(bitmap, k) == 0) {
                    bitmap = set(bitmap, k);
                    ++validSignatures;
                }
                // TODO: Check for actual m-of-n. Which loop does this break out of?
                break;
            }
        }

        if (validSignatures < _keyData.requiredSigners) revert InvalidSignature();
    }

    /// @dev We can assume index is less than 256.
    function set(uint256 bitmap, uint256 index) internal pure returns (uint256 newBitmap) {
        return bitmap | (1 << index);
    }

    /// @dev We can assume index is less than 256.
    function get(uint256 bitmap, uint256 index) internal pure returns (uint256 flag) {
        return (bitmap >> index) & 1;
    }

    /// @dev This function assumes `signature` is already of length 65.
    /// @param signature - The signature to parse.
    /// @return r - The r component of the signature.
    /// @return s - The s component of the signature.
    /// @return v - The v component of the signature.
    function _parseSignature(bytes calldata signature) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        /// @solidity memory-safe-assembly
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }
    }

    function _decodeECDSAKeyData(bytes calldata keyData) internal pure returns (ECDSAKeyData calldata out) {
        /// @solidity memory-safe-assembly
        assembly {
            out := add(keyData.offset, 1)
        }
    }
}
