// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IL1Block {
    function number() external view returns (uint64);
    function hash() external view returns (bytes32);
}
