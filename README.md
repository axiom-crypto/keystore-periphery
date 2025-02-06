# Keystore Periphery Contracts

## Overview

This repo houses a set of smart contracts to facilitate interactions with the Axiom Keystore from EVM rollups. While Axiom maintains the deployed instances of the contracts in this repository, the Keystore is permissionless and can be used even without these contracts.

## Building the Contracts

```bash
cd contracts/lib/modulekit
pnpm install
cd ../../
forge build
```

## Keystore Validator

The Keystore Validator (KV) is the core contract connecting rollups to the Axiom Keystore. It is a validation module for both ERC-6900 and ERC-7579 smart accounts which facilitates reading the keystore state and authenticating userOps against data from the reads. There are three primary actors interacting with the KV:

- **Keystore state syncers** verify finalized keystore state roots at a certain L1 block timestamp in the module.
- **User smart accounts** install the module, read the keystore state and use the data to authenticate userOps.
- **Consumer registrars** deploy and add [key data consumers](https://keystore-docs.axiom.xyz/docs/creating-a-keystore-account-type/key-data-consumer) to the module's consumer registry.

We give an overview of the details of each actor below.

### Actors for the Keystore Validator

#### Keystore State Syncer

The exact role of the keystore state syncer (KSS) changes slightly depending on the L2. On L2s like OP Stack that support reading an L1 blockhash from L2, the module provides the interface below for verifying a keystore state root.

```solidity
/// Caches
function cacheBlockhash() external;

function cacheKeystoreStateRoot(StorageProof calldata storageProof) external;
```

The KSS will cache an L1 blockhash in the module's storage, after which it can verify a keystore state root against the L1 blockhash with an L1 storage proof.

For L2s that do not enshrine L1 blockhash access, the module will expose the following alternative interface, which is **not currently implemented**.

```solidity
/// On L1 Broadcaster contract
function sendKeystoreStateRoot() external {
    bytes32 keystoreStateRoot = keystoreBridge.latestStateRoot();
    l2Bridge.sendCrossChainMessage(
        keystoreValidatorModule, abi.encodeCall(cacheKeystoreStateRoot, (keystoreStateRoot, block.timestamp))
    );
}

/// On L2
function cacheKeystoreStateRoot(bytes32 keystoreStateRoot, uint256 timestamp) external onlyBridge;
```

The KSS will initiate a bridge transaction from L1 to send the keystore state root to the module on L2.

#### User Smart Accounts

For smart accounts, the module supports both ERC-6900 and ERC-7579 `validateUserOp(..)` interfaces which call the same underlying logic.

```solidity
/// ERC-6900
function validateUserOp(uint32, PackedUserOperation calldata userOp, bytes32 userOpHash) external;

/// ERC-7579
function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external;
```

Other forms of validation (such as ERC-6900's `validateRuntime(..)`) are not supported.

#### Consumer Registrars

The KV uses a `creationCodehash` to identify a [key data consumer](https://keystore-docs.axiom.xyz/docs/creating-a-keystore-account-type/key-data-consumer) to outsource authentication against `keyData` to. For this to work, the contract must be deployed and registered in the module's consumer registry.

The consumer registrar facilitates deployment and registration of key data consumer contracts. It does this by exposing the following interface:

```solidity
function deployAndRegisterKeyDataConsumer(bytes memory bytecode) external;
```

This will deploy the provided `bytecode` and register its `creationCodehash` in the module's consumer registry where `creationCodehash = keccak256(bytecode)` .

### Immutability and Trust Assumptions of the KV

The module is [deployed](https://keystore-docs.axiom.xyz/docs/developer-reference/contract-addresses) immutably on all supported L2s. However, Axiom will retain the ability to update the storage proof verification logic in the future to follow potential upgrades to Ethereum L1. Unfortunately, because Ethereum L1 may change in future hard forks, there is no clear path at present to completely ossifying this module.
