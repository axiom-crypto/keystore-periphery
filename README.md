# Keystore Periphery

## Overview

The Keystore Periphery repository provides libraries and utilities to facilitate developing applications on the Axiom Keystore Rollup.
This repo contains:

- Smart contracts to facilitate interactions with the Axiom Keystore from EVM rollups. While Axiom maintains the deployed instances of the contracts in this repository, the Keystore is permissionless and can be used even without these contracts.
- Signature prover Rust crates providing a toolkit for building a signature prover.

## Smart Contracts

The core architecture of the Keystore Periphery is comprised of the following two smart contracts:
- `KeystoreStateOracle`: This is the core contract that facilitates reading the keystore state on L2.
- `KeystoreValidator`: This is a validation module for both ERC-6900 and ERC-7579 smart accounts which authenticates userOps against data from the keystore.

### Keystore State Oracle

The Keystore State Oracle (KSO) is the core smart contract connecting L2s to the Keystore rollup. On L1, provers will finalize `outputRoot`s onto the Keystore bridge, where `outputRoot` is computed as

```solidity
bytes32 outputRoot = keccak256(abi.encodePacked(stateRoot, withdrawalsRoot, lastValidBlockhash));
```

The KSO's responsibility is to "read" these `outputRoot`s from L1, extract the `stateRoot`, and store the `stateRoot` to expose it to L2s. The L1-read can take place in two ways:

- **L1 Storage Proof**: For L2s that exposes L1 `blockhash` access (e.g. OP Stack rollups), a storage proof can be used to read the `outputRoot` from the relevant storage slot on the Keystore bridge.
- **Bridge Transaction**: For other L2s, the KSO can receive `outputRoot`s from L1 via a native bridge transaction. 

Finally, the `stateRoot` can be extracted by taking a claimed preimage of the `outputRoot` and checking a hash-equivalence. 

Currently, OP Stack rollups are supported with the `OPStackStateOracle` and Arbitrum is supported with the `ArbitrumStateOracle`.

### Keystore Validator

The Keystore Validator (KV) is a validation module for both ERC-6900 and ERC-7579 smart accounts which authenticates userOps against data from the Keystore. It achieves this by:

- Verifying IMT proofs against the `stateRoot` stored in the KSO, to validate the integrity of some key data.
- Verify some authentication data against the validated key data.

The former is done within the KV itself, while the latter is outsourced to an external key data consumer.

#### Key Data Consumers

Key data consumers are separate smart contracts that serve as external components of the KV, responsible for defining how key data is processed and validated against. The key data is expected to include metadata that informs the KV of the `codehash` of the contract to invoke for validation. Within the validation flow, users will pass a consumer address as input. Once the KV has verified the authenticity of the key data, it will forward the key data to the consumer contract for further external use, but only if the `EXTCODEHASH` of the inputted consumer address matches the designated `codehash` from the key data. The KV expects key data to conform to the following structure.

```
keyData[0] - domain separator (should be 0x00)
keyData[1..33] - key data consumer codehash
keyData[33..] - arbitrary key data
```

Note that this structure is only required for integrating with the KV. The Keystore protocol itself allows for key data to be arbitrary.

The motivation for separating verification of some key data's presence on the keystore from its actual use is to allow the former to be immutable while allowing for new forms of the latter to be introduced permissionlessly via external consumer contracts.

### Building the Contracts

```bash
cd contracts/lib/modulekit
pnpm install
cd ../../
forge build
```

## Signature Prover Crates

To facilitate writing your signature prover, Keystore Periphery provides the following crates:

- `signature-prover-guest`
- `signature-prover-server`
- `signature-prover-lib`

### Signature Prover Guest

The `signature-prover-guest` crate provides functionality for defining authentication inputs and handling public values in your guest program crate. It provides:

- `SignatureProverInput`: a generic struct for defining authentication inputs.
- `set_public_values`: function to format `data_hash` and `msg_hash` into hi-lo form for the halo2 proof.

### Signature Prover Server

The `signature-prover-server` crate provides the core components of the signature prover JSON-RPC server. It provides:

- `SignatureProverApi`: signature prover JSON-RPC API interface.
- `SignatureProverServer`: signature prover JSON-RPC server implementation.
- `AuthInputsDecoder`: trait for decoding the authentication input data received from the JSON-RPC endpoint.
- `SignatureProverInputValidator`: trait for validating the authentication inputs before proof generation.

### Signature Prover Library

The `signature-prover-lib` crate provides tooling to develop and test a ZK authentication program developed for OpenVM. It provides:

- `keygen`: function to generate the proving and verifying keys.
- `SignatureProverTester`: testing framework for OpenVM program setup and execution.
