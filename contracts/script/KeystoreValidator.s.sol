// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { StorageProofVerifier } from "../src/StorageProofVerifier.sol";
import { KeystoreStateOracle } from "../src/KeystoreStateOracle.sol";
import { KeystoreValidator } from "../src/KeystoreValidator.sol";
import { ECDSAConsumer } from "../test/example/ECDSAConsumer.sol";

import { Script, safeconsole as console } from "forge-std/Script.sol";

import { stdJson as StdJson } from "forge-std/StdJson.sol";

using StdJson for string;

contract KeystoreValidatorScript is Script {
    /// @dev Included to enable compilation of the script without a $MNEMONIC environment variable.
    string internal constant TEST_MNEMONIC = "test test test test test test test test test test test junk";

    address internal broadcaster;

    string internal mnemonic;

    string configPath = "./deployment-config/KeystoreValidator.json";

    modifier broadcast() {
        vm.startBroadcast(broadcaster);
        _;
        vm.stopBroadcast();
    }

    constructor() {
        address from = vm.envOr({ name: "ETH_FROM", defaultValue: address(0) });
        if (from != address(0)) {
            broadcaster = from;
        } else {
            mnemonic = vm.envOr({ name: "MNEMONIC", defaultValue: TEST_MNEMONIC });
            (broadcaster,) = deriveRememberKey({ mnemonic: mnemonic, index: 0 });
        }
    }

    function run() external broadcast returns (StorageProofVerifier, KeystoreStateOracle, KeystoreValidator) {
        string memory config = vm.readFile(configPath);
        address bridge = vm.parseJsonAddress(config, ".bridge");

        StorageProofVerifier storageProofVerifier = new StorageProofVerifier();

        KeystoreStateOracle stateOracle = new KeystoreStateOracle(
            storageProofVerifier, bridge, 0xc94330da5d5688c06df0ade6bfd773c87249c0b9f38b25021e2c16ab9672d000
        );

        KeystoreValidator validator = new KeystoreValidator(stateOracle);

        return (storageProofVerifier, stateOracle, validator);
    }
}
