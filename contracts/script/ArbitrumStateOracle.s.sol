// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { ArbitrumStateOracle } from "../src/state/ArbitrumStateOracle.sol";
import { ArbitrumBroadcaster } from "../src/broadcast/ArbitrumBroadcaster.sol";
import { IAxiomKeystoreRollup } from "../src/interfaces/IAxiomKeystoreRollup.sol";

import { ICreateX } from "./ICreateX.sol";

import { Script, safeconsole as console, console2 } from "forge-std/Script.sol";

contract MockBridge is IAxiomKeystoreRollup {
    bytes32 public latestOutputRoot = keccak256(
        abi.encodePacked(
            bytes32(0x870887a884726c27d70b6242ca8978e047d697e0240a021c66201243aa57ac8b),
            bytes32(0x870887a884726c27d70b6242ca8978e047d697e0240a021c66201243aa57ac8b),
            bytes32(0x870887a884726c27d70b6242ca8978e047d697e0240a021c66201243aa57ac8b)
        )
    );
}

contract ArbitrumStateOracleScript is Script {
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

    function run() external {
        ICreateX createX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

        vm.createSelectFork("sepolia");

        address sender = msg.sender;

        // Construct random seeds we don't care about
        bytes32 seed1 = keccak256(abi.encodePacked(block.timestamp, block.prevrandao, block.coinbase));
        bytes32 seed2 = keccak256(abi.encodePacked(seed1, block.timestamp, block.prevrandao, block.coinbase));

        // Construct CreateX salts with msg.sender protection but no cross-chain protection
        bytes32 salt1 = bytes32(abi.encodePacked(bytes20(sender), bytes1(0x00), seed1));
        bytes32 salt2 = bytes32(abi.encodePacked(bytes20(sender), bytes1(0x00), seed2));

        // Compute the guarded salts for address prediction
        bytes32 guardedSalt1 = keccak256(abi.encodePacked(bytes32(uint256(uint160(msg.sender))), salt1));
        bytes32 guardedSalt2 = keccak256(abi.encodePacked(bytes32(uint256(uint160(msg.sender))), salt2));

        address arbitrumSepoliaBroadcaster = createX.computeCreate3Address(guardedSalt1);
        address stateOracle = createX.computeCreate3Address(guardedSalt2);

        address arbSepoliaL1Inbox = 0xaAe29B0366299461418F5324a79Afc425BE5ae21; // Sepolia L1 Inbox

        vm.startBroadcast();

        MockBridge bridge = new MockBridge();
        bytes memory arbitrumSepoliaBroadcasterDeploymentCode =
            abi.encodePacked(type(ArbitrumBroadcaster).creationCode, abi.encode(arbSepoliaL1Inbox, bridge, stateOracle));
        createX.deployCreate3(salt1, arbitrumSepoliaBroadcasterDeploymentCode);

        vm.stopBroadcast();

        vm.createSelectFork("arbitrum_sepolia");
        vm.startBroadcast();

        bytes memory stateOracleDeploymentCode =
            abi.encodePacked(type(ArbitrumStateOracle).creationCode, abi.encode(arbitrumSepoliaBroadcaster));
        address deployedStateOracle = createX.deployCreate3(salt2, stateOracleDeploymentCode);

        require(deployedStateOracle == stateOracle, "State oracle deployment failed");

        vm.stopBroadcast();
    }
}
