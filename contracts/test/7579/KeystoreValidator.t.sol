// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { KeystoreValidator } from "../../src/KeystoreValidator.sol";
import { ECDSAConsumer } from "../../src/keydata-consumers/ECDSAConsumer.sol";
import { KeystoreAggregator } from "../../src/KeystoreAggregator.sol";
import { StorageProofVerifier } from "../../src/StorageProofVerifier.sol";
import { IStorageProofVerifier } from "../../src/interfaces/IStorageProofVerifier.sol";

import { RhinestoneModuleKit, ModuleKitHelpers, AccountInstance, UserOpData } from "modulekit/ModuleKit.sol";
import { MODULE_TYPE_VALIDATOR } from "modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { IEntryPoint, PackedUserOperation } from "modulekit/external/ERC4337.sol";

import { UserOperationLib } from "account-abstraction/core/UserOperationLib.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

import { Test, stdJson as StdJson, safeconsole as console, console2 } from "forge-std/Test.sol";

contract KeystoreValidatorTest is RhinestoneModuleKit, Test {
    using StdJson for *;
    using ModuleKitHelpers for AccountInstance;

    KeystoreAggregator aggregator;

    AccountInstance internal instance;
    KeystoreValidator internal validator;

    address ownerSigner = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    uint256 ownerSignerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    address target = makeAddr("target");
    uint256 value = 1 ether;

    StorageProofVerifier newStorageProofVerifier;

    function setUp() public {
        vm.createSelectFork(vm.envString("RPC_URL_10"), 123_022_040);

        init();

        newStorageProofVerifier = (new StorageProofVerifier());
        aggregator = new KeystoreAggregator(newStorageProofVerifier);

        validator = new KeystoreValidator(
            newStorageProofVerifier,
            0x829ce5730041De079995F7E7D9749E11F36Da0Bc,
            0xc94330da5d5688c06df0ade6bfd773c87249c0b9f38b25021e2c16ab9672d001
        );
        vm.label(address(validator), "KeystoreValidator");

        instance = makeAccountInstance("KeystoreECDSAAccount");
        vm.deal(address(instance.account), 10 ether);

        aggregator.cacheBlockhash();

        vm.warp(1_736_565_242);
    }

    function test_1() public {
        vm.store(
            0x4200000000000000000000000000000000000015,
            bytes32(uint256(0x02)),
            0x9d1cb7a93eaed952b60cc8f8bd367a163f6fde8ca65b45579c9b242ff5748552
        );

        validator.cacheBlockhash();
        validator.deployAndRegisterKeyDataConsumer(type(ECDSAConsumer).creationCode);

        (bytes memory blockHeader, bytes[] memory accountProof, bytes[] memory storageProof) =
            _readStorageProof("proofs/Exclusion.json");

        IStorageProofVerifier.StorageProof memory _storageProof = IStorageProofVerifier.StorageProof({
            storageValue: bytes32(0x3c88834ecd749dae9348033b2a889acad890fa045f84061d2347dba67facda8c),
            blockHeader: blockHeader,
            accountProof: accountProof,
            storageProof: storageProof
        });

        validator.cacheKeystoreStateRoot(_storageProof);

        address[] memory allowedSignersList = new address[](1);
        allowedSignersList[0] = ownerSigner;

        bytes32[] memory proof = new bytes32[](19);
        proof[0] = 0x10dd99ee5e9ccc2b8a351dbdb0738a77911e1a4ef6fb50174851bb3fc9c2b03c;
        proof[1] = 0x0c3714142233810f87811489afa05f423c38a84f5860cd52ba6073057f7dfc6b;
        proof[2] = 0xbe7c57b264ad51b358c7bca4c0b028c87c837282245d1629f07839fc3f95fdad;
        proof[3] = 0x23f12b19ac5215bad792510da63e99c109bb4b145107e62680cc0551055c2119;
        proof[4] = 0xcb865f7301bcabb14ac928211790d8e98dd761a1dbc155837a52f43e4f700ec3;
        proof[5] = 0xb66eb60aac26fe8683674e1298df83c2fc3ce7b068416fdbdb97ac1d6491d623;
        proof[6] = 0xb79b822e622f4e6539e85753abbf617c551960695696ce7f53b291009ddfc700;
        proof[7] = 0x463767d3d9645709037a15c39ea75442c122e0870853151ba09ef1ea7de455f9;
        proof[8] = 0x46c02db5326229fc8321e53f46b87ebd9c1a1456125fbf282838b16134a7f335;
        proof[9] = 0xf7e2b3faab9d3959fa6d9a256a91d78a239de95dc7aad3feb744fdafc6b68918;
        proof[10] = 0xb9e03292b62fbb07857ca5c0ffb6738c4346a584b231a06595ebd750d839030a;
        proof[11] = 0x3c5a0f49884c3927d7c8ce29129403ae4af3bd1bf003f48afbaaa49c71b0dd3e;
        proof[12] = 0x91ac2a2d16c21e3e5b7c4d559494316fc14f71a20efd7b49d700d03101c4eee0;
        proof[13] = 0x7af1e2cfef35ce0d0235e2e63c6916f127e280c6c8f6727283463d54eca09742;
        proof[14] = 0xca4146047e1503c1e9233f62d7f749a5bf07ebca0c608b1ce1ee0eabaa5ffe57;
        proof[15] = 0x09b6ae444fa0541008cd3e1750d421390b2c2fdf9b8dbf7f4d056ad2a77ab208;
        proof[16] = 0x1eeea27956aedafe5d00195db8eebef745628a1b6ccc24bb085347d913e616ef;
        proof[17] = 0x314621349ffe6aca302f3492052670cd2c62a30a90ff0ceb3c185fbd7a42ec88;
        proof[18] = 0xdcf51acaac269aea518fe315fff18ba82424d138c1ac4bbfe2ec2f947e9af6a7;

        bytes32 keyDataConsumerCodehash = keccak256(type(ECDSAConsumer).creationCode);
        bytes memory keyData =
            abi.encodePacked(bytes1(0x00), abi.encode(keyDataConsumerCodehash, 1, allowedSignersList));

        bytes32 salt = 0x0000000000000000000000000000000000000000000000000000000000000000;
        bytes32 dataHash = keccak256(keyData);
        bytes32 vkeyHash = keccak256("vkey");

        bytes32 keystoreAddress = keccak256(abi.encodePacked(salt, dataHash, vkeyHash));
        KeystoreValidator.KeyDataMerkleProof memory keyDataMerkleProof = KeystoreValidator.KeyDataMerkleProof({
            isExclusion: true,
            exclusionExtraData: hex"01030303030303030303030303030303030303030303030303030303030303030300000000000000000000000000000000000000000000000000000000000000004a7a4de37def8e10861261f58e1003e6086df449b615bb411c39669548e19dba",
            nextDummyByte: 0x00,
            nextImtKey: 0x0000000000000000000000000000000000000000000000000000000000000000,
            vkeyHash: vkeyHash,
            keyData: keyData,
            proof: proof,
            isLeft: 524_284
        });

        UserOpData memory userOpData =
            instance.getExecOps({ target: target, value: value, callData: "", txValidator: address(validator) });

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOpData.userOp;
        userOps[0].initCode = hex"";

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(ownerSignerKey, this.userOpHash(userOps[0], address(instance.aux.entrypoint), block.chainid));

        bytes memory userOpSig = abi.encodePacked(r, s, v);

        bytes memory sig = abi.encode(keyDataMerkleProof, userOpSig);

        userOps[0].signature = sig;

        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(validator),
            data: abi.encode(100_000 days, keystoreAddress)
        });

        uint256 prevBalance = target.balance;

        instance.aux.entrypoint.handleOps(userOps, payable(address(this)));

        assertEq(target.balance, prevBalance + value);
    }

    function _readStorageProof(string memory filePath)
        public
        view
        returns (bytes memory blockHeader, bytes[] memory accountProof, bytes[] memory storageProof)
    {
        string memory json = vm.readFile(filePath);
        blockHeader = json.readBytes(".rlp_block_header");
        accountProof = json.readBytesArray(".storage_proof.accountProof");
        storageProof = json.readBytesArray(".storage_proof.storageProof[0].proof");
    }

    function userOpHash(PackedUserOperation calldata userOp, address _entrypoint, uint256 chainId)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(UserOperationLib.hash(userOp), _entrypoint, chainId));
    }

    receive() external payable { }

    fallback() external payable { }
}
