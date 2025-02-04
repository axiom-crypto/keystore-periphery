// // SPDX-License-Identifier: MIT
// pragma solidity 0.8.26;

// import { KeystoreAggregator } from "../src/KeystoreAggregator.sol";
// import { StorageProofVerifier } from "../src/StorageProofVerifier.sol";
// import { IStorageProofVerifier } from "../src/interfaces/IStorageProofVerifier.sol";
// import { IL1Block } from "../src/interfaces/IL1Block.sol";

// import { UserOperationLib } from "account-abstraction/core/UserOperationLib.sol";
// import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

// import { Test, safeconsole as console, console2, stdJson as StdJson } from "forge-std/Test.sol";

// contract KeystoreAggregatorTest is Test {
//     using StdJson for *;

//     IL1Block internal constant L1BLOCK = IL1Block(0x4200000000000000000000000000000000000015);

//     StorageProofVerifier public verifier;
//     KeystoreAggregator public aggregator;

//     address permissionedSigner = 0x956dCC274857dB39bCa4b59bbD8723cb41A1bcd3;
//     uint256 permissionedSignerKey = 0x5d410fb728112d479864c6a72703441ef9cdd51935ad5a6ee359b6cca74d82c9;

//     function setUp() public {
//         // Block number at which L1Block.number() is 20361359
//         vm.createSelectFork(vm.envString("RPC_URL_10"), 123_022_040);

//         verifier = new StorageProofVerifier();
//         aggregator = new KeystoreAggregator(verifier);
//     }

//     function test_persistBlockhash() public {
//         aggregator.cacheBlockhash();

//         bytes32 _hash = L1BLOCK.hash();

//         assertEq(aggregator.blockhashes(_hash), true, "Persisted blockhash is incorrect");
//     }

//     function test_AggregationWithExclusionProof() public {
//         vm.store(
//             0x4200000000000000000000000000000000000015,
//             bytes32(uint256(0x02)),
//             0x70427ad6ea61db7a02c6b35d4b84b4ecd343cbcdee6e528b703555ec2c406eff
//         );

//         aggregator.cacheBlockhash();

//         (bytes memory blockHeader, bytes[] memory accountProof, bytes[] memory storageProof) =
//             _readStorageProof("proofs/Exclusion.json");

//         IStorageProofVerifier.StorageProof memory _storageProof = IStorageProofVerifier.StorageProof({
//             storageValue: bytes32(0x825d6e5f8555e9550bbd12045907da3b0f78ada099df1ed548c3df366037eabc),
//             blockHeader: blockHeader,
//             accountProof: accountProof,
//             storageProof: storageProof
//         });

//         // Aggregated signature data
//         IStorageProofVerifier.StorageProof[] memory storageProofs = new IStorageProofVerifier.StorageProof[](1);
//         storageProofs[0] = _storageProof;
//         uint256[] memory derivedRootIndices = new uint256[](1);
//         derivedRootIndices[0] = 0;

//         bytes memory aggregatedSignature = abi.encode(storageProofs, derivedRootIndices);

//         // Unaggregated signature data
//         address[] memory allowedSignersList = new address[](1);
//         allowedSignersList[0] = permissionedSigner;

//         bytes32[] memory proof = new bytes32[](3);
//         proof[0] = 0x10dd99ee5e9ccc2b8a351dbdb0738a77911e1a4ef6fb50174851bb3fc9c2b03c;
//         proof[1] = 0x0c3714142233810f87811489afa05f423c38a84f5860cd52ba6073057f7dfc6b;
//         proof[2] = 0xba804543273025b68f7eb29beaedc4b8b108fc8baffea6846b33d31403391fdb;

//         KeystoreAggregator.KeyDataMerkleProof memory keyDataMerkleProof = KeystoreAggregator.KeyDataMerkleProof({
//             isExclusion: true,
//             exclusionExtraData: hex"01030303030303030303030303030303030303030303030303030303030303030300000000000000000000000000000000000000000000000000000000000000004a7a4de37def8e10861261f58e1003e6086df449b615bb411c39669548e19dba",
//             nextDummyByte: 0x00,
//             nextImtKey: 0x0000000000000000000000000000000000000000000000000000000000000000,
//             vkeyHash: 0xafc6c9447c95010572d8479b90db27c53534a65555825f324cb0530152b169a4,
//             keystoreAddress: 0x03d0c89f264b5a63961f686a18ce0756abb6b886096f70b6bd4ed5fa3324da43,
//             requiredSigners: 1,
//             allowedSignersList: allowedSignersList,
//             proof: proof,
//             isLeft: 4
//         });

//         PackedUserOperation[] memory userOps = new PackedUserOperation[](1);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(permissionedSignerKey, this.userOpHash(userOps[0]));

//         bytes memory userOpSig = abi.encodePacked(r, s, v);

//         bytes memory unaggregatedSignature = abi.encode(_storageProof, keyDataMerkleProof, userOpSig);

//         userOps[0].signature = unaggregatedSignature;

//         assertEq(
//             keccak256(aggregatedSignature),
//             keccak256(aggregator.aggregateSignatures(userOps)),
//             "Aggregated signature is incorrect"
//         );

//         assertEq(
//             keccak256(aggregator.validateUserOpSignature(userOps[0])),
//             keccak256(unaggregatedSignature),
//             "Unaggregated signature should remain unchanged"
//         );

//         aggregator.validateSignatures(userOps, aggregatedSignature);
//     }

//     function test_AggregationWithInclusionProof() public {
//         vm.store(
//             0x4200000000000000000000000000000000000015,
//             bytes32(uint256(0x02)),
//             0x2c3d428851d093aa9f98b399a783f0ca7dbf578689d8419fe7c04a4acf4ffb82
//         );

//         aggregator.cacheBlockhash();

//         (bytes memory blockHeader, bytes[] memory accountProof, bytes[] memory storageProof) =
//             _readStorageProof("proofs/Inclusion.json");

//         IStorageProofVerifier.StorageProof memory _storageProof = IStorageProofVerifier.StorageProof({
//             storageValue: bytes32(0xeda6e8581ab632607096bd147db73eb9b07a1f6b134864b601146ff44299ad6f),
//             blockHeader: blockHeader,
//             accountProof: accountProof,
//             storageProof: storageProof
//         });

//         // Aggregated signature data
//         IStorageProofVerifier.StorageProof[] memory storageProofs = new IStorageProofVerifier.StorageProof[](1);
//         storageProofs[0] = _storageProof;
//         uint256[] memory derivedRootIndices = new uint256[](1);
//         derivedRootIndices[0] = 0;

//         bytes memory aggregatedSignature = abi.encode(storageProofs, derivedRootIndices);

//         // Unaggregated signature data
//         address[] memory allowedSignersList = new address[](1);
//         allowedSignersList[0] = permissionedSigner;

//         bytes32[] memory proof = new bytes32[](3);
//         proof[0] = 0xdb1e4e1ce576f023aecc49f3386ed363f440ca96a053ca56f6df50076c342c75;
//         proof[1] = 0xe829a30f44bef8ee63124c388fe83112ca71b09979001c1b861de35d3562ab93;
//         proof[2] = 0x7ead7c301b6f2bb38f30a57e70205e602ad8b9b95555fe654188222de5781675;

//         KeystoreAggregator.KeyDataMerkleProof memory keyDataMerkleProof = KeystoreAggregator.KeyDataMerkleProof({
//             isExclusion: false,
//             exclusionExtraData: hex"",
//             nextDummyByte: 0x00,
//             nextImtKey: 0x0000000000000000000000000000000000000000000000000000000000000000,
//             vkeyHash: 0xafc6c9447c95010572d8479b90db27c53534a65555825f324cb0530152b169a4,
//             keystoreAddress: 0x03d0c89f264b5a63961f686a18ce0756abb6b886096f70b6bd4ed5fa3324da43,
//             requiredSigners: 1,
//             allowedSignersList: allowedSignersList,
//             proof: proof,
//             isLeft: 3
//         });

//         PackedUserOperation[] memory userOps = new PackedUserOperation[](1);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(permissionedSignerKey, this.userOpHash(userOps[0]));

//         bytes memory userOpSig = abi.encodePacked(r, s, v);

//         bytes memory unaggregatedSignature = abi.encode(_storageProof, keyDataMerkleProof, userOpSig);

//         userOps[0].signature = unaggregatedSignature;

//         assertEq(
//             keccak256(aggregatedSignature),
//             keccak256(aggregator.aggregateSignatures(userOps)),
//             "Aggregated signature is incorrect"
//         );

//         assertEq(
//             keccak256(aggregator.validateUserOpSignature(userOps[0])),
//             keccak256(unaggregatedSignature),
//             "Unaggregated signature should remain unchanged"
//         );

//         aggregator.validateSignatures(userOps, aggregatedSignature);
//     }

//     function _readStorageProof(string memory filePath)
//         public
//         view
//         returns (bytes memory blockHeader, bytes[] memory accountProof, bytes[] memory storageProof)
//     {
//         string memory json = vm.readFile(filePath);
//         blockHeader = json.readBytes(".rlp_block_header");
//         accountProof = json.readBytesArray(".storage_proof.accountProof");
//         storageProof = json.readBytesArray(".storage_proof.storageProof[0].proof");
//     }

//     function userOpHash(PackedUserOperation calldata userOp) external pure returns (bytes32) {
//         return UserOperationLib.hash(userOp);
//     }
// }
