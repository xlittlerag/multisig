// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Multisig} from "../src/Multisig.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// --- Interface for accessing internal function selectors ---
interface IMultisig {
    function updateThreshold(uint256 _newThreshold) external;
    function updateSigners(address[] calldata _newSigners) external;
}

// --- Helper Contract for Testing Execution ---
contract TargetContract {
    uint256 public valueSet;
    address public lastSender;
    bool public called = false;

    event ValueSet(address indexed sender, uint256 value);

    function setValue(uint256 _value) public payable {
        valueSet = _value;
        lastSender = msg.sender;
        called = true;
        emit ValueSet(msg.sender, _value);
    }

    function callMe() public {
        called = true;
        lastSender = msg.sender;
    }

    function callMeAndRevert() public pure {
        revert("Target contract reverted");
    }

    receive() external payable {
        called = true;
        lastSender = msg.sender;
    }
}

// --- Test Suite ---
contract MultisigTest is Test {
    // Contract instances
    Multisig internal multisig;
    TargetContract internal target;

    // Signer configuration
    uint256 internal constant THRESHOLD = 2; // k = 2
    uint256 internal signer1Pk = 0x111;
    uint256 internal signer2Pk = 0x222;
    uint256 internal signer3Pk = 0x333; // An extra signer not initially part of k=2
    address internal signer1Addr;
    address internal signer2Addr;
    address internal signer3Addr;
    address[] internal initialSigners;

    // Other addresses
    address internal nonSignerAddr = makeAddr("nonSigner");
    address internal deployer;

    // --- Setup ---
    function setUp() public {
        // Derive addresses from private keys
        signer1Addr = vm.addr(signer1Pk);
        signer2Addr = vm.addr(signer2Pk);
        signer3Addr = vm.addr(signer3Pk);
        deployer = address(this);

        // Define initial signers for deployment
        initialSigners = new address[](2);
        initialSigners[0] = signer1Addr;
        initialSigners[1] = signer2Addr;

        // Deploy Multisig contract
        multisig = new Multisig(initialSigners, THRESHOLD);

        // Deploy TargetContract
        target = new TargetContract();

        // Fund the multisig contract for value transfers in tests
        vm.deal(address(multisig), 10 ether);
    }

    // --- Helper Functions ---

    /**
     * @notice Calculates the EIP-712 digest hash for a transaction.
     */
    function _calculateDigest(address _target, uint256 _value, bytes memory _data, uint256 _nonce)
        internal
        view
        returns (bytes32 digest)
    {
        bytes32 domainSeparator = multisig.getDomainSeparator();
        bytes32 transactionTypeHash = multisig.getTransactionTypeHash();
        bytes32 structHash = keccak256(abi.encode(transactionTypeHash, _target, _value, keccak256(_data), _nonce));
        digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /**
     * @notice Extracts v, r, s components from a 65-byte signature.
     */
    function _extractVRS(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(sig.length == 65, "Invalid sig length");
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60))) // Loads 32 bytes, takes the first byte
        }
    }

    /**
     * @notice Signs the EIP-712 hash of a multisig transaction.
     */
    function _signTransaction(address _target, uint256 _value, bytes memory _data, uint256 _nonce, uint256 _privateKey)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 digest = _calculateDigest(_target, _value, _data, _nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    /**
     * @notice Assembles an array of signatures from specified signers.
     */
    function _assembleSignatures(
        address _target,
        uint256 _value,
        bytes memory _data,
        uint256 _nonce,
        uint256[] memory _privateKeys
    ) internal view returns (bytes[] memory signatures) {
        signatures = new bytes[](_privateKeys.length);
        for (uint256 i = 0; i < _privateKeys.length; i++) {
            signatures[i] = _signTransaction(_target, _value, _data, _nonce, _privateKeys[i]);
        }
    }

    // --- Deployment Tests ---

    function test_Deploy_CorrectState() public view {
        assertEq(multisig.threshold(), THRESHOLD);
        assertEq(multisig.nonce(), 0);
        assertEq(multisig.getSignerCount(), initialSigners.length);
        assertTrue(multisig.isSigner(signer1Addr));
        assertTrue(multisig.isSigner(signer2Addr));
        assertFalse(multisig.isSigner(signer3Addr));
        assertEq(multisig.getSigners()[0], signer1Addr);
        assertEq(multisig.getSigners()[1], signer2Addr);
    }

    function test_Deploy_Revert_InvalidThreshold_Zero() public {
        vm.expectRevert(abi.encodeWithSelector(Multisig.InvalidThreshold.selector, 0, 2));
        new Multisig(initialSigners, 0);
    }

    function test_Deploy_Revert_InvalidThreshold_TooHigh() public {
        vm.expectRevert(abi.encodeWithSelector(Multisig.InvalidThreshold.selector, 3, 2));
        new Multisig(initialSigners, 3);
    }

    function test_Deploy_Revert_EmptySigners() public {
        address[] memory emptySigners = new address[](0);
        vm.expectRevert(Multisig.EmptySigners.selector);
        new Multisig(emptySigners, 1);
    }

    function test_Deploy_Revert_ZeroAddressSigner() public {
        address[] memory signersWithZero = new address[](2);
        signersWithZero[0] = signer1Addr;
        signersWithZero[1] = address(0);
        vm.expectRevert(Multisig.ZeroAddressSigner.selector);
        new Multisig(signersWithZero, 2);
    }

    function test_Deploy_Revert_DuplicateSigner() public {
        address[] memory duplicateSigners = new address[](2);
        duplicateSigners[0] = signer1Addr;
        duplicateSigners[1] = signer1Addr;
        vm.expectRevert(Multisig.DuplicateSigner.selector);
        new Multisig(duplicateSigners, 2);
    }

    // --- Execute Success Tests ---

    function test_Execute_Success_ExactThreshold() public {
        uint256 valueToSend = 1 ether;
        uint256 targetValue = 123;
        bytes memory data = abi.encodeWithSelector(TargetContract.setValue.selector, targetValue);
        uint256 nonce = multisig.nonce();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(target), valueToSend, data, nonce, pks);

        bytes32 expectedTxHash = _calculateDigest(address(target), valueToSend, data, nonce);
        vm.expectEmit(true, true, true, true, address(multisig));
        emit Multisig.ExecutionSuccess(expectedTxHash);

        uint256 balanceBefore = address(target).balance;
        multisig.execute{value: 0}(address(target), valueToSend, data, signatures);
        uint256 balanceAfter = address(target).balance;

        assertTrue(target.called());
        assertEq(target.valueSet(), targetValue);
        assertEq(target.lastSender(), address(multisig));
        assertEq(multisig.nonce(), nonce + 1);
        assertEq(balanceAfter - balanceBefore, valueToSend);
    }

    function test_Execute_Success_MoreThanThreshold() public {
        // Add signer3 to the multisig first
        address[] memory newSigners = new address[](3);
        newSigners[0] = signer1Addr;
        newSigners[1] = signer2Addr;
        newSigners[2] = signer3Addr;
        bytes memory updateSignersData = abi.encodeWithSelector(IMultisig.updateSigners.selector, newSigners);
        uint256 nonce0 = multisig.nonce();
        uint256[] memory pks0 = new uint256[](2);
        pks0[0] = signer1Pk;
        pks0[1] = signer2Pk;
        bytes[] memory signatures0 = _assembleSignatures(address(multisig), 0, updateSignersData, nonce0, pks0);

        vm.expectEmit(true, true, true, true, address(multisig));
        emit Multisig.SignersUpdated(newSigners);
        bytes32 expectedTxHash0 = _calculateDigest(address(multisig), 0, updateSignersData, nonce0);
        vm.expectEmit(true, true, true, true, address(multisig));
        emit Multisig.ExecutionSuccess(expectedTxHash0);

        multisig.execute(address(multisig), 0, updateSignersData, signatures0);
        assertEq(multisig.getSignerCount(), 3, "Signer count should be 3 after update");
        assertTrue(multisig.isSigner(signer3Addr), "Signer 3 should be added");

        // Now execute with 3 signatures (threshold is still 2)
        bytes memory data = abi.encodeWithSelector(TargetContract.callMe.selector);
        uint256 nonce1 = multisig.nonce();
        uint256[] memory pks1 = new uint256[](3);
        pks1[0] = signer1Pk;
        pks1[1] = signer2Pk;
        pks1[2] = signer3Pk;
        bytes[] memory signatures1 = _assembleSignatures(address(target), 0, data, nonce1, pks1);

        bytes32 expectedTxHash1 = _calculateDigest(address(target), 0, data, nonce1);
        vm.expectEmit(true, true, true, true, address(multisig));
        emit Multisig.ExecutionSuccess(expectedTxHash1);

        multisig.execute(address(target), 0, data, signatures1);

        assertTrue(target.called());
        assertEq(target.lastSender(), address(multisig));
        assertEq(multisig.nonce(), nonce1 + 1);
    }

    function test_Execute_Success_ZeroValueEmptyData() public {
        uint256 valueToSend = 0 ether;
        bytes memory data = "";
        uint256 nonce = multisig.nonce();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(target), valueToSend, data, nonce, pks);

        bytes32 expectedTxHash = _calculateDigest(address(target), valueToSend, data, nonce);
        vm.expectEmit(true, true, true, true, address(multisig));
        emit Multisig.ExecutionSuccess(expectedTxHash);

        uint256 balanceBefore = address(target).balance;
        multisig.execute(address(target), valueToSend, data, signatures);
        uint256 balanceAfter = address(target).balance;

        assertTrue(target.called());
        assertEq(target.lastSender(), address(multisig));
        assertEq(multisig.nonce(), nonce + 1);
        assertEq(balanceAfter, balanceBefore);
    }

    // --- Execute Revert Tests ---

    function test_Execute_Revert_InsufficientSignatures() public {
        bytes memory data = abi.encodeWithSelector(TargetContract.callMe.selector);
        uint256 nonce = multisig.nonce();

        uint256[] memory pks = new uint256[](1);
        pks[0] = signer1Pk;
        bytes[] memory signatures = _assembleSignatures(address(target), 0, data, nonce, pks);

        vm.expectRevert(abi.encodeWithSelector(Multisig.ThresholdNotMet.selector, THRESHOLD, 0));
        multisig.execute(address(target), 0, data, signatures);

        assertEq(multisig.nonce(), nonce);
    }

    function test_Execute_Revert_DuplicatedSignature() public {
        bytes memory data = abi.encodeWithSelector(TargetContract.callMe.selector);
        uint256 nonce = multisig.nonce();

        bytes memory sig1 = _signTransaction(address(target), 0, data, nonce, signer1Pk);
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = sig1;
        signatures[1] = sig1;

        vm.expectRevert(abi.encodeWithSelector(Multisig.AlreadySigner.selector, signer1Addr));
        multisig.execute(address(target), 0, data, signatures);

        assertEq(multisig.nonce(), nonce);
    }

    function test_Execute_Revert_InvalidSignature_Length() public {
        bytes memory data = abi.encodeWithSelector(TargetContract.callMe.selector);
        uint256 nonce = multisig.nonce();

        bytes memory sig1 = _signTransaction(address(target), 0, data, nonce, signer1Pk);
        bytes memory sig2_invalid = hex"112233";
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = sig1;
        signatures[1] = sig2_invalid;

        vm.expectRevert(abi.encodeWithSelector(Multisig.InvalidSignatureLength.selector, 1));
        multisig.execute(address(target), 0, data, signatures);
        assertEq(multisig.nonce(), nonce);
    }

    function test_Execute_Revert_InvalidSignature_Content() public {
        bytes memory data = abi.encodeWithSelector(TargetContract.callMe.selector);
        uint256 nonce = multisig.nonce();

        bytes memory sig1 = _signTransaction(address(target), 0, data, nonce, signer1Pk);
        bytes memory wrong_data = abi.encodeWithSelector(TargetContract.setValue.selector, 999);
        bytes memory sig2_wrong = _signTransaction(address(target), 0, wrong_data, nonce, signer2Pk);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = sig1;
        signatures[1] = sig2_wrong;

        bytes32 digest = _calculateDigest(address(target), 0, data, nonce);
        (uint8 v, bytes32 r, bytes32 s) = _extractVRS(sig2_wrong);
        address expectedRecoveredAddr = ecrecover(digest, v, r, s);

        vm.expectRevert(abi.encodeWithSelector(Multisig.NotSigner.selector, expectedRecoveredAddr));
        multisig.execute(address(target), 0, data, signatures);
        assertEq(multisig.nonce(), nonce);
    }

    function test_Execute_Revert_NotSigner() public {
        bytes memory data = abi.encodeWithSelector(TargetContract.callMe.selector);
        uint256 nonce = multisig.nonce();

        bytes memory sig1 = _signTransaction(address(target), 0, data, nonce, signer1Pk);
        uint256 nonSignerPk = 0x999;
        address nonSignerAddrDerived = vm.addr(nonSignerPk);
        bytes memory sig_non_signer = _signTransaction(address(target), 0, data, nonce, nonSignerPk);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = sig1;
        signatures[1] = sig_non_signer;

        vm.expectRevert(abi.encodeWithSelector(Multisig.NotSigner.selector, nonSignerAddrDerived));
        multisig.execute(address(target), 0, data, signatures);
        assertEq(multisig.nonce(), nonce);
    }

    function test_Execute_Revert_IncorrectNonce() public {
        bytes memory data = abi.encodeWithSelector(TargetContract.callMe.selector);
        uint256 currentNonce = multisig.nonce();
        uint256 incorrectNonce = currentNonce + 1;

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(target), 0, data, incorrectNonce, pks);

        bytes32 correctDigest = _calculateDigest(address(target), 0, data, currentNonce);
        (uint8 v, bytes32 r, bytes32 s) = _extractVRS(signatures[0]);
        address expectedRecoveredAddr = ecrecover(correctDigest, v, r, s);

        vm.expectRevert(abi.encodeWithSelector(Multisig.NotSigner.selector, expectedRecoveredAddr));
        multisig.execute(address(target), 0, data, signatures);
        assertEq(multisig.nonce(), currentNonce);
    }

    function test_Execute_Revert_ReplayAttack() public {
        bytes memory data = abi.encodeWithSelector(TargetContract.callMe.selector);
        uint256 nonce0 = multisig.nonce();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures0 = _assembleSignatures(address(target), 0, data, nonce0, pks);
        bytes32 expectedTxHash0 = _calculateDigest(address(target), 0, data, nonce0);
        vm.expectEmit(true, true, true, true, address(multisig));
        emit Multisig.ExecutionSuccess(expectedTxHash0);
        multisig.execute(address(target), 0, data, signatures0);
        assertEq(multisig.nonce(), nonce0 + 1);

        uint256 nonce1 = multisig.nonce();

        bytes32 digestNonce1 = _calculateDigest(address(target), 0, data, nonce1);
        (uint8 v, bytes32 r, bytes32 s) = _extractVRS(signatures0[0]);
        address expectedRecoveredAddr = ecrecover(digestNonce1, v, r, s);

        vm.expectRevert(abi.encodeWithSelector(Multisig.NotSigner.selector, expectedRecoveredAddr));
        multisig.execute(address(target), 0, data, signatures0);
        assertEq(multisig.nonce(), nonce1);
    }

    function test_Execute_HandleTargetRevert() public {
        bytes memory data = abi.encodeWithSelector(TargetContract.callMeAndRevert.selector);
        uint256 nonce = multisig.nonce();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(target), 0, data, nonce, pks);

        bytes32 expectedTxHash = _calculateDigest(address(target), 0, data, nonce);
        vm.expectEmit(true, true, false, false, address(multisig));
        emit Multisig.ExecutionFailure(expectedTxHash, "");

        multisig.execute(address(target), 0, data, signatures);

        assertEq(multisig.nonce(), nonce + 1);
    }

    // --- Governance Tests ---

    function test_UpdateThreshold_Success() public {
        uint256 newThreshold = 1;
        bytes memory updateData = abi.encodeWithSelector(IMultisig.updateThreshold.selector, newThreshold);
        uint256 nonce = multisig.nonce();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(multisig), 0, updateData, nonce, pks);

        vm.expectEmit(true, true, true, true, address(multisig)); // ThresholdUpdated
        emit Multisig.ThresholdUpdated(newThreshold);
        bytes32 expectedTxHash = _calculateDigest(address(multisig), 0, updateData, nonce);
        vm.expectEmit(true, true, true, true, address(multisig)); // ExecutionSuccess
        emit Multisig.ExecutionSuccess(expectedTxHash);

        multisig.execute(address(multisig), 0, updateData, signatures);

        assertEq(multisig.threshold(), newThreshold);
        assertEq(multisig.nonce(), nonce + 1);
    }

    function test_UpdateThreshold_Revert_InvalidNewThreshold_Zero() public {
        uint256 newThreshold = 0;
        bytes memory updateData = abi.encodeWithSelector(IMultisig.updateThreshold.selector, newThreshold);
        uint256 nonce = multisig.nonce();
        uint256 initialThreshold = multisig.threshold();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(multisig), 0, updateData, nonce, pks);

        vm.expectRevert(abi.encodeWithSelector(Multisig.InvalidThreshold.selector, newThreshold, 2));

        multisig.execute(address(multisig), 0, updateData, signatures);

        assertEq(multisig.threshold(), initialThreshold);
        assertEq(multisig.nonce(), nonce);
    }

    function test_UpdateThreshold_Revert_InvalidNewThreshold_TooHigh() public {
        uint256 newThreshold = 3;
        bytes memory updateData = abi.encodeWithSelector(IMultisig.updateThreshold.selector, newThreshold);
        uint256 nonce = multisig.nonce();
        uint256 initialThreshold = multisig.threshold();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(multisig), 0, updateData, nonce, pks);

        vm.expectRevert(abi.encodeWithSelector(Multisig.InvalidThreshold.selector, newThreshold, 2));

        multisig.execute(address(multisig), 0, updateData, signatures);

        assertEq(multisig.threshold(), initialThreshold);
        assertEq(multisig.nonce(), nonce);
    }

    function test_UpdateSigners_Success() public {
        address[] memory newSigners = new address[](2);
        newSigners[0] = signer1Addr;
        newSigners[1] = signer3Addr;
        bytes memory updateData = abi.encodeWithSelector(IMultisig.updateSigners.selector, newSigners);
        uint256 nonce = multisig.nonce();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(multisig), 0, updateData, nonce, pks);

        vm.expectEmit(true, true, true, true, address(multisig));
        emit Multisig.SignersUpdated(newSigners);
        bytes32 expectedTxHash = _calculateDigest(address(multisig), 0, updateData, nonce);
        vm.expectEmit(true, true, true, true, address(multisig));
        emit Multisig.ExecutionSuccess(expectedTxHash);

        multisig.execute(address(multisig), 0, updateData, signatures);

        assertEq(multisig.getSignerCount(), 2);
        assertTrue(multisig.isSigner(signer1Addr));
        assertFalse(multisig.isSigner(signer2Addr));
        assertTrue(multisig.isSigner(signer3Addr));
        assertEq(multisig.nonce(), nonce + 1);
    }

    function test_UpdateSigners_Revert_EmptyNewSet() public {
        address[] memory newSigners = new address[](0);
        bytes memory updateData = abi.encodeWithSelector(IMultisig.updateSigners.selector, newSigners);
        uint256 nonce = multisig.nonce();
        uint256 initialSignerCount = multisig.getSignerCount();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(multisig), 0, updateData, nonce, pks);

        vm.expectRevert(Multisig.EmptySigners.selector);

        multisig.execute(address(multisig), 0, updateData, signatures);

        assertEq(multisig.getSignerCount(), initialSignerCount);
        assertEq(multisig.nonce(), nonce);
    }

    function test_UpdateSigners_Revert_ZeroAddressInNewSet() public {
        address[] memory newSigners = new address[](2);
        newSigners[0] = signer1Addr;
        newSigners[1] = address(0);
        bytes memory updateData = abi.encodeWithSelector(IMultisig.updateSigners.selector, newSigners);
        uint256 nonce = multisig.nonce();
        uint256 initialSignerCount = multisig.getSignerCount();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(multisig), 0, updateData, nonce, pks);

        vm.expectRevert(Multisig.ZeroAddressSigner.selector);

        multisig.execute(address(multisig), 0, updateData, signatures);

        assertEq(multisig.getSignerCount(), initialSignerCount);
        assertEq(multisig.nonce(), nonce);
    }

    function test_UpdateSigners_Revert_DuplicateInNewSet() public {
        address[] memory newSigners = new address[](2);
        newSigners[0] = signer1Addr;
        newSigners[1] = signer1Addr;
        bytes memory updateData = abi.encodeWithSelector(IMultisig.updateSigners.selector, newSigners);
        uint256 nonce = multisig.nonce();
        uint256 initialSignerCount = multisig.getSignerCount();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(multisig), 0, updateData, nonce, pks);

        vm.expectRevert(Multisig.DuplicateSigner.selector);

        multisig.execute(address(multisig), 0, updateData, signatures);

        assertEq(multisig.getSignerCount(), initialSignerCount);
        assertEq(multisig.nonce(), nonce);
    }

    function test_UpdateSigners_Revert_ThresholdBecomesInvalid() public {
        address[] memory newSigners = new address[](1);
        newSigners[0] = signer1Addr;
        bytes memory updateData = abi.encodeWithSelector(IMultisig.updateSigners.selector, newSigners);
        uint256 nonce = multisig.nonce();
        uint256 initialSignerCount = multisig.getSignerCount();
        uint256 initialThreshold = multisig.threshold();

        uint256[] memory pks = new uint256[](2);
        pks[0] = signer1Pk;
        pks[1] = signer2Pk;
        bytes[] memory signatures = _assembleSignatures(address(multisig), 0, updateData, nonce, pks);

        vm.expectRevert(abi.encodeWithSelector(Multisig.InvalidThreshold.selector, initialThreshold, 1));

        multisig.execute(address(multisig), 0, updateData, signatures);

        assertEq(multisig.getSignerCount(), initialSignerCount);
        assertEq(multisig.nonce(), nonce);
    }

    // --- Receive Ether Test ---
    function test_ReceiveEther() public {
        uint256 amount = 1 ether;
        uint256 initialBalance = address(multisig).balance;
        (bool success,) = payable(address(multisig)).call{value: amount}("");
        assertTrue(success, "Receive Ether failed");
        assertEq(address(multisig).balance, initialBalance + amount);
    }
}
