// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title Multisig
 * @author Franco Bregante
 * @notice Implements a k-of-n multisignature wallet using ECDSA signature verification.
 * Signatures can be provided in any order.
 * Changes to threshold or signers must also be approved via k-of-n signatures.
 * Uses EIP-712 for typed structured data hashing and signing.
 * Uses direct internal calls for self-governance functions.
 */
contract Multisig is EIP712 {
    // --- Custom Errors ---

    error InvalidThreshold(uint256 k, uint256 n);
    error AlreadySigner(address signer);
    error NotSigner(address signer);
    error ThresholdNotMet(uint256 required, uint256 provided);
    error InvalidSignature(address recovered);
    error InvalidSignaturesArray();
    error InvalidSignatureLength(uint256 index);
    error DuplicateSignerInNewSet();
    error DuplicateSignerInInitialSet();
    error InvalidSelfCallTarget();
    error ZeroAddressSigner();
    error EmptySigners();

    // --- Events ---

    event ExecutionSuccess(bytes32 indexed txHash);
    event ExecutionFailure(bytes32 indexed txHash, bytes reason);
    event ThresholdUpdated(uint256 newThreshold);
    event SignersUpdated(address[] newSigners);

    // --- State Variables ---

    mapping(address => bool) public isSigner;
    address[] public signers;
    uint256 public threshold;
    uint256 public nonce;

    // --- Selectors for Internal Governance Functions ---
    bytes4 private constant _UPDATE_THRESHOLD_SELECTOR = bytes4(keccak256("updateThreshold(uint256)"));
    bytes4 private constant _UPDATE_SIGNERS_SELECTOR = bytes4(keccak256("updateSigners(address[])"));

    // --- EIP-712 Struct Hashes ---

    bytes32 private constant _TRANSACTION_TYPEHASH =
        keccak256("Transaction(address target,uint256 value,bytes data,uint256 nonce)");

    // --- Constructor ---

    constructor(address[] memory _initialSigners, uint256 _initialThreshold) EIP712("Multisig", "1") {
        uint256 numSigners = _initialSigners.length;
        if (_initialThreshold == 0 || _initialThreshold > numSigners) {
            revert InvalidThreshold(_initialThreshold, numSigners);
        }
        if (numSigners == 0) {
            revert EmptySigners();
        }

        for (uint256 i = 0; i < numSigners; i++) {
            address signer = _initialSigners[i];
            if (signer == address(0)) {
                revert ZeroAddressSigner();
            }
            for (uint256 j = 0; j < i; j++) {
                if (_initialSigners[j] == signer) {
                    revert DuplicateSignerInInitialSet();
                }
            }
            isSigner[signer] = true;
        }
        signers = _initialSigners;
        threshold = _initialThreshold;
    }

    // --- Core Execution Logic ---

    function execute(address _target, uint256 _value, bytes calldata _data, bytes[] calldata _signatures)
        public
        payable
        returns (bool success)
    {
        uint256 requiredSigs = threshold;
        if (_signatures.length < requiredSigs) {
            revert ThresholdNotMet(requiredSigs, 0);
        }

        uint256 currentNonce = nonce;
        bytes32 txHash = _hashTransaction(_target, _value, _data, currentNonce);

        _verifySignatures(txHash, _signatures, requiredSigs);

        nonce++;

        if (_target == address(this)) {
            // Internal call (Governance)
            if (_value != 0) {
                revert InvalidSelfCallTarget();
            }

            bytes4 selector;
            if (_data.length < 4) {
                revert InvalidSelfCallTarget();
            }
            assembly {
                // Extract selector
                selector := calldataload(_data.offset)
            }

            if (selector == _UPDATE_THRESHOLD_SELECTOR) {
                (uint256 newThreshold) = abi.decode(_data[4:], (uint256));
                updateThreshold(newThreshold);
                success = true;
            } else if (selector == _UPDATE_SIGNERS_SELECTOR) {
                (address[] memory newSigners) = abi.decode(_data[4:], (address[]));
                updateSigners(newSigners);
                success = true;
            } else {
                revert InvalidSelfCallTarget();
            }
            emit ExecutionSuccess(txHash);
        } else {
            // External call
            bytes memory result;
            (success, result) = _target.call{value: _value}(_data);

            if (success) {
                emit ExecutionSuccess(txHash);
            } else {
                emit ExecutionFailure(txHash, result);
            }
        }
        return success;
    }

    // --- Signature Verification ---

    function _verifySignatures(bytes32 _txHash, bytes[] calldata _signatures, uint256 _requiredSigs) internal view {
        uint256 validSignatureCount = 0;
        address[] memory signersWhoSigned = new address[](_requiredSigs);

        for (uint256 i = 0; i < _signatures.length; i++) {
            bytes calldata sig = _signatures[i];
            if (sig.length != 65) {
                revert InvalidSignatureLength(i);
            }

            address recoveredSigner = ECDSA.recover(_txHash, sig);

            if (recoveredSigner == address(0)) {
                revert InvalidSignature(recoveredSigner);
            }
            if (!isSigner[recoveredSigner]) {
                revert NotSigner(recoveredSigner);
            }

            bool alreadySigned = false;
            for (uint256 j = 0; j < validSignatureCount; j++) {
                if (signersWhoSigned[j] == recoveredSigner) {
                    alreadySigned = true;
                    break;
                }
            }

            if (!alreadySigned) {
                signersWhoSigned[validSignatureCount] = recoveredSigner;
                validSignatureCount++;
            }

            if (validSignatureCount >= _requiredSigs) {
                return;
            }
        }

        if (validSignatureCount < _requiredSigs) {
            revert ThresholdNotMet(_requiredSigs, validSignatureCount);
        }
    }

    // --- Self-Governance Functions (Internal) ---

    function updateThreshold(uint256 _newThreshold) internal {
        uint256 numSigners = signers.length;
        if (_newThreshold == 0 || _newThreshold > numSigners) {
            revert InvalidThreshold(_newThreshold, numSigners);
        }
        threshold = _newThreshold;
        emit ThresholdUpdated(_newThreshold);
    }

    function updateSigners(address[] memory _newSigners) internal {
        uint256 newNumSigners = _newSigners.length;
        if (newNumSigners == 0) {
            revert EmptySigners();
        }
        if (threshold > newNumSigners) {
            revert InvalidThreshold(threshold, newNumSigners);
        }

        for (uint256 i = 0; i < signers.length; i++) {
            delete isSigner[signers[i]];
        }

        address[] memory newSignersMemory = new address[](newNumSigners);
        for (uint256 i = 0; i < newNumSigners; i++) {
            address signer = _newSigners[i];
            if (signer == address(0)) {
                revert ZeroAddressSigner();
            }
            for (uint256 j = 0; j < i; j++) {
                if (_newSigners[j] == signer) {
                    revert DuplicateSignerInNewSet();
                }
            }
            isSigner[signer] = true;
            newSignersMemory[i] = signer;
        }
        signers = newSignersMemory;
        emit SignersUpdated(newSignersMemory);
    }

    // --- EIP-712 Hashing ---

    function _hashTransaction(address _target, uint256 _value, bytes calldata _data, uint256 _nonce)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(keccak256(abi.encode(_TRANSACTION_TYPEHASH, _target, _value, keccak256(_data), _nonce)));
    }

    // --- Getters ---

    function getSigners() external view returns (address[] memory) {
        return signers;
    }

    function getSignerCount() external view returns (uint256) {
        return signers.length;
    }

    function getDomainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function getTransactionTypeHash() external pure returns (bytes32) {
        return _TRANSACTION_TYPEHASH;
    }

    // --- Fallback ---

    receive() external payable {}
}
