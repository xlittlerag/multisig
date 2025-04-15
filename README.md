# K-of-N ECDSA Multisig Wallet

## Overview

This repository contains a Solidity smart contract implementing a K-of-N multisignature wallet for EVM-compatible blockchains. This contract manages its own authorization logic based on multiple signatures verified on-chain.

It allows a predefined group of `n` authorized signers to collectively approve actions by reaching a threshold of `k` signatures. The contract emphasizes security and decentralization by having no single owner and requiring the multisignature mechanism even for managing the wallet itself.

## Features

This contract meets the following requirements:

1.  **K-of-N Signing:** Manages a set of `n` authorized signers (`signers`) and requires a minimum of `k` signatures (`threshold`) to approve actions. Both `k` and `n` are configurable.
2.  **Arbitrary Execution:** The core `execute` function allows signers to approve calls to any target contract (`_target`) with any specified Ether value (`_value`) and arbitrary calldata (`_data`). This enables the multisig to interact with any other smart contract or perform any on-chain action.
3.  **Permissionless Execution Trigger:** Anyone can submit a transaction proposal to the `execute` function. Authorization depends solely on providing a sufficient number of valid signatures from the authorized signer set, *not* on the `msg.sender` of the transaction.
4.  **On-Chain Signature Verification:** The contract verifies signatures *internally*. It does not rely on the blockchain's native transaction signing mechanism or built-in multisig account features for authorization.
5.  **ECDSA Signatures:** Uses the standard Elliptic Curve Digital Signature Algorithm (ECDSA) common to Ethereum and EVM chains. Signatures (r, s, v components) are passed directly as parameters to the `execute` function.
6.  **EIP-712 Compliance:** Implements EIP-712 for typed structured data hashing. This provides clearer signing messages for users (when using compatible wallets/signers) and robust protection against replay attacks across different contracts and chains via domain separation.
7.  **Self-Governance:** The contract governs itself. Changes to the signer set (via `updateSigners`) or the signature threshold (via `updateThreshold`) must be executed through the standard `execute` function, requiring k-of-n approval from the *current* set of signers. There is no special owner or admin role.

## Core Mechanism

1.  **Transaction Proposal:** An action (target address, value, calldata) is defined.
2.  **Hashing:** The transaction details, along with the contract's current `nonce`, are hashed according to the EIP-712 standard, using the contract's unique domain separator.
3.  **Signing:** Authorized signers sign this EIP-712 hash using their private keys, producing standard 65-byte ECDSA signatures.
4.  **Execution Call:** Anyone collects at least `k` valid signatures and calls the `execute` function, providing the transaction details and the array of signatures.
5.  **Verification (`_verifySignatures`):**
    * The contract reconstructs the EIP-712 hash using the provided parameters and its current nonce.
    * It iterates through the provided signatures.
    * For each signature, it uses `ECDSA.recover` to determine the signer's address.
    * It checks if the recovered address is an authorized signer (`isSigner`) and if that signer hasn't already provided a valid signature for this specific transaction.
    * It counts the number of unique, valid signatures from authorized signers.
6.  **Nonce Increment:** If signature verification is successful (threshold met), the contract's `nonce` is incremented immediately to prevent replay attacks.
7.  **Dispatch:**
    * **Internal Call (Governance):** If the target is the multisig contract itself and the data corresponds to `updateThreshold` or `updateSigners`, the contract decodes the arguments and calls the internal function directly. Reverts from these internal functions propagate outwards.
    * **External Call:** If the target is an external address, the contract uses a low-level `call` to execute the transaction. Failures in the external call emit an `ExecutionFailure` event but do *not* cause `execute` to revert.

## Self-Governance

The `updateThreshold` and `updateSigners` functions are marked `internal`. They can only be invoked by calling the main `execute` function with:
* `_target` set to `address(this)`.
* `_data` containing the ABI-encoded function call for either `updateThreshold` or `updateSigners`.
* `_value` set to 0.
* A valid set of `k` signatures from the *current* signers authorizing the change.

This ensures that modifications to the contract's core rules require the same level of consensus as any other action.

## Security Considerations

* **Replay Protection:** Crucially handled by the `nonce` incremented on each execution and inclusion in the EIP-712 signed hash. The EIP-712 domain separator further prevents cross-chain or cross-contract replays.
* **Signature Verification:** Relies on OpenZeppelin's battle-tested `ECDSA.recover` implementation. Uniqueness of signatures *per transaction* is checked internally.
* **Access Control:** Internal visibility of governance functions prevents direct external calls. All state changes require passing the `_verifySignatures` check within `execute`.
* **Initialization:** The security of the multisig heavily depends on the correct and secure setup of the initial signers and threshold during deployment.
* **External Call Safety:** Uses low-level `call`. While flexible, callers should be aware of the risks associated with the target contract (reentrancy, etc.). The multisig itself does not add reentrancy guards, assuming the primary security lies in the signature verification. Failures in external calls are logged via event but do not revert the multisig state change (nonce increment).

## Testing Coverage Areas

A comprehensive test suite should cover the following areas (implementation details omitted as per requirements):

* **Deployment:**
    * Successful deployment with valid parameters (k > 0, k <= n, n > 0).
    * Revert on invalid threshold (k=0, k > n).
    * Revert on empty initial signer set.
    * Revert on zero address in initial signer set.
    * Revert on duplicate signers in initial set.
    * Correct initial state (threshold, nonce, signers mapping/array).
* **`execute` Function (Success Cases):**
    * Execution with exactly `k` valid unique signatures.
    * Execution with more than `k` valid unique signatures.
    * Execution involving Ether transfer (`_value > 0`).
    * Execution with complex `_data` targeting another contract.
    * Execution with empty `_data` targeting an EOA or contract `receive()`.
* **`execute` Function (Failure Cases):**
    * Revert if `< k` signatures provided (initial check).
    * Revert if `< k` *unique* valid signatures provided (e.g., duplicate valid signatures).
    * Revert on invalid signature format (e.g., incorrect length).
    * Revert on invalid signature content (e.g., signed wrong hash/nonce).
    * Revert if signature is from a non-authorized address.
    * Revert on replay attack attempt (reusing signatures with an incremented nonce).
    * Failure of external call (check for `ExecutionFailure` event, check nonce *is* incremented).
* **`updateThreshold` (via `execute`):**
    * Successful threshold update.
    * Revert on attempt to set threshold to 0.
    * Revert on attempt to set threshold > current signer count.
    * Correct event emission (`ThresholdUpdated`, `ExecutionSuccess`).
* **`updateSigners` (via `execute`):**
    * Successful signer set replacement (add, remove, replace).
    * Revert on attempt to set empty signer array.
    * Revert on attempt to set zero address as a signer.
    * Revert on attempt to set duplicate signers in the new set.
    * Revert if the update makes the current threshold impossible (threshold > new signer count).
    * Correct state updates (`isSigner` map, `signers` array, `signerCount`).
    * Correct event emission (`SignersUpdated`, `ExecutionSuccess`).
* **Nonce:** Ensure nonce increments exactly once per successful `execute` call (whether internal or external call succeeds/fails) and does not increment on revert.
* **Ether Handling:** Test direct Ether transfer to the contract via `receive()`.

## Dependencies

* [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts): Uses `ECDSA.sol` for signature recovery and `EIP712.sol` for EIP-712 hashing support.

