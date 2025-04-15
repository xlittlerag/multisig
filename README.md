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

## Security Considerations

* **Replay Protection:** Crucially handled by the `nonce` incremented on each execution and inclusion in the EIP-712 signed hash. The EIP-712 domain separator further prevents cross-chain or cross-contract replays.
* **Signature Verification:** Relies on OpenZeppelin's battle-tested `ECDSA.recover` implementation. Adds new validations on top of the precompiled `ecrecover`.
* **Access Control:** Internal visibility of governance functions prevents direct external calls. All state changes require passing the `_verifySignatures` check within `execute`.
* **External Call Safety:** Uses low-level `call`. `execute` follows Check-Effect-Interaction pattern. Failures in external calls are logged via event but do not revert the multisig state change (nonce increment).

## Testing Coverage Areas

* **Deployment:**
    * Successful deployment with valid parameters (k > 0, k <= n).
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
    * Revert if duplicated valid signatures.
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
    * Successful signer set replacement.
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

