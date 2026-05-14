// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @notice JAW recovery manager. Registered as an owner of each JustanAccount.
/// Holds the per-account registry of EIP-7947 recovery providers and, on a
/// successful proof, calls addOwnerPublicKey on the target account.
contract JustaRecoveryManager {
    // intentionally empty — architecture in a follow-up session

    }
