// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @notice Per-many-accounts wrapper around EIP-7947. Not a re-export of
/// IAccountRecovery — every function takes an explicit `account` argument
/// because a single manager serves all JustanAccount instances.
interface IRecoveryManager {
    // intentionally empty — function signatures in a follow-up session

    }
