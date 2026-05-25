// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IRecoveryManager
 *
 * @notice Per-many-accounts wrapper around the EIP-7947 recovery interfaces.
 * Every function takes an explicit `account` argument because a single
 * JustaRecoveryManager singleton serves all JustanAccount instances.
 *
 * Recovery is a two-step time-locked flow:
 *   1. `initiateRecovery` verifies the proof via the registered provider and queues a
 *      `PendingRecovery` with `executeAt = block.timestamp + recoveryDelay(account)`.
 *   2. After the delay elapses, anyone may call `executeRecovery` to apply the new owner.
 * During the delay window the account itself may call `cancelRecovery` to abort.
 *
 * @author JustaLab
 */
interface IRecoveryManager {

    ////////////////////////////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Thrown when the provider address is zero.
     */
    error JustaRecoveryManager_ZeroProvider();

    /**
     * @notice Thrown when attempting to add a provider that is already registered for the account.
     * @param account The smart account.
     * @param provider The recovery provider address.
     */
    error JustaRecoveryManager_ProviderAlreadyAdded(address account, address provider);

    /**
     * @notice Thrown when the provider is not registered for the account.
     * @param account The smart account.
     * @param provider The recovery provider address.
     */
    error JustaRecoveryManager_ProviderNotRegistered(address account, address provider);

    /**
     * @notice Thrown when the caller is not the account named in the call.
     * @param caller The actual caller.
     * @param account The expected account.
     */
    error JustaRecoveryManager_NotAccount(address caller, address account);

    /**
     * @notice Thrown when `setRecoveryDelay` is called with a value outside the allowed bounds.
     * @param requested The requested delay value in seconds.
     * @param min The minimum allowed delay in seconds.
     * @param max The maximum allowed delay in seconds.
     */
    error JustaRecoveryManager_DelayOutOfBounds(uint256 requested, uint256 min, uint256 max);

    /**
     * @notice Thrown when `initiateRecovery` is called for an account that has never set its delay.
     * @param account The smart account.
     */
    error JustaRecoveryManager_DelayNotSet(address account);

    /**
     * @notice Thrown when a recovery id does not correspond to a pending recovery.
     * @param recoveryId The recovery id.
     */
    error JustaRecoveryManager_RecoveryNotPending(bytes32 recoveryId);

    /**
     * @notice Thrown when `executeRecovery` is called before the recovery's `executeAt` timestamp.
     * @param recoveryId The recovery id.
     * @param executeAt The timestamp at which the recovery becomes executable.
     */
    error JustaRecoveryManager_RecoveryNotReady(bytes32 recoveryId, uint64 executeAt);

    ////////////////////////////////////////////////////////////////////////
    // EVENTS
    ////////////////////////////////////////////////////////////////////////

    event RecoveryProviderAdded(address indexed account, address indexed provider);
    event RecoveryProviderRemoved(address indexed account, address indexed provider);
    event RecoveryInitiated(
        address indexed account, bytes32 indexed recoveryId, address indexed provider, bytes subject, uint64 executeAt
    );
    event RecoveryExecuted(
        address indexed account, bytes32 indexed recoveryId, address indexed provider, bytes subject
    );
    event RecoveryCancelled(address indexed account, bytes32 indexed recoveryId);
    event RecoveryDelayChanged(address indexed account, uint256 oldDelay, uint256 newDelay);

    ////////////////////////////////////////////////////////////////////////
    // ADMIN FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Register a recovery provider for an account.
     * @dev Callable only by the account itself (msg.sender == account). The account is expected to
     *      route this call through its ERC-7821 execute path so that its normal owner check
     *      authorizes the operation. The provider receives a subscribe call with msg.sender = manager
     *      and the account passed explicitly.
     * @param account The smart account registering the provider.
     * @param provider The recovery provider address.
     * @param data Provider-specific commitment data (forwarded to provider.subscribe).
     */
    function addRecoveryProvider(address account, address provider, bytes calldata data) external payable;

    /**
     * @notice Unregister a recovery provider for an account.
     * @dev Callable only by the account itself (msg.sender == account). The provider receives an
     *      unsubscribe call with msg.sender = manager and the account passed explicitly.
     * @param account The smart account unregistering the provider.
     * @param provider The recovery provider address.
     */
    function removeRecoveryProvider(address account, address provider) external payable;

    /**
     * @notice Set the per-account recovery delay.
     * @dev Callable only by the account itself (msg.sender == account). Takes effect immediately
     *      in both directions; pending recoveries already queued keep their original `executeAt`.
     *      `delaySeconds` must lie within `[MIN_RECOVERY_DELAY, MAX_RECOVERY_DELAY]`.
     *      There is no on-chain default — the UI is responsible for picking a value at opt-in.
     *      Until this is called, `initiateRecovery` reverts with `JustaRecoveryManager_DelayNotSet`.
     * @param account The smart account.
     * @param delaySeconds The new delay in seconds.
     */
    function setRecoveryDelay(address account, uint256 delaySeconds) external;

    ////////////////////////////////////////////////////////////////////////
    // EXECUTION FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Queue a recovery for an account by submitting a valid proof to a registered provider.
     * @dev Unrestricted caller; the proof carries authorization. Verifies the proof via the
     *      provider, then stores a `PendingRecovery` whose `executeAt` is the current
     *      `block.timestamp` plus the account's configured delay. Reverts with `DelayNotSet` if the
     *      account has never set its delay.
     * @param account The smart account to recover.
     * @param subject ABI-encoded WebAuthn public key (bytes32 x, bytes32 y) of the new owner.
     * @param provider The recovery provider whose proof is being submitted.
     * @param proof Provider-specific recovery proof.
     * @return recoveryId A deterministic id for the queued recovery.
     */
    function initiateRecovery(
        address account,
        bytes calldata subject,
        address provider,
        bytes calldata proof
    )
        external
        returns (bytes32 recoveryId);

    /**
     * @notice Finalize a queued recovery whose delay has elapsed.
     * @dev Unrestricted caller. Decodes `subject` as `abi.encode(bytes32 x, bytes32 y)` and calls
     *      `addOwnerPublicKey(x, y)` on the account. Reverts if the recovery is not pending or its
     *      `executeAt` has not yet been reached.
     * @param recoveryId The id returned from `initiateRecovery`.
     */
    function executeRecovery(bytes32 recoveryId) external;

    /**
     * @notice Cancel a queued recovery before it executes.
     * @dev Callable only by the account that the recovery is for (msg.sender == pending.account).
     *      The account authorizes this through its execute path, so any current owner can veto a
     *      malicious recovery during the delay window.
     * @param recoveryId The id of the pending recovery to cancel.
     */
    function cancelRecovery(bytes32 recoveryId) external;

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Check whether a provider is registered for an account.
     * @param account The smart account.
     * @param provider The recovery provider.
     * @return True if the provider is registered for the account.
     */
    function recoveryProviderAdded(address account, address provider) external view returns (bool);

    /**
     * @notice Get the list of recovery providers registered for an account.
     * @param account The smart account.
     * @return The list of provider addresses.
     */
    function getRecoveryProviders(address account) external view returns (address[] memory);

    /**
     * @notice Read the account's configured recovery delay in seconds.
     * @dev Returns `0` if the account has never called `setRecoveryDelay`. There is no on-chain
     *      default — callers should treat `0` as "delay not configured."
     * @param account The smart account.
     * @return The configured delay in seconds, or 0 if unset.
     */
    function recoveryDelay(address account) external view returns (uint256);

    /**
     * @notice Read the details of a pending recovery.
     * @dev Returns zero / empty values if `recoveryId` is not a currently pending recovery.
     * @param recoveryId The recovery id.
     * @return account The smart account being recovered.
     * @return provider The provider whose proof initiated this recovery.
     * @return executeAt The timestamp at which the recovery becomes executable.
     * @return subject The new-owner payload (ABI-encoded WebAuthn key).
     */
    function pendingRecovery(bytes32 recoveryId)
        external
        view
        returns (address account, address provider, uint64 executeAt, bytes memory subject);

}
