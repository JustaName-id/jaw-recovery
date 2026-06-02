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
 *   1. `initiateRecovery` verifies proofs from the account's threshold of registered providers and
 *      queues a `PendingRecovery` with `executeAt = block.timestamp + recoveryDelay(account)`.
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
     * @notice Thrown when `providers.length != proofs.length` in `initiateRecovery`.
     */
    error JustaRecoveryManager_LengthMismatch(uint256 providersLength, uint256 proofsLength);

    /**
     * @notice Thrown when the number of submitted proofs does not equal the account's threshold.
     */
    error JustaRecoveryManager_InvalidProofCount(uint256 submitted, uint256 required);

    /**
     * @notice Thrown when the same provider appears more than once in `initiateRecovery`.
     */
    error JustaRecoveryManager_DuplicateProvider(address provider);

    /**
     * @notice Thrown when `subject` is not 32 bytes (EOA owner) or 64 bytes (passkey owner).
     */
    error JustaRecoveryManager_InvalidSubjectLength(uint256 length);

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

    /**
     * @notice Thrown when a threshold is outside `[1, providerCount]`.
     * @param requested The requested threshold.
     * @param providerCount The account's current number of registered providers.
     */
    error JustaRecoveryManager_InvalidThreshold(uint256 requested, uint256 providerCount);

    /**
     * @notice Thrown when removing a provider would drop the count below the account's threshold.
     * @param newCount The provider count that would remain after removal.
     * @param threshold The account's current effective threshold.
     */
    error JustaRecoveryManager_RemovalBelowThreshold(uint256 newCount, uint256 threshold);

    ////////////////////////////////////////////////////////////////////////
    // EVENTS
    ////////////////////////////////////////////////////////////////////////

    event RecoveryProviderAdded(address indexed account, address indexed provider);
    event RecoveryProviderRemoved(address indexed account, address indexed provider);
    event RecoveryInitiated(
        address indexed account, bytes32 indexed recoveryId, address[] providers, bytes subject, uint64 executeAt
    );
    event RecoveryExecuted(address indexed account, bytes32 indexed recoveryId, bytes subject);
    event RecoveryCancelled(address indexed account, bytes32 indexed recoveryId);
    event RecoveryDelayChanged(address indexed account, uint256 oldDelay, uint256 newDelay);
    event RecoveryThresholdChanged(address indexed account, uint256 oldThreshold, uint256 newThreshold);

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
     *      `delaySeconds` must lie within `[0, MAX_RECOVERY_DELAY]`. A 24h default applies until
     *      this is explicitly called.
     * @param account The smart account.
     * @param delaySeconds The new delay in seconds.
     */
    function setRecoveryDelay(address account, uint256 delaySeconds) external;

    /**
     * @notice Set the per-account approval threshold (how many providers must approve a recovery).
     * @dev Callable only by the account. Must be within `[1, getRecoveryProviders(account).length]`.
     * @param account The smart account.
     * @param threshold The number of distinct providers required to approve a recovery.
     */
    function setRecoveryThreshold(address account, uint256 threshold) external;

    ////////////////////////////////////////////////////////////////////////
    // EXECUTION FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Queue a recovery once enough providers have approved the same new owner.
     * @dev Unrestricted caller; the proofs carry authorization. Requires exactly
     *      `recoveryThreshold(account)` distinct, registered providers, each verifying a proof over the
     *      same `subject`. `subject` must be a 32-byte EOA owner or a 64-byte passkey owner.
     * @param account The smart account to recover.
     * @param subject ABI-encoded new owner: `abi.encode(address)` (32B) or `abi.encode(bytes32 x, bytes32 y)` (64B).
     * @param providers The registered providers approving this recovery (length must equal the threshold).
     * @param proofs Provider-specific proofs, index-aligned with `providers`.
     * @return recoveryId A deterministic id for the queued recovery.
     */
    function initiateRecovery(
        address account,
        bytes calldata subject,
        address[] calldata providers,
        bytes[] calldata proofs
    )
        external
        returns (bytes32 recoveryId);

    /**
     * @notice Finalize a queued recovery whose delay has elapsed.
     * @dev Unrestricted caller. Registers the new owner from `subject` — a 64-byte passkey via
     *      `addOwnerPublicKey`, or a 32-byte EOA via `addOwnerAddress`. Reverts if the recovery is not
     *      pending or its `executeAt` has not yet been reached.
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
     * @notice Read the account's effective recovery delay in seconds.
     * @dev Returns `DEFAULT_RECOVERY_DELAY` (24h) until the account explicitly sets a delay; thereafter
     *      returns the configured value (which may be 0 = instant).
     * @param account The smart account.
     * @return The effective delay in seconds.
     */
    function recoveryDelay(address account) external view returns (uint256);

    /**
     * @notice Read the account's effective approval threshold (1 if never set).
     * @param account The smart account.
     * @return The number of distinct providers required to approve a recovery.
     */
    function recoveryThreshold(address account) external view returns (uint256);

    /**
     * @notice Read the details of a pending recovery.
     * @dev Returns zero / empty values if `recoveryId` is not a currently pending recovery.
     * @param recoveryId The recovery id.
     * @return account The smart account being recovered.
     * @return executeAt The timestamp at which the recovery becomes executable.
     * @return subject The new-owner payload.
     */
    function pendingRecovery(bytes32 recoveryId)
        external
        view
        returns (address account, uint64 executeAt, bytes memory subject);

}
