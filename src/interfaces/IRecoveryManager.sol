// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IRecoveryManager
 *
 * @notice Per-many-accounts recovery coordinator. A single JustaRecoveryManager singleton serves all
 * JustanAccount instances, so every function takes an explicit `account`.
 *
 * The unit of recovery is a "slot": a `(provider, commitment)` pair. The same provider may back several
 * slots for one account (e.g. two ECDSA EOAs, or two committed emails). The manager owns the slots, the
 * per-account replay nonce, the approval threshold, and the time-lock delay; providers are stateless
 * verifiers (see {IJustaRecoveryProvider}).
 *
 * Recovery is a two-step time-locked flow:
 *   1. `initiateRecovery` verifies one proof per slot for the account's threshold of distinct slots, then
 *      queues a `PendingRecovery` with `executeAt = block.timestamp + recoveryDelay(account)`.
 *   2. After the delay elapses, anyone may call `executeRecovery` to register the new owner.
 * During the delay window the account itself may call `cancelRecovery` to abort.
 *
 * @author JustaLab
 */
interface IRecoveryManager {

    ////////////////////////////////////////////////////////////////////////
    // TYPES
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice A registered recovery slot: a provider paired with a commitment it verifies against.
     */
    struct RecoverySlot {
        address provider;
        bytes commitment;
    }

    /**
     * @notice One slot's approval submitted to `initiateRecovery`.
     * @dev `provider` + `commitment` must identify a registered slot; `proof` is verified by that provider.
     */
    struct Approval {
        address provider;
        bytes commitment;
        bytes proof;
    }

    ////////////////////////////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Thrown when the provider address is zero.
     */
    error JustaRecoveryManager_ZeroProvider();

    /**
     * @notice Thrown when the commitment is empty.
     */
    error JustaRecoveryManager_EmptyCommitment();

    /**
     * @notice Thrown when adding a slot that is already registered for the account.
     * @param account The smart account.
     * @param slotId The slot id (`keccak256(abi.encode(provider, commitment))`).
     */
    error JustaRecoveryManager_SlotAlreadyAdded(address account, bytes32 slotId);

    /**
     * @notice Thrown when the slot is not registered for the account.
     * @param account The smart account.
     * @param slotId The slot id.
     */
    error JustaRecoveryManager_SlotNotRegistered(address account, bytes32 slotId);

    /**
     * @notice Thrown when the same slot appears more than once in `initiateRecovery`.
     * @param slotId The duplicated slot id.
     */
    error JustaRecoveryManager_DuplicateSlot(bytes32 slotId);

    /**
     * @notice Thrown when the caller is not the account named in the call.
     * @param caller The actual caller.
     * @param account The expected account.
     */
    error JustaRecoveryManager_NotAccount(address caller, address account);

    /**
     * @notice Thrown when `setRecoveryDelay` is called with a value above the allowed maximum.
     * @param requested The requested delay in seconds.
     * @param min The minimum allowed delay in seconds (0).
     * @param max The maximum allowed delay in seconds.
     */
    error JustaRecoveryManager_DelayOutOfBounds(uint256 requested, uint256 min, uint256 max);

    /**
     * @notice Thrown when a threshold is outside `[1, slotCount]`.
     * @param requested The requested threshold.
     * @param slotCount The account's current number of registered slots.
     */
    error JustaRecoveryManager_InvalidThreshold(uint256 requested, uint256 slotCount);

    /**
     * @notice Thrown when removing a slot would drop the count below the account's threshold.
     * @param newCount The slot count that would remain after removal.
     * @param threshold The account's current effective threshold.
     */
    error JustaRecoveryManager_RemovalBelowThreshold(uint256 newCount, uint256 threshold);

    /**
     * @notice Thrown when the number of submitted approvals does not equal the account's threshold.
     * @param submitted The number of approvals submitted.
     * @param required The account's effective threshold.
     */
    error JustaRecoveryManager_InvalidApprovalCount(uint256 submitted, uint256 required);

    /**
     * @notice Thrown when `subject` is not 32 bytes (EOA owner) or 64 bytes (passkey owner).
     * @param length The length of the supplied subject.
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

    ////////////////////////////////////////////////////////////////////////
    // EVENTS
    ////////////////////////////////////////////////////////////////////////

    event RecoverySlotAdded(
        address indexed account, address indexed provider, bytes commitment, bytes32 indexed slotId
    );
    event RecoverySlotRemoved(
        address indexed account, address indexed provider, bytes commitment, bytes32 indexed slotId
    );
    event RecoveryThresholdChanged(address indexed account, uint256 oldThreshold, uint256 newThreshold);
    event RecoveryDelayChanged(address indexed account, uint256 oldDelay, uint256 newDelay);
    event RecoveryInitiated(address indexed account, bytes32 indexed recoveryId, bytes subject, uint64 executeAt);
    event RecoveryExecuted(address indexed account, bytes32 indexed recoveryId, bytes subject);
    event RecoveryCancelled(address indexed account, bytes32 indexed recoveryId);

    ////////////////////////////////////////////////////////////////////////
    // SLOT ADMIN
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Register a recovery slot for an account.
     * @dev Callable only by the account. The same `provider` may be registered with different
     *      `commitment`s. Reverts if the `(provider, commitment)` slot already exists.
     * @param account The smart account.
     * @param provider The recovery provider (a stateless verifier).
     * @param commitment Provider-specific commitment bytes (e.g. `abi.encode(eoa)`, an email hash).
     * @return slotId The registered slot's id (`keccak256(abi.encode(provider, commitment))`).
     */
    function addRecoverySlot(
        address account,
        address provider,
        bytes calldata commitment
    )
        external
        returns (bytes32 slotId);

    /**
     * @notice Unregister a recovery slot for an account.
     * @dev Callable only by the account. Rejected if it would drop the slot count below the threshold,
     *      unless it removes the last slot (a full opt-out to zero).
     * @param account The smart account.
     * @param provider The slot's provider.
     * @param commitment The slot's commitment.
     */
    function removeRecoverySlot(address account, address provider, bytes calldata commitment) external;

    /**
     * @notice Set the per-account approval threshold (how many slots must approve a recovery).
     * @dev Callable only by the account. Must be within `[1, recoverySlotCount(account)]`.
     * @param account The smart account.
     * @param threshold The number of distinct slots required to approve a recovery.
     */
    function setRecoveryThreshold(address account, uint256 threshold) external;

    /**
     * @notice Set the per-account recovery delay.
     * @dev Callable only by the account. No minimum — `0` means instant. Reverts above
     *      `MAX_RECOVERY_DELAY`. A 24h default applies until this is explicitly called. Pending
     *      recoveries keep their original `executeAt`.
     * @param account The smart account.
     * @param delaySeconds The new delay in seconds (`0` = instant).
     */
    function setRecoveryDelay(address account, uint256 delaySeconds) external;

    ////////////////////////////////////////////////////////////////////////
    // EXECUTION
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Queue a recovery once the threshold of distinct slots have approved the same new owner.
     * @dev Unrestricted caller; the proofs carry authorization. Requires exactly
     *      `recoveryThreshold(account)` distinct, registered slots, each verifying a proof over the same
     *      `subject` and the account's current `recoveryNonce`. `subject` must be a 32-byte EOA owner or
     *      a 64-byte passkey owner. The nonce is bumped on success, making the proofs single-use.
     * @param account The smart account to recover.
     * @param subject ABI-encoded new owner: `abi.encode(address)` (32B) or `abi.encode(bytes32 x, bytes32 y)` (64B).
     * @param approvals One approval per required slot: the `(provider, commitment)` slot plus its proof.
     * @return recoveryId A deterministic id for the queued recovery.
     */
    function initiateRecovery(
        address account,
        bytes calldata subject,
        Approval[] calldata approvals
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
     * @param recoveryId The id of the pending recovery to cancel.
     */
    function cancelRecovery(bytes32 recoveryId) external;

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice The deterministic id for a `(provider, commitment)` slot.
     * @return The slot id (`keccak256(abi.encode(provider, commitment))`).
     */
    function computeSlotId(address provider, bytes calldata commitment) external pure returns (bytes32);

    /**
     * @notice Whether a `(provider, commitment)` slot is registered for an account.
     */
    function hasRecoverySlot(address account, address provider, bytes calldata commitment) external view returns (bool);

    /**
     * @notice The recovery slots registered for an account.
     */
    function getRecoverySlots(address account) external view returns (RecoverySlot[] memory);

    /**
     * @notice The number of recovery slots registered for an account.
     */
    function recoverySlotCount(address account) external view returns (uint256);

    /**
     * @notice The account's effective approval threshold (1 if never set).
     */
    function recoveryThreshold(address account) external view returns (uint256);

    /**
     * @notice The account's effective recovery delay in seconds (the 24h default until explicitly set).
     */
    function recoveryDelay(address account) external view returns (uint256);

    /**
     * @notice The account's current recovery (replay) nonce. Bind this into proofs submitted to
     *         `initiateRecovery`; it increments on each successful initiation.
     */
    function recoveryNonce(address account) external view returns (uint256);

    /**
     * @notice The details of a pending recovery. Returns zero / empty values if not pending.
     * @return account The smart account being recovered.
     * @return executeAt The timestamp at which the recovery becomes executable.
     * @return subject The new-owner payload.
     */
    function pendingRecovery(bytes32 recoveryId)
        external
        view
        returns (address account, uint64 executeAt, bytes memory subject);

}
