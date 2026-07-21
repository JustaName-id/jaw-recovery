// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IRecoveryManager
 *
 * @notice Per-many-accounts recovery coordinator. A single JustaRecoveryManager singleton serves all
 * JustanAccount instances, so every account-scoped function takes an explicit `account`.
 *
 * The unit of recovery is a "recovery": a `(provider, commitment)` pair plus a per-recovery time-lock
 * `delay`. The same provider may back several recoveries for one account (e.g. two ECDSA EOAs, or two
 * committed emails), each with its own delay. The manager owns the recoveries, the per-account replay
 * nonce, and the approval threshold; providers are stateless verifiers (see {IRecoveryProvider}).
 *
 * Recovery is a two-step time-locked flow built around a "recovery request":
 *   1. `requestRecovery` verifies one proof per recovery for the account's threshold of distinct
 *      recoveries, then queues a `RecoveryRequest` with `executeAt = block.timestamp + maxDelay`, where
 *      `maxDelay` is the largest delay among the approving recoveries (the request is only as fast as its
 *      most-cautious approving factor).
 *   2. After the delay elapses, anyone may call `executeRecoveryRequest` to register the new owner.
 * During the delay window the account itself may call `cancelRecoveryRequest` to abort.
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
     * @notice Thrown when the provider address has no contract code (e.g. an EOA or a typo). Checking at
     *         registration moves the failure here, while the account can still fix it, rather than to
     *         recovery time when the account is locked out.
     * @param provider The offending provider address.
     */
    error JustaRecoveryManager_ProviderNotContract(address provider);

    /**
     * @notice Thrown when the commitment is empty.
     */
    error JustaRecoveryManager_EmptyCommitment();

    /**
     * @notice Thrown when the recovery manager is not registered as an owner of `account`: either the
     *         account never opted in (never called `addOwnerAddress(address(manager))`), or it was later
     *         removed as an owner.
     * @param account The smart account.
     */
    error JustaRecoveryManager_ManagerNotAccountOwner(address account);

    /**
     * @notice Thrown when adding a recovery that is already registered for the account.
     * @param account The smart account.
     * @param recoveryId The recovery id (`keccak256(abi.encode(account, provider, commitment))`).
     */
    error JustaRecoveryManager_RecoveryAlreadyAdded(address account, bytes32 recoveryId);

    /**
     * @notice Thrown when the recovery is not registered for the account.
     * @param account The smart account.
     * @param recoveryId The recovery id.
     */
    error JustaRecoveryManager_RecoveryNotRegistered(address account, bytes32 recoveryId);

    /**
     * @notice Thrown when the same recovery appears more than once in `requestRecovery`.
     * @param recoveryId The duplicated recovery id.
     */
    error JustaRecoveryManager_DuplicateRecovery(bytes32 recoveryId);

    /**
     * @notice Thrown when the caller is not the account named in the call.
     * @param caller The actual caller.
     * @param account The expected account.
     */
    error JustaRecoveryManager_NotAccount(address caller, address account);

    /**
     * @notice Thrown when a threshold is outside `[1, recoveryCount]`.
     * @param requested The requested threshold.
     * @param recoveryCount The account's current number of registered recoveries.
     */
    error JustaRecoveryManager_InvalidThreshold(uint256 requested, uint256 recoveryCount);

    /**
     * @notice Thrown when removing a recovery would drop the count below the account's threshold.
     * @param newCount The recovery count that would remain after removal.
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
     * @notice Thrown when a 32-byte `subject` does not fit in an `address` (dirty upper bits). Validated
     *         at request so `executeRecoveryRequest`'s `abi.decode(subject, (address))` cannot revert
     *         after the delay has elapsed.
     * @param subject The offending subject.
     */
    error JustaRecoveryManager_InvalidSubject(bytes subject);

    /**
     * @notice Thrown when `subject` is already an owner of the account at request time. A best-effort
     *         fail-fast: the owner set can change during the delay, so this does not guarantee
     *         `executeRecoveryRequest` won't later revert with `MultiOwnable_AlreadyOwner`.
     * @param subject The new-owner payload that is already registered.
     */
    error JustaRecoveryManager_SubjectAlreadyOwner(bytes subject);

    /**
     * @notice Thrown when a request id does not correspond to a pending recovery request.
     * @param requestId The recovery request id.
     */
    error JustaRecoveryManager_RequestNotPending(bytes32 requestId);

    /**
     * @notice Thrown when `executeRecoveryRequest` is called before the request's `executeAt` timestamp.
     * @param requestId The recovery request id.
     * @param executeAt The timestamp at which the request becomes executable.
     */
    error JustaRecoveryManager_RequestNotReady(bytes32 requestId, uint64 executeAt);

    ////////////////////////////////////////////////////////////////////////
    // TYPES
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice A registered recovery: a provider paired with a commitment it verifies against, plus the
     *         time-lock delay applied when this recovery participates in a request.
     */
    struct Recovery {
        address provider;
        bytes commitment;
        uint32 delay;
    }

    /**
     * @notice One recovery's approval submitted to `requestRecovery`.
     * @dev `recoveryId` must identify a registered recovery for the account; the manager looks up its
     *      stored `(provider, commitment)` and verifies `proof` against them.
     */
    struct Approval {
        bytes32 recoveryId;
        bytes proof;
    }

    /**
     * @notice A queued recovery request awaiting execution.
     * @dev `account == address(0)` is the sentinel for "not present": a request is only written for an
     *      account that registered a recovery, and registration requires `msg.sender == account`, so
     *      `address(0)` can never be the subject of a request. The implementation packs `account`
     *      (20 bytes) and `executeAt` (8 bytes) into one storage slot.
     */
    struct RecoveryRequest {
        address account;
        uint64 executeAt;
        bytes subject;
    }

    ////////////////////////////////////////////////////////////////////////
    // EVENTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Events reference recoveries by `recoveryId` only. A `recoveryId` is `keccak256` of its
     *      `(account, provider, commitment)` and is not reversible on-chain; resolve it to a provider/commitment via
     *      `getRecoveries(account)` (current registrations). Callers that need the preimage of a removed
     *      recovery must retain it off-chain at `addRecovery` time.
     */
    event RecoveryAdded(address indexed account, uint32 delay, bytes32 indexed recoveryId);
    event RecoveryRemoved(address indexed account, bytes32 indexed recoveryId);
    event RecoveryThresholdChanged(address indexed account, uint256 oldThreshold, uint256 newThreshold);
    event RecoveryRequested(
        address indexed account, bytes32 indexed requestId, bytes32[] recoveryIds, bytes subject, uint64 executeAt
    );
    event RecoveryRequestExecuted(address indexed account, bytes32 indexed requestId, bytes subject);
    event RecoveryRequestCancelled(address indexed account, bytes32 indexed requestId);

    ////////////////////////////////////////////////////////////////////////
    // RECOVERY ADMIN
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Register a recovery for an account.
     * @dev Callable only by the account. The same `provider` may be registered with different
     *      `commitment`s. Reverts if the `(provider, commitment)` recovery already exists. To change a
     *      recovery's `delay`, remove it and add it again.
     * @param account The smart account.
     * @param provider The recovery provider (a stateless verifier); must be a contract.
     * @param commitment Provider-specific commitment bytes (e.g. `abi.encode(eoa)`, an email hash).
     * @param delay The per-recovery time-lock in seconds applied when this recovery approves a request
     *        (`0` = instant; no upper bound beyond the `uint32` type).
     * @return recoveryId The registered recovery's id (`keccak256(abi.encode(account, provider, commitment))`).
     */
    function addRecovery(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        external
        returns (bytes32 recoveryId);

    /**
     * @notice Unregister a recovery for an account.
     * @dev Callable only by the account. Rejected if it would drop the recovery count below the threshold,
     *      unless it removes the last recovery (a full opt-out to zero).
     * @param account The smart account.
     * @param recoveryId The recovery id to remove (`keccak256(abi.encode(account, provider, commitment))`).
     */
    function removeRecovery(address account, bytes32 recoveryId) external;

    /**
     * @notice Set the per-account approval threshold (how many recoveries must approve a request).
     * @dev Callable only by the account. Must be within `[1, recoveryCount(account)]`.
     * @param account The smart account.
     * @param threshold The number of distinct recoveries required to approve a request.
     */
    function setRecoveryThreshold(address account, uint256 threshold) external;

    ////////////////////////////////////////////////////////////////////////
    // EXECUTION
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Queue a recovery request once the threshold of distinct recoveries have approved the same
     *         new owner.
     * @dev Unrestricted caller; the proofs carry authorization. Requires exactly
     *      `recoveryThreshold(account)` distinct, registered recoveries, each verifying a proof over the
     *      same `subject` and the account's current `recoveryNonce`. `subject` must be a 32-byte EOA owner
     *      or a 64-byte passkey owner. The queued `executeAt` uses the largest delay among the approving
     *      recoveries. The nonce is bumped on success, making the proofs single-use.
     * @param account The smart account to recover.
     * @param subject ABI-encoded new owner: `abi.encode(address)` (32B) or `abi.encode(bytes32 x, bytes32 y)` (64B).
     * @param approvals One approval per required recovery: the recovery's id plus its proof.
     * @return requestId A deterministic id for the queued recovery request.
     */
    function requestRecovery(
        address account,
        bytes calldata subject,
        Approval[] calldata approvals
    )
        external
        returns (bytes32 requestId);

    /**
     * @notice Finalize a queued recovery request whose delay has elapsed.
     * @dev Unrestricted caller. Registers the new owner from `subject` — a 64-byte passkey via
     *      `addOwnerPublicKey`, or a 32-byte EOA via `addOwnerAddress`. Reverts if the request is not
     *      pending or its `executeAt` has not yet been reached.
     * @param requestId The id returned from `requestRecovery`.
     */
    function executeRecoveryRequest(bytes32 requestId) external;

    /**
     * @notice Cancel a queued recovery request before it executes.
     * @dev Callable only by the account that the request is for (msg.sender == request.account).
     * @param requestId The id of the pending recovery request to cancel.
     */
    function cancelRecoveryRequest(bytes32 requestId) external;

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice The deterministic id for an account's `(provider, commitment)` recovery.
     * @return The recovery id (`keccak256(abi.encode(account, provider, commitment))`).
     */
    function computeRecoveryId(
        address account,
        address provider,
        bytes calldata commitment
    )
        external
        pure
        returns (bytes32);

    /**
     * @notice Whether a recovery id is registered for an account.
     */
    function hasRecovery(address account, bytes32 recoveryId) external view returns (bool);

    /**
     * @notice The recoveries registered for an account.
     */
    function getRecoveries(address account) external view returns (Recovery[] memory);

    /**
     * @notice A single registered recovery by id.
     * @dev Returns a zeroed `Recovery` (`provider == address(0)`) if the id is not registered for the
     *      account; pair with `hasRecovery` when the distinction matters.
     * @param account The smart account.
     * @param recoveryId The recovery id.
     * @return The registered recovery (`provider`, `commitment`, `delay`).
     */
    function getRecovery(address account, bytes32 recoveryId) external view returns (Recovery memory);

    /**
     * @notice The number of recoveries registered for an account.
     */
    function recoveryCount(address account) external view returns (uint256);

    /**
     * @notice The account's effective approval threshold (1 if never set).
     */
    function recoveryThreshold(address account) external view returns (uint256);

    /**
     * @notice The account's current recovery (replay) nonce. Bind this into proofs submitted to
     *         `requestRecovery`; it increments on each successful request.
     */
    function recoveryNonce(address account) external view returns (uint256);

    /**
     * @notice The details of a pending recovery request (a zeroed `RecoveryRequest` if not pending).
     * @param requestId The recovery request id.
     * @return The pending request: `account`, `executeAt`, and the new-owner `subject`.
     */
    function recoveryRequest(bytes32 requestId) external view returns (RecoveryRequest memory);

}
