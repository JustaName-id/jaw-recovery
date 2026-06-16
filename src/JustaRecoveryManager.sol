// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { MultiOwnable } from "justanaccount/MultiOwnable.sol";

import { ReentrancyGuard } from "solady/utils/ReentrancyGuard.sol";

import { IJustaRecoveryProvider } from "./interfaces/IJustaRecoveryProvider.sol";
import { IRecoveryManager } from "./interfaces/IRecoveryManager.sol";

/**
 * @title JustaRecoveryManager
 *
 * @notice Recovery coordinator for JustanAccount. Registered as an owner of each opted-in account, it
 * holds the per-account registry of recovery slots and orchestrates a two-step time-locked recovery flow
 * that, once a threshold of slots approve and after a configurable delay, registers a new owner (WebAuthn
 * passkey or EOA) on the target account.
 *
 * @dev The unit of recovery is a "slot": a `(provider, commitment)` pair, keyed by
 *      `keccak256(abi.encode(provider, commitment))`. The same provider may back several slots for one
 *      account. The manager owns all state — slots & commitments, the approval threshold, the time-lock
 *      delay, and the per-account replay nonce — and treats providers as stateless verifiers: on each
 *      slot it calls `provider.verify(account, subject, nonce, commitment, proof)`, which reverts on an
 *      invalid proof. Provider trust is therefore equivalent to provider correctness. Non-ownable,
 *      non-upgradeable, deployed once per chain at a deterministic address.
 *
 * @author JustaLab
 */
contract JustaRecoveryManager is IRecoveryManager, ReentrancyGuard {

    using EnumerableSet for EnumerableSet.Bytes32Set;

    ////////////////////////////////////////////////////////////////////////
    // STRUCTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Per-account recovery configuration and replay nonce, packed into a single storage slot.
     * @dev `uint64` is ample for every field: `delay` is bounded by `MAX_RECOVERY_DELAY`, and
     *      `threshold`/`nonce` each grow by at most one per transaction. Sentinels: `threshold == 0`
     *      means "use the default of 1"; `delayConfigured == false` means `DEFAULT_RECOVERY_DELAY`
     *      applies (once configured, the stored `delay` applies, including 0 = instant).
     */
    struct AccountConfig {
        uint64 delay;
        bool delayConfigured;
        uint64 threshold;
        uint64 nonce;
    }

    /**
     * @notice A queued recovery awaiting execution.
     * @dev `account == address(0)` is the sentinel for "not present."
     */
    struct PendingRecovery {
        address account;
        uint64 executeAt;
        bytes subject;
    }

    ////////////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice The default per-account recovery delay, applied until an account overrides it.
     */
    uint256 public constant DEFAULT_RECOVERY_DELAY = 24 hours;

    /**
     * @notice The maximum allowed value for the per-account recovery delay.
     */
    uint256 public constant MAX_RECOVERY_DELAY = 30 days;

    ////////////////////////////////////////////////////////////////////////
    // STORAGE
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Per-account set of registered slot ids (`keccak256(abi.encode(provider, commitment))`).
     */
    mapping(address account => EnumerableSet.Bytes32Set slotIds) internal _slotIds;

    /**
     * @notice Per-account slot data, keyed by slot id.
     */
    mapping(address account => mapping(bytes32 slotId => RecoverySlot slot)) internal _slots;

    /**
     * @notice Per-account configuration (delay override + approval threshold) and replay nonce. The
     *         nonce is bound into every proof and bumped on each successful initiation, which makes
     *         proofs single-use; it also seeds the deterministic `recoveryId`.
     */
    mapping(address account => AccountConfig config) internal _config;

    /**
     * @notice Pending recoveries keyed by `recoveryId`.
     */
    mapping(bytes32 recoveryId => PendingRecovery) internal _pendingRecoveries;

    ////////////////////////////////////////////////////////////////////////
    // MODIFIERS
    ////////////////////////////////////////////////////////////////////////

    modifier onlyAccount(address account) {
        if (msg.sender != account) {
            revert JustaRecoveryManager_NotAccount(msg.sender, account);
        }
        _;
    }

    ////////////////////////////////////////////////////////////////////////
    // INTERNAL HELPERS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Effective approval threshold for an account (`0` stored => default `1`).
     */
    function _effectiveThreshold(address account) internal view returns (uint256) {
        uint256 threshold = _config[account].threshold;
        return threshold == 0 ? 1 : threshold;
    }

    /**
     * @dev Effective recovery delay: the stored value if the account configured one, else the default.
     */
    function _effectiveDelay(address account) internal view returns (uint256) {
        AccountConfig storage config = _config[account];
        return config.delayConfigured ? config.delay : DEFAULT_RECOVERY_DELAY;
    }

    /**
     * @dev Deterministic id for a `(provider, commitment)` slot.
     */
    function _computeSlotId(address provider, bytes calldata commitment) internal pure returns (bytes32) {
        return keccak256(abi.encode(provider, commitment));
    }

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
     * @return slotId The registered slot's id.
     */
    function addRecoverySlot(
        address account,
        address provider,
        bytes calldata commitment
    )
        external
        onlyAccount(account)
        returns (bytes32 slotId)
    {
        if (provider == address(0)) {
            revert JustaRecoveryManager_ZeroProvider();
        }
        if (commitment.length == 0) {
            revert JustaRecoveryManager_EmptyCommitment();
        }

        slotId = _computeSlotId(provider, commitment);
        if (!_slotIds[account].add(slotId)) {
            revert JustaRecoveryManager_SlotAlreadyAdded(account, slotId);
        }

        _slots[account][slotId] = RecoverySlot({ provider: provider, commitment: commitment });

        emit RecoverySlotAdded(account, provider, commitment, slotId);
    }

    /**
     * @notice Unregister a recovery slot for an account.
     * @dev Callable only by the account. Rejected if it would drop the slot count below the threshold,
     *      unless it removes the last slot (a full opt-out to zero).
     * @param account The smart account.
     * @param provider The slot's provider.
     * @param commitment The slot's commitment.
     */
    function removeRecoverySlot(
        address account,
        address provider,
        bytes calldata commitment
    )
        external
        onlyAccount(account)
    {
        bytes32 slotId = _computeSlotId(provider, commitment);
        if (!_slotIds[account].remove(slotId)) {
            revert JustaRecoveryManager_SlotNotRegistered(account, slotId);
        }

        // Disallow dropping below the threshold (except a full opt-out to zero slots).
        uint256 newCount = _slotIds[account].length();
        if (newCount != 0 && newCount < _effectiveThreshold(account)) {
            revert JustaRecoveryManager_RemovalBelowThreshold(newCount, _effectiveThreshold(account));
        }

        delete _slots[account][slotId];

        emit RecoverySlotRemoved(account, provider, commitment, slotId);
    }

    /**
     * @notice Set the per-account approval threshold.
     * @dev Callable only by the account. Must be within `[1, slotCount]` so a recovery is always
     *      achievable.
     * @param account The smart account.
     * @param threshold The number of distinct slots required to approve a recovery.
     */
    function setRecoveryThreshold(address account, uint256 threshold) external onlyAccount(account) {
        uint256 slotCount = _slotIds[account].length();
        if (threshold < 1 || threshold > slotCount) {
            revert JustaRecoveryManager_InvalidThreshold(threshold, slotCount);
        }

        uint256 oldThreshold = _effectiveThreshold(account);
        // Cast is safe: `threshold <= slotCount`, and every slot costs a prior transaction to add,
        // so the count can never approach 2^64.
        _config[account].threshold = uint64(threshold);

        emit RecoveryThresholdChanged(account, oldThreshold, threshold);
    }

    /**
     * @notice Set the per-account recovery delay.
     * @dev Callable only by the account. No minimum — `0` is allowed and means instant. Reverts only if
     *      above `MAX_RECOVERY_DELAY`. Marks the account as having configured a delay. Pending recoveries
     *      keep their original `executeAt`.
     * @param account The smart account.
     * @param delaySeconds The new delay in seconds (`0` = instant).
     */
    function setRecoveryDelay(address account, uint256 delaySeconds) external onlyAccount(account) {
        if (delaySeconds > MAX_RECOVERY_DELAY) {
            revert JustaRecoveryManager_DelayOutOfBounds(delaySeconds, MAX_RECOVERY_DELAY);
        }

        uint256 oldDelay = _effectiveDelay(account);
        AccountConfig storage config = _config[account];
        config.delay = uint64(delaySeconds); // Cast is safe: bounded by `MAX_RECOVERY_DELAY` above.
        config.delayConfigured = true;

        emit RecoveryDelayChanged(account, oldDelay, delaySeconds);
    }

    ////////////////////////////////////////////////////////////////////////
    // EXECUTION
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Queue a recovery once the threshold of distinct slots have approved the same new owner.
     * @dev Unrestricted caller; the proofs carry authorization. Requires exactly
     *      `recoveryThreshold(account)` distinct, registered slots, each verifying a proof over the same
     *      `subject` and the account's current `recoveryNonce`. `subject` must be a 32-byte EOA owner or a
     *      64-byte passkey owner. The nonce is bumped on success, making the proofs single-use.
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
        nonReentrant
        returns (bytes32 recoveryId)
    {
        uint256 required = _effectiveThreshold(account);
        if (approvals.length != required) {
            revert JustaRecoveryManager_InvalidApprovalCount(approvals.length, required);
        }

        if (subject.length != 32 && subject.length != 64) {
            revert JustaRecoveryManager_InvalidSubjectLength(subject.length);
        }

        uint256 nonce = _config[account].nonce;

        bytes32[] memory seen = new bytes32[](approvals.length);
        for (uint256 i = 0; i < approvals.length; ++i) {
            Approval calldata approval = approvals[i];
            bytes32 slotId = _computeSlotId(approval.provider, approval.commitment);

            // Must be a registered slot for this account.
            if (!_slotIds[account].contains(slotId)) {
                revert JustaRecoveryManager_SlotNotRegistered(account, slotId);
            }

            // Must be distinct from every earlier approval.
            for (uint256 j = 0; j < i; ++j) {
                if (seen[j] == slotId) {
                    revert JustaRecoveryManager_DuplicateSlot(slotId);
                }
            }
            seen[i] = slotId;

            // Delegate verification; the provider reverts on an invalid proof. Membership above
            // guarantees `commitment` matches the registered slot, so the verified commitment is trusted.
            IJustaRecoveryProvider(approval.provider)
                .verify(account, subject, nonce, approval.commitment, approval.proof);
        }

        recoveryId = keccak256(abi.encode(account, subject, nonce));
        // Cast is safe: the nonce increments once per successful initiation.
        _config[account].nonce = uint64(nonce + 1);

        uint64 executeAt = uint64(block.timestamp + _effectiveDelay(account));
        _pendingRecoveries[recoveryId] = PendingRecovery({ account: account, executeAt: executeAt, subject: subject });

        emit RecoveryInitiated(account, recoveryId, seen, subject, executeAt);
    }

    /**
     * @notice Finalize a queued recovery whose delay has elapsed.
     * @dev Unrestricted caller. Registers the new owner from `subject` — a 64-byte passkey via
     *      `addOwnerPublicKey`, or a 32-byte EOA via `addOwnerAddress`. Requires the manager to be a
     *      registered owner of the account (set during opt-in). The pending entry is deleted before the
     *      external call (CEI).
     * @param recoveryId The id returned from `initiateRecovery`.
     */
    function executeRecovery(bytes32 recoveryId) external nonReentrant {
        PendingRecovery storage rec = _pendingRecoveries[recoveryId];

        // Confirm the recovery exists.
        if (rec.account == address(0)) {
            revert JustaRecoveryManager_RecoveryNotPending(recoveryId);
        }

        // Confirm the delay has elapsed.
        if (block.timestamp < rec.executeAt) {
            revert JustaRecoveryManager_RecoveryNotReady(recoveryId, rec.executeAt);
        }

        // Snapshot fields to memory before deletion.
        address account = rec.account;
        bytes memory subject = rec.subject;

        // Delete the pending entry first (CEI).
        delete _pendingRecoveries[recoveryId];

        // Register the new owner. `subject` length selects the owner type (validated at initiate):
        //   64 bytes => WebAuthn passkey (bytes32 x, bytes32 y); 32 bytes => EOA address.
        if (subject.length == 64) {
            (bytes32 x, bytes32 y) = abi.decode(subject, (bytes32, bytes32));
            MultiOwnable(account).addOwnerPublicKey(x, y);
        } else if (subject.length == 32) {
            address owner = abi.decode(subject, (address));
            MultiOwnable(account).addOwnerAddress(owner);
        } else {
            revert JustaRecoveryManager_InvalidSubjectLength(subject.length);
        }

        emit RecoveryExecuted(account, recoveryId, subject);
    }

    /**
     * @notice Cancel a queued recovery before it executes.
     * @dev Callable only by the account named in the pending recovery (msg.sender == pending.account).
     * @param recoveryId The id of the pending recovery to cancel.
     */
    function cancelRecovery(bytes32 recoveryId) external {
        PendingRecovery storage rec = _pendingRecoveries[recoveryId];

        // Confirm the recovery exists.
        if (rec.account == address(0)) {
            revert JustaRecoveryManager_RecoveryNotPending(recoveryId);
        }

        // Only the account that the recovery is for may cancel it.
        if (msg.sender != rec.account) {
            revert JustaRecoveryManager_NotAccount(msg.sender, rec.account);
        }

        address account = rec.account;
        delete _pendingRecoveries[recoveryId];

        emit RecoveryCancelled(account, recoveryId);
    }

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice The deterministic id for a `(provider, commitment)` slot.
     */
    function computeSlotId(address provider, bytes calldata commitment) external pure returns (bytes32) {
        return _computeSlotId(provider, commitment);
    }

    /**
     * @notice Whether a `(provider, commitment)` slot is registered for an account.
     */
    function hasRecoverySlot(address account, address provider, bytes calldata commitment)
        external
        view
        returns (bool)
    {
        return _slotIds[account].contains(_computeSlotId(provider, commitment));
    }

    /**
     * @notice The recovery slots registered for an account.
     */
    function getRecoverySlots(address account) external view returns (RecoverySlot[] memory slots) {
        bytes32[] memory ids = _slotIds[account].values();
        slots = new RecoverySlot[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            slots[i] = _slots[account][ids[i]];
        }
    }

    /**
     * @notice The number of recovery slots registered for an account.
     */
    function recoverySlotCount(address account) external view returns (uint256) {
        return _slotIds[account].length();
    }

    /**
     * @notice The account's effective approval threshold (1 if never set).
     */
    function recoveryThreshold(address account) external view returns (uint256) {
        return _effectiveThreshold(account);
    }

    /**
     * @notice The account's effective recovery delay in seconds (the 24h default until explicitly set).
     */
    function recoveryDelay(address account) external view returns (uint256) {
        return _effectiveDelay(account);
    }

    /**
     * @notice The account's current recovery (replay) nonce.
     */
    function recoveryNonce(address account) external view returns (uint256) {
        return _config[account].nonce;
    }

    /**
     * @notice The details of a pending recovery. Returns zero / empty values if not pending.
     * @param recoveryId The recovery id.
     * @return account The smart account being recovered.
     * @return executeAt The timestamp at which the recovery becomes executable.
     * @return subject The new-owner payload.
     */
    function pendingRecovery(bytes32 recoveryId)
        external
        view
        returns (address account, uint64 executeAt, bytes memory subject)
    {
        PendingRecovery storage rec = _pendingRecoveries[recoveryId];
        return (rec.account, rec.executeAt, rec.subject);
    }

}
