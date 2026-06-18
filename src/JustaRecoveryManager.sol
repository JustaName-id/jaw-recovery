// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { MultiOwnable } from "justanaccount/MultiOwnable.sol";

import { ReentrancyGuard } from "solady/utils/ReentrancyGuard.sol";

import { IRecoveryManager } from "./interfaces/IRecoveryManager.sol";
import { IRecoveryProvider } from "./interfaces/IRecoveryProvider.sol";

/**
 * @title JustaRecoveryManager
 *
 * @notice Recovery coordinator for JustanAccount. Registered as an owner of each opted-in account, it
 * holds the per-account registry of recoveries and orchestrates a two-step time-locked flow that, once a
 * threshold of recoveries approve and after a per-recovery delay, registers a new owner (WebAuthn passkey
 * or EOA) on the target account.
 *
 * @dev The unit of recovery is a "recovery": a `(provider, commitment)` pair plus a time-lock `delay`,
 *      keyed by `recoveryId = keccak256(abi.encode(provider, commitment))`. The same provider may back
 *      several recoveries for one account. The manager owns all state — recoveries & commitments, the
 *      approval threshold, the per-recovery delays, and the per-account replay nonce — and treats
 *      providers as stateless verifiers: on each approval it calls
 *      `provider.verify(account, subject, nonce, commitment, proof)`, which reverts on an invalid proof.
 *      Provider trust is therefore equivalent to provider correctness. Non-ownable, non-upgradeable,
 *      deployed once per chain at a deterministic address.
 *
 * @author JustaLab
 */
contract JustaRecoveryManager is IRecoveryManager, ReentrancyGuard {

    using EnumerableSet for EnumerableSet.Bytes32Set;

    ////////////////////////////////////////////////////////////////////////
    // STORAGE
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Per-account set of registered recovery ids (`keccak256(abi.encode(provider, commitment))`).
     */
    mapping(address account => EnumerableSet.Bytes32Set recoveryIds) internal _recoveryIds;

    /**
     * @notice Per-account recovery data, keyed by recovery id.
     */
    mapping(address account => mapping(bytes32 recoveryId => Recovery recovery)) internal _recoveries;

    /**
     * @notice Per-account approval threshold. `0` means "use the default of 1".
     */
    mapping(address account => uint256 threshold) internal _recoveryThreshold;

    /**
     * @notice Per-account replay nonce. Bound into every proof and bumped on each successful request,
     *         which makes proofs single-use. Also seeds the deterministic `requestId`.
     */
    mapping(address account => uint256 nonce) internal _recoveryNonce;

    /**
     * @notice Pending recovery requests keyed by `requestId`.
     */
    mapping(bytes32 requestId => RecoveryRequest request) internal _recoveryRequests;

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
     * @param delay The per-recovery time-lock in seconds (`0` = instant; bounded only by `uint32`).
     * @return recoveryId The registered recovery's id.
     */
    function addRecovery(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        external
        onlyAccount(account)
        returns (bytes32 recoveryId)
    {
        if (provider == address(0)) {
            revert JustaRecoveryManager_ZeroProvider();
        }
        if (provider.code.length == 0) {
            revert JustaRecoveryManager_ProviderNotContract(provider);
        }
        if (commitment.length == 0) {
            revert JustaRecoveryManager_EmptyCommitment();
        }

        recoveryId = _computeRecoveryId(provider, commitment);
        if (!_recoveryIds[account].add(recoveryId)) {
            revert JustaRecoveryManager_RecoveryAlreadyAdded(account, recoveryId);
        }

        _recoveries[account][recoveryId] = Recovery({ provider: provider, commitment: commitment, delay: delay });

        emit RecoveryAdded(account, delay, recoveryId);
    }

    /**
     * @notice Unregister a recovery for an account.
     * @dev Callable only by the account. Rejected if it would drop the recovery count below the threshold,
     *      unless it removes the last recovery (a full opt-out to zero).
     * @param account The smart account.
     * @param recoveryId The recovery id to remove.
     */
    function removeRecovery(address account, bytes32 recoveryId) external onlyAccount(account) {
        // Remove first, then validate the resulting count; a failed check reverts the whole tx and undoes
        // the removal, so reading the post-removal length directly is safe and avoids `length - 1` math.
        if (!_recoveryIds[account].remove(recoveryId)) {
            revert JustaRecoveryManager_RecoveryNotRegistered(account, recoveryId);
        }

        // Disallow dropping below the threshold (except a full opt-out to zero recoveries). The setter's
        // `threshold <= count` bound plus this check keep the invariant `count == 0 || count >= threshold`.
        uint256 newCount = _recoveryIds[account].length();
        if (newCount != 0 && newCount < _effectiveThreshold(account)) {
            revert JustaRecoveryManager_RemovalBelowThreshold(newCount, _effectiveThreshold(account));
        }

        delete _recoveries[account][recoveryId];

        emit RecoveryRemoved(account, recoveryId);
    }

    /**
     * @notice Set the per-account approval threshold.
     * @dev Callable only by the account. Must be within `[1, recoveryCount]` so a recovery is always
     *      achievable.
     * @param account The smart account.
     * @param threshold The number of distinct recoveries required to approve a request.
     */
    function setRecoveryThreshold(address account, uint256 threshold) external onlyAccount(account) {
        uint256 count = _recoveryIds[account].length();
        if (threshold < 1 || threshold > count) {
            revert JustaRecoveryManager_InvalidThreshold(threshold, count);
        }

        uint256 oldThreshold = _effectiveThreshold(account);
        _recoveryThreshold[account] = threshold;

        emit RecoveryThresholdChanged(account, oldThreshold, threshold);
    }

    ////////////////////////////////////////////////////////////////////////
    // EXECUTION
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Queue a recovery request once the threshold of distinct recoveries have approved the same
     *         new owner.
     * @dev Unrestricted caller; the proofs carry authorization. Requires exactly
     *      `recoveryThreshold(account)` distinct, registered recoveries, each verifying a proof over the
     *      same `subject` and the account's current `recoveryNonce`. `subject` must be a 32-byte EOA owner
     *      or a 64-byte passkey owner. `executeAt` uses the largest delay among the approving recoveries.
     *      The nonce is bumped on success, making the proofs single-use.
     * @param account The smart account to recover.
     * @param subject ABI-encoded new owner: `abi.encode(address)` (32B) or `abi.encode(bytes32 x, bytes32 y)` (64B).
     * @param approvals One approval per required recovery: the `(provider, commitment)` recovery plus its proof.
     * @return requestId A deterministic id for the queued recovery request.
     */
    function requestRecovery(
        address account,
        bytes calldata subject,
        Approval[] calldata approvals
    )
        external
        nonReentrant
        returns (bytes32 requestId)
    {
        uint256 required = _effectiveThreshold(account);
        if (approvals.length != required) {
            revert JustaRecoveryManager_InvalidApprovalCount(approvals.length, required);
        }

        if (subject.length != 32 && subject.length != 64) {
            revert JustaRecoveryManager_InvalidSubjectLength(subject.length);
        }

        uint256 nonce = _recoveryNonce[account];

        uint256 maxDelay;
        bytes32[] memory recoveryIds = new bytes32[](approvals.length);
        for (uint256 i = 0; i < approvals.length; ++i) {
            bytes32 recoveryId = approvals[i].recoveryId;

            // Must be a registered recovery for this account.
            if (!_recoveryIds[account].contains(recoveryId)) {
                revert JustaRecoveryManager_RecoveryNotRegistered(account, recoveryId);
            }

            // Must be distinct from every earlier approval.
            for (uint256 j = 0; j < i; ++j) {
                if (recoveryIds[j] == recoveryId) {
                    revert JustaRecoveryManager_DuplicateRecovery(recoveryId);
                }
            }
            recoveryIds[i] = recoveryId;

            // Load the registered recovery; its `(provider, commitment)` are trusted (set at add time and
            // proven registered above), so verification cannot be steered by caller-supplied data.
            Recovery storage recovery = _recoveries[account][recoveryId];

            // The queued delay is the largest among the approving recoveries.
            if (recovery.delay > maxDelay) {
                maxDelay = recovery.delay;
            }

            // Delegate verification; the provider reverts on an invalid proof.
            IRecoveryProvider(recovery.provider)
                .verify(account, subject, nonce, recovery.commitment, approvals[i].proof);
        }

        requestId = keccak256(abi.encode(account, subject, nonce));
        _recoveryNonce[account] = nonce + 1;

        // Safe: `block.timestamp` plus a `uint32` delay cannot exceed `uint64`.
        uint64 executeAt = uint64(block.timestamp + maxDelay);
        _recoveryRequests[requestId] = RecoveryRequest({ account: account, executeAt: executeAt, subject: subject });

        emit RecoveryRequested(account, requestId, recoveryIds, subject, executeAt);
    }

    /**
     * @notice Finalize a queued recovery request whose delay has elapsed.
     * @dev Unrestricted caller. Registers the new owner from `subject` — a 64-byte passkey via
     *      `addOwnerPublicKey`, or a 32-byte EOA via `addOwnerAddress`. Requires the manager to be a
     *      registered owner of the account (set during opt-in). The pending entry is deleted before the
     *      external call (CEI); a reverting owner-add rolls the delete back, so the request stays
     *      executable rather than being lost.
     * @param requestId The id returned from `requestRecovery`.
     */
    function executeRecoveryRequest(bytes32 requestId) external nonReentrant {
        RecoveryRequest storage request = _recoveryRequests[requestId];

        // Confirm the request exists.
        if (request.account == address(0)) {
            revert JustaRecoveryManager_RequestNotPending(requestId);
        }

        // Confirm the delay has elapsed.
        if (block.timestamp < request.executeAt) {
            revert JustaRecoveryManager_RequestNotReady(requestId, request.executeAt);
        }

        // Snapshot fields to memory before deletion.
        address account = request.account;
        bytes memory subject = request.subject;

        // Delete the pending entry first (CEI).
        delete _recoveryRequests[requestId];

        // Register the new owner. `subject` length selects the owner type (validated at request):
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

        emit RecoveryRequestExecuted(account, requestId, subject);
    }

    /**
     * @notice Cancel a queued recovery request before it executes.
     * @dev Callable only by the account named in the request (msg.sender == request.account).
     * @param requestId The id of the pending recovery request to cancel.
     */
    function cancelRecoveryRequest(bytes32 requestId) external {
        RecoveryRequest storage request = _recoveryRequests[requestId];

        // Confirm the request exists.
        if (request.account == address(0)) {
            revert JustaRecoveryManager_RequestNotPending(requestId);
        }

        // Only the account that the request is for may cancel it.
        if (msg.sender != request.account) {
            revert JustaRecoveryManager_NotAccount(msg.sender, request.account);
        }

        address account = request.account;
        delete _recoveryRequests[requestId];

        emit RecoveryRequestCancelled(account, requestId);
    }

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice The deterministic id for a `(provider, commitment)` recovery.
     */
    function computeRecoveryId(address provider, bytes calldata commitment) external pure returns (bytes32) {
        return _computeRecoveryId(provider, commitment);
    }

    /**
     * @notice Whether a recovery id is registered for an account.
     */
    function hasRecovery(address account, bytes32 recoveryId) external view returns (bool) {
        return _recoveryIds[account].contains(recoveryId);
    }

    /**
     * @notice The recoveries registered for an account.
     */
    function getRecoveries(address account) external view returns (Recovery[] memory recoveries) {
        bytes32[] memory ids = _recoveryIds[account].values();
        recoveries = new Recovery[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            recoveries[i] = _recoveries[account][ids[i]];
        }
    }

    /**
     * @notice A single registered recovery by id.
     * @dev Returns a zeroed `Recovery` (`provider == address(0)`) if the id is not registered for the
     *      account; pair with `hasRecovery` when the distinction matters.
     */
    function getRecovery(address account, bytes32 recoveryId) external view returns (Recovery memory) {
        return _recoveries[account][recoveryId];
    }

    /**
     * @notice The number of recoveries registered for an account.
     */
    function recoveryCount(address account) external view returns (uint256) {
        return _recoveryIds[account].length();
    }

    /**
     * @notice The account's effective approval threshold (1 if never set).
     */
    function recoveryThreshold(address account) external view returns (uint256) {
        return _effectiveThreshold(account);
    }

    /**
     * @notice The account's current recovery (replay) nonce.
     */
    function recoveryNonce(address account) external view returns (uint256) {
        return _recoveryNonce[account];
    }

    /**
     * @notice The details of a pending recovery request (a zeroed `RecoveryRequest` if not pending).
     * @param requestId The recovery request id.
     * @return The pending request: `account`, `executeAt`, and the new-owner `subject`.
     */
    function recoveryRequest(bytes32 requestId) external view returns (RecoveryRequest memory) {
        return _recoveryRequests[requestId];
    }

    ////////////////////////////////////////////////////////////////////////
    // INTERNAL HELPERS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Effective approval threshold for an account (`0` stored => default `1`).
     */
    function _effectiveThreshold(address account) internal view returns (uint256) {
        uint256 threshold = _recoveryThreshold[account];
        return threshold == 0 ? 1 : threshold;
    }

    /**
     * @dev Deterministic id for a `(provider, commitment)` recovery.
     */
    function _computeRecoveryId(address provider, bytes calldata commitment) internal pure returns (bytes32) {
        return keccak256(abi.encode(provider, commitment));
    }

}
