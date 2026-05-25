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
 * @notice Recovery coordinator for JustanAccount. Registered as an owner of each opted-in account,
 * it holds the per-account registry of recovery providers and orchestrates a two-step time-locked
 * recovery flow that, on a successful proof and after a configurable delay, registers a new
 * WebAuthn public-key owner on the target account.
 *
 * @dev The manager performs no cryptographic verification of its own. It dispatches to the provider
 *      the account opted into and trusts the provider's return value; provider trust is therefore
 *      equivalent to provider correctness. The delay is enforced purely at the manager level and is
 *      provider-agnostic. Non-ownable, non-upgradeable, deployed once per chain at a deterministic
 *      address.
 *
 * @author JustaLab
 */
contract JustaRecoveryManager is IRecoveryManager, ReentrancyGuard {

    using EnumerableSet for EnumerableSet.AddressSet;

    ////////////////////////////////////////////////////////////////////////
    // STRUCTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice A queued recovery awaiting execution.
     * @dev `account == address(0)` is the sentinel for "not present."
     */
    struct PendingRecovery {
        address account;
        address provider;
        uint64 executeAt;
        bytes subject;
    }

    ////////////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice The minimum allowed value for the per-account recovery delay.
     */
    uint256 public constant MIN_RECOVERY_DELAY = 24 hours;

    /**
     * @notice The maximum allowed value for the per-account recovery delay.
     */
    uint256 public constant MAX_RECOVERY_DELAY = 30 days;

    ////////////////////////////////////////////////////////////////////////
    // STORAGE
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Per-account set of registered recovery providers.
     */
    mapping(address account => EnumerableSet.AddressSet providers) internal _providers;

    /**
     * @notice Per-account recovery delay in seconds. `0` means "never set" — recovery is disabled
     *         for the account until `setRecoveryDelay` is called.
     */
    mapping(address account => uint256 delaySeconds) internal _recoveryDelay;

    /**
     * @notice Per-account monotonic counter used to derive deterministic `recoveryId`s.
     */
    mapping(address account => uint256 nonce) internal _recoveryNonce;

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
    function addRecoveryProvider(
        address account,
        address provider,
        bytes calldata data
    )
        external
        payable
        nonReentrant
        onlyAccount(account)
    {
        // Reject zero provider
        if (provider == address(0)) {
            revert JustaRecoveryManager_ZeroProvider();
        }

        // Add to the per-account set; EnumerableSet.add returns false on duplicate
        if (!_providers[account].add(provider)) {
            revert JustaRecoveryManager_ProviderAlreadyAdded(account, provider);
        }

        // Forward to the provider, attaching any value sent with the call
        IJustaRecoveryProvider(provider).subscribe{ value: msg.value }(account, data);

        emit RecoveryProviderAdded(account, provider);
    }

    /**
     * @notice Unregister a recovery provider for an account.
     * @dev Callable only by the account itself. The provider receives an unsubscribe call with
     *      msg.sender = manager and the account passed explicitly; the provider is expected to
     *      delete all data associated with the account.
     * @param account The smart account unregistering the provider.
     * @param provider The recovery provider address.
     */
    function removeRecoveryProvider(
        address account,
        address provider
    )
        external
        payable
        nonReentrant
        onlyAccount(account)
    {
        // Remove from the per-account set; EnumerableSet.remove returns false if not present
        if (!_providers[account].remove(provider)) {
            revert JustaRecoveryManager_ProviderNotRegistered(account, provider);
        }

        // Forward to the provider, attaching any value sent with the call
        IJustaRecoveryProvider(provider).unsubscribe{ value: msg.value }(account);

        emit RecoveryProviderRemoved(account, provider);
    }

    /**
     * @notice Set the per-account recovery delay.
     * @dev Callable only by the account itself. Takes effect immediately in both directions; any
     *      already-queued recovery keeps its original `executeAt`. Reverts if `delaySeconds` is
     *      outside `[MIN_RECOVERY_DELAY, MAX_RECOVERY_DELAY]`. There is no on-chain default — until
     *      this is called for an account, `initiateRecovery` will revert with `DelayNotSet`.
     * @param account The smart account.
     * @param delaySeconds The new delay in seconds.
     */
    function setRecoveryDelay(address account, uint256 delaySeconds) external onlyAccount(account) {
        // Validate bounds
        if (delaySeconds < MIN_RECOVERY_DELAY || delaySeconds > MAX_RECOVERY_DELAY) {
            revert JustaRecoveryManager_DelayOutOfBounds(delaySeconds, MIN_RECOVERY_DELAY, MAX_RECOVERY_DELAY);
        }

        // Capture previous value for the event, then write
        uint256 oldDelay = _recoveryDelay[account];
        _recoveryDelay[account] = delaySeconds;

        emit RecoveryDelayChanged(account, oldDelay, delaySeconds);
    }

    ////////////////////////////////////////////////////////////////////////
    // EXECUTION FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Queue a recovery for an account.
     * @dev Unrestricted caller; the proof carries authorization. Verifies the proof via the
     *      provider (which is expected to enforce its own replay protection), then stores a
     *      `PendingRecovery` whose `executeAt` is `block.timestamp + recoveryDelay(account)`.
     *      Reverts with `DelayNotSet` if the account has never configured its delay.
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
        nonReentrant
        returns (bytes32 recoveryId)
    {
        // Confirm the provider is registered for this account
        if (!_providers[account].contains(provider)) {
            revert JustaRecoveryManager_ProviderNotRegistered(account, provider);
        }

        // Require the account to have explicitly configured a delay
        uint256 delay = _recoveryDelay[account];
        if (delay == 0) {
            revert JustaRecoveryManager_DelayNotSet(account);
        }

        // Delegate proof verification to the provider; provider MUST revert on invalid proof
        IJustaRecoveryProvider(provider).recover(account, subject, proof);

        // Derive a deterministic recoveryId from the per-account nonce
        recoveryId = keccak256(abi.encode(account, provider, subject, _recoveryNonce[account]++));

        // Queue the recovery — executeAt is captured now and never recomputed
        uint64 executeAt = uint64(block.timestamp + delay);
        _pendingRecoveries[recoveryId] =
            PendingRecovery({ account: account, provider: provider, executeAt: executeAt, subject: subject });

        emit RecoveryInitiated(account, recoveryId, provider, subject, executeAt);
    }

    /**
     * @notice Finalize a queued recovery whose delay has elapsed.
     * @dev Unrestricted caller. Decodes `subject` and calls `addOwnerPublicKey(x, y)` on the
     *      account, which requires the manager to be a registered owner of the account (set during
     *      opt-in). The pending entry is deleted before the external call (CEI).
     * @param recoveryId The id returned from `initiateRecovery`.
     */
    function executeRecovery(bytes32 recoveryId) external nonReentrant {
        PendingRecovery storage rec = _pendingRecoveries[recoveryId];

        // Confirm the recovery exists
        if (rec.account == address(0)) {
            revert JustaRecoveryManager_RecoveryNotPending(recoveryId);
        }

        // Confirm the delay has elapsed
        if (block.timestamp < rec.executeAt) {
            revert JustaRecoveryManager_RecoveryNotReady(recoveryId, rec.executeAt);
        }

        // Snapshot fields to memory before deletion
        address account = rec.account;
        address provider = rec.provider;
        bytes memory subject = rec.subject;

        // Delete the pending entry first (CEI)
        delete _pendingRecoveries[recoveryId];

        // Decode the new WebAuthn public key from subject and register it as an owner
        (bytes32 x, bytes32 y) = abi.decode(subject, (bytes32, bytes32));
        MultiOwnable(account).addOwnerPublicKey(x, y);

        emit RecoveryExecuted(account, recoveryId, provider, subject);
    }

    /**
     * @notice Cancel a queued recovery before it executes.
     * @dev Callable only by the account named in the pending recovery (msg.sender == pending.account).
     *      The account authorizes this through its execute path, so any current owner can veto a
     *      malicious recovery during the delay window.
     * @param recoveryId The id of the pending recovery to cancel.
     */
    function cancelRecovery(bytes32 recoveryId) external {
        PendingRecovery storage rec = _pendingRecoveries[recoveryId];

        // Confirm the recovery exists
        if (rec.account == address(0)) {
            revert JustaRecoveryManager_RecoveryNotPending(recoveryId);
        }

        // Only the account that the recovery is for may cancel it
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
     * @notice Check whether a provider is registered for an account.
     * @param account The smart account.
     * @param provider The recovery provider.
     * @return True if the provider is registered for the account.
     */
    function recoveryProviderAdded(address account, address provider) external view returns (bool) {
        return _providers[account].contains(provider);
    }

    /**
     * @notice Get the list of recovery providers registered for an account.
     * @param account The smart account.
     * @return The list of provider addresses.
     */
    function getRecoveryProviders(address account) external view returns (address[] memory) {
        return _providers[account].values();
    }

    /**
     * @notice Read the account's configured recovery delay in seconds.
     * @dev Returns `0` if the account has never called `setRecoveryDelay`.
     * @param account The smart account.
     * @return The configured delay in seconds, or 0 if unset.
     */
    function recoveryDelay(address account) external view returns (uint256) {
        return _recoveryDelay[account];
    }

    /**
     * @notice Read the details of a pending recovery.
     * @dev Returns zero / empty values if `recoveryId` is not currently pending.
     * @param recoveryId The recovery id.
     * @return account The smart account being recovered.
     * @return provider The provider whose proof initiated this recovery.
     * @return executeAt The timestamp at which the recovery becomes executable.
     * @return subject The new-owner payload (ABI-encoded WebAuthn key).
     */
    function pendingRecovery(bytes32 recoveryId)
        external
        view
        returns (address account, address provider, uint64 executeAt, bytes memory subject)
    {
        PendingRecovery storage rec = _pendingRecoveries[recoveryId];
        return (rec.account, rec.provider, rec.executeAt, rec.subject);
    }

}
