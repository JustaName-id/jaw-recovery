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
 * recovery flow that, once the account's threshold of providers approve and after a configurable
 * delay, registers a new owner (WebAuthn passkey or EOA) on the target account.
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
     * @notice Per-account set of registered recovery providers.
     */
    mapping(address account => EnumerableSet.AddressSet providers) internal _providers;

    /**
     * @notice Per-account recovery delay override in seconds. Only meaningful when
     *         `_recoveryDelayConfigured[account]` is true; otherwise `DEFAULT_RECOVERY_DELAY` applies.
     */
    mapping(address account => uint256 delaySeconds) internal _recoveryDelay;

    /**
     * @notice Whether the account has explicitly set a delay. When false, `DEFAULT_RECOVERY_DELAY`
     *         applies; when true, the stored `_recoveryDelay` value applies (including 0 = instant).
     */
    mapping(address account => bool configured) internal _recoveryDelayConfigured;

    /**
     * @notice Per-account monotonic counter used to derive deterministic `recoveryId`s.
     */
    mapping(address account => uint256 nonce) internal _recoveryNonce;

    /**
     * @notice Pending recoveries keyed by `recoveryId`.
     */
    mapping(bytes32 recoveryId => PendingRecovery) internal _pendingRecoveries;

    /**
     * @notice Per-account approval threshold. `0` means "use the default of 1".
     */
    mapping(address account => uint256 threshold) internal _recoveryThreshold;

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
        uint256 threshold = _recoveryThreshold[account];
        return threshold == 0 ? 1 : threshold;
    }

    /**
     * @dev Effective recovery delay: the stored value if the account configured one, else the default.
     */
    function _effectiveDelay(address account) internal view returns (uint256) {
        return _recoveryDelayConfigured[account] ? _recoveryDelay[account] : DEFAULT_RECOVERY_DELAY;
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

        // Disallow dropping below the threshold (except a full opt-out to zero providers).
        uint256 newCount = _providers[account].length();
        if (newCount != 0 && newCount < _effectiveThreshold(account)) {
            revert JustaRecoveryManager_RemovalBelowThreshold(newCount, _effectiveThreshold(account));
        }

        // Forward to the provider, attaching any value sent with the call
        IJustaRecoveryProvider(provider).unsubscribe{ value: msg.value }(account);

        emit RecoveryProviderRemoved(account, provider);
    }

    /**
     * @notice Set the per-account recovery delay.
     * @dev Callable only by the account. No minimum — `0` is allowed and means instant. Reverts only
     *      if above `MAX_RECOVERY_DELAY`. Marks the account as having configured a delay (so the
     *      default no longer applies). Pending recoveries keep their original `executeAt`.
     * @param account The smart account.
     * @param delaySeconds The new delay in seconds (`0` = instant).
     */
    function setRecoveryDelay(address account, uint256 delaySeconds) external onlyAccount(account) {
        if (delaySeconds > MAX_RECOVERY_DELAY) {
            revert JustaRecoveryManager_DelayOutOfBounds(delaySeconds, 0, MAX_RECOVERY_DELAY);
        }

        uint256 oldDelay = _effectiveDelay(account);
        _recoveryDelay[account] = delaySeconds;
        _recoveryDelayConfigured[account] = true;

        emit RecoveryDelayChanged(account, oldDelay, delaySeconds);
    }

    /**
     * @notice Set the per-account approval threshold.
     * @dev Callable only by the account. Must be within `[1, providerCount]` so a recovery is always
     *      achievable. With a single provider the only valid value is 1 (the default).
     * @param account The smart account.
     * @param threshold The number of distinct providers required to approve a recovery.
     */
    function setRecoveryThreshold(address account, uint256 threshold) external onlyAccount(account) {
        uint256 providerCount = _providers[account].length();
        if (threshold < 1 || threshold > providerCount) {
            revert JustaRecoveryManager_InvalidThreshold(threshold, providerCount);
        }

        uint256 oldThreshold = _effectiveThreshold(account);
        _recoveryThreshold[account] = threshold;

        emit RecoveryThresholdChanged(account, oldThreshold, threshold);
    }

    ////////////////////////////////////////////////////////////////////////
    // EXECUTION FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Queue a recovery for an account once enough providers have approved the same new owner.
     * @dev Unrestricted caller; the proofs carry authorization. Requires exactly
     *      `recoveryThreshold(account)` distinct, registered providers to each verify a proof over the
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
        nonReentrant
        returns (bytes32 recoveryId)
    {
        if (providers.length != proofs.length) {
            revert JustaRecoveryManager_LengthMismatch(providers.length, proofs.length);
        }

        uint256 required = _effectiveThreshold(account);
        if (providers.length != required) {
            revert JustaRecoveryManager_InvalidProofCount(providers.length, required);
        }

        if (subject.length != 32 && subject.length != 64) {
            revert JustaRecoveryManager_InvalidSubjectLength(subject.length);
        }

        for (uint256 i = 0; i < providers.length; ++i) {
            address provider = providers[i];

            // Must be a registered provider for this account.
            if (!_providers[account].contains(provider)) {
                revert JustaRecoveryManager_ProviderNotRegistered(account, provider);
            }

            // Must be distinct from every earlier entry.
            for (uint256 j = 0; j < i; ++j) {
                if (providers[j] == provider) {
                    revert JustaRecoveryManager_DuplicateProvider(provider);
                }
            }

            // Delegate proof verification; provider reverts on an invalid proof and bumps its own nonce.
            IJustaRecoveryProvider(provider).recover(account, subject, proofs[i]);
        }

        recoveryId = keccak256(abi.encode(account, subject, _recoveryNonce[account]++));

        uint64 executeAt = uint64(block.timestamp + _effectiveDelay(account));
        _pendingRecoveries[recoveryId] = PendingRecovery({ account: account, executeAt: executeAt, subject: subject });

        emit RecoveryInitiated(account, recoveryId, providers, subject, executeAt);
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
        bytes memory subject = rec.subject;

        // Delete the pending entry first (CEI)
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
     * @notice Read the account's effective recovery delay in seconds (the 24h default if never set).
     * @param account The smart account.
     * @return The effective delay in seconds.
     */
    function recoveryDelay(address account) external view returns (uint256) {
        return _effectiveDelay(account);
    }

    /**
     * @notice Read the account's effective approval threshold (1 if never set).
     * @param account The smart account.
     * @return The number of distinct providers required to approve a recovery.
     */
    function recoveryThreshold(address account) external view returns (uint256) {
        return _effectiveThreshold(account);
    }

    /**
     * @notice Read the details of a pending recovery.
     * @dev Returns zero / empty values if `recoveryId` is not currently pending.
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
