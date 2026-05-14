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
 * it holds the per-account registry of recovery providers and, on a successful proof, registers
 * a new WebAuthn public-key owner on the target account.
 *
 * @dev The manager performs no cryptographic verification of its own. It dispatches to the provider
 *      the account opted into and trusts the provider's return value; provider trust is therefore
 *      equivalent to provider correctness. Non-ownable, non-upgradeable, deployed once per chain at
 *      a deterministic address.
 *
 * @author JustaLab
 */
contract JustaRecoveryManager is IRecoveryManager, ReentrancyGuard {

    using EnumerableSet for EnumerableSet.AddressSet;

    ////////////////////////////////////////////////////////////////////////
    // STORAGE
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Per-account set of registered recovery providers.
     */
    mapping(address account => EnumerableSet.AddressSet providers) internal _providers;

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
     *      (passkey signature on the UserOp or direct owner call) authorizes the operation. The
     *      provider receives a subscribe call with msg.sender = manager and the account passed
     *      explicitly.
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
     * @dev Callable only by the account itself (msg.sender == account). The provider receives an
     *      unsubscribe call with msg.sender = manager and the account passed explicitly; the
     *      provider is expected to delete all data associated with the account.
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

    ////////////////////////////////////////////////////////////////////////
    // EXECUTION FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Recover account access by submitting a valid proof to a registered provider.
     * @dev Unrestricted caller; the proof carries authorization. On a successful proof the manager
     *      decodes `subject` as `abi.encode(bytes32 x, bytes32 y)` and calls `addOwnerPublicKey(x, y)`
     *      on the account. Requires the manager to be an owner of the account (set during opt-in).
     *      Replay protection is the provider's responsibility — providers MUST update their internal
     *      state on success so the same proof cannot be reused.
     * @param account The smart account to recover.
     * @param subject ABI-encoded WebAuthn public key (bytes32 x, bytes32 y) of the new owner.
     * @param provider The recovery provider whose proof is being submitted.
     * @param proof Provider-specific recovery proof.
     * @return Always returns true on success; reverts on any failure.
     */
    function recoverAccess(
        address account,
        bytes calldata subject,
        address provider,
        bytes calldata proof
    )
        external
        nonReentrant
        returns (bool)
    {
        // Confirm the provider is registered for this account
        if (!_providers[account].contains(provider)) {
            revert JustaRecoveryManager_ProviderNotRegistered(account, provider);
        }

        // Delegate proof verification to the provider; provider MUST revert on invalid proof
        IJustaRecoveryProvider(provider).recover(account, subject, proof);

        // Decode the new WebAuthn public key from subject and register it as an owner on the account
        (bytes32 x, bytes32 y) = abi.decode(subject, (bytes32, bytes32));
        MultiOwnable(account).addOwnerPublicKey(x, y);

        emit AccessRecovered(account, provider, subject);

        return true;
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

}
