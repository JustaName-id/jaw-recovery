// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IRecoveryManager
 *
 * @notice Per-many-accounts wrapper around the EIP-7947 recovery interfaces.
 * Every function takes an explicit `account` argument because a single
 * JustaRecoveryManager singleton serves all JustanAccount instances.
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

    ////////////////////////////////////////////////////////////////////////
    // EVENTS
    ////////////////////////////////////////////////////////////////////////

    event RecoveryProviderAdded(address indexed account, address indexed provider);
    event RecoveryProviderRemoved(address indexed account, address indexed provider);
    event AccessRecovered(address indexed account, address indexed provider, bytes subject);

    ////////////////////////////////////////////////////////////////////////
    // EXTERNAL FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Register a recovery provider for an account.
     * @dev Callable only by the account itself (msg.sender == account). The account is expected to
     *      route this call through its ERC-7821 execute path so that its normal owner check (passkey
     *      signature on the UserOp or direct owner call) authorizes the operation.
     * @param account The smart account registering the provider.
     * @param provider The recovery provider address.
     * @param data Provider-specific commitment data (forwarded to provider.subscribe).
     */
    function addRecoveryProvider(address account, address provider, bytes calldata data) external payable;

    /**
     * @notice Unregister a recovery provider for an account.
     * @dev Callable only by the account itself (msg.sender == account).
     * @param account The smart account unregistering the provider.
     * @param provider The recovery provider address.
     */
    function removeRecoveryProvider(address account, address provider) external payable;

    /**
     * @notice Recover account access by submitting a valid proof to a registered provider.
     * @dev Unrestricted caller; the proof carries authorization. On a successful proof the manager
     *      decodes `subject` as `abi.encode(bytes32 x, bytes32 y)` and calls `addOwnerPublicKey(x, y)`
     *      on the account. Requires the manager to be an owner of the account.
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
        returns (bool);

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

}
