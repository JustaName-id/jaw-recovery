// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IJustaRecoveryProvider
 *
 * @notice JAW-specific recovery provider interface. Differs from EIP-7947's IRecoveryProvider
 * by taking `account` explicitly on every state-changing function — the caller is always the
 * JustaRecoveryManager singleton, never the account itself, so `msg.sender` cannot be used
 * to identify the account.
 *
 * Implementations MUST:
 *   - hard-code the JustaRecoveryManager address as an immutable;
 *   - reject calls from any other address on subscribe / unsubscribe / recover;
 *   - ensure that proofs cannot be replayed (typically via a per-account nonce).
 *
 * @author JustaLab
 */
interface IJustaRecoveryProvider {

    ////////////////////////////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Thrown when the caller is not the JustaRecoveryManager.
     * @param caller The actual caller.
     */
    error JustaRecoveryProvider_NotManager(address caller);

    ////////////////////////////////////////////////////////////////////////
    // EVENTS
    ////////////////////////////////////////////////////////////////////////

    event AccountSubscribed(address indexed account);
    event AccountUnsubscribed(address indexed account);

    ////////////////////////////////////////////////////////////////////////
    // EXTERNAL FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Subscribe an account to this provider with the given commitment.
     * @dev MUST be callable only by the JustaRecoveryManager. Stores the commitment keyed by `account`.
     * @param account The smart account being subscribed.
     * @param data Provider-specific commitment payload.
     */
    function subscribe(address account, bytes calldata data) external payable;

    /**
     * @notice Unsubscribe an account from this provider, deleting all stored recovery data.
     * @dev MUST be callable only by the JustaRecoveryManager.
     * @param account The smart account being unsubscribed.
     */
    function unsubscribe(address account) external payable;

    /**
     * @notice Verify a recovery proof for an account.
     * @dev MUST be callable only by the JustaRecoveryManager. Reverts if the proof is invalid.
     *      MUST update internal replay state (e.g. nonce) on success so the same proof cannot be reused.
     * @param account The smart account being recovered.
     * @param subject The recovery subject (opaque to provider; bound by the proof).
     * @param proof Provider-specific proof.
     */
    function recover(address account, bytes calldata subject, bytes calldata proof) external;

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Get the stored recovery commitment for an account.
     * @param account The smart account.
     * @return The provider-specific commitment bytes.
     */
    function getRecoveryData(address account) external view returns (bytes memory);

}
