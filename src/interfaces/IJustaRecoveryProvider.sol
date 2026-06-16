// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IJustaRecoveryProvider
 *
 * @notice Stateless verifier interface for JAW recovery providers. A provider holds NO per-account
 * state: the JustaRecoveryManager owns the registry of recovery commitments and the per-account replay
 * nonce, and passes both in on every call. A provider's sole job is to answer — for a given commitment —
 * whether a proof authorizes recovering `account` to the new owner encoded in `subject`.
 *
 * Implementations MUST:
 *   - revert on an invalid proof, and return (no value) on success;
 *   - bind the proof to `(account, nonce, subject)` so it cannot be replayed across accounts, nonces, or
 *     target owners. The manager increments `nonce` after every recovery, which makes a proof single-use;
 *   - verify the proof against `commitment`: a proof is valid for exactly one commitment and MUST NOT
 *     pass for any other commitment accepted by this provider. Otherwise one factor could satisfy
 *     several slots of the same provider in one recovery, silently weakening an M-of-N threshold.
 *
 * Implementations SHOULD be `view` (pure verification) — they are handed all the state they need.
 *
 * @author JustaLab
 */
interface IJustaRecoveryProvider {

    /**
     * @notice Verify that `proof` authorizes recovering `account` to the owner encoded in `subject`,
     *         against the recovery `commitment`. MUST revert if it does not.
     * @param account The smart account being recovered.
     * @param subject The new-owner payload (opaque to the provider; bound by the proof).
     * @param nonce The manager's current per-account recovery nonce, bound into the proof for replay safety.
     * @param commitment The recovery commitment this proof is checked against (e.g. an EOA, an email hash).
     * @param proof Provider-specific proof.
     */
    function verify(
        address account,
        bytes calldata subject,
        uint256 nonce,
        bytes calldata commitment,
        bytes calldata proof
    )
        external;

}
