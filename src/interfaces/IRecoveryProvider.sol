// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IRecoveryProvider
 *
 * @notice Stateless verifier interface for JAW recovery providers. A provider holds NO per-account
 * state: the JustaRecoveryManager owns the registry of recovery commitments, the per-account used-salt
 * registry (which makes proofs single-use per chain), and the proof expiry check, and passes everything
 * in on every call. A provider's sole job is to answer — for a given commitment — whether a proof
 * authorizes recovering `account` to the new owner encoded in `subject`.
 *
 * Implementations MUST (universal, including third-party providers):
 *   - revert on an invalid proof, and return (no value) on success;
 *   - bind the proof to all of `(account, subject, salt, expiry)` so it cannot be reused across
 *     accounts, target owners, or ceremonies, and so a relayer cannot substitute a different salt or
 *     expiry than the one the guardians authorized. The manager consumes `salt` per chain and enforces
 *     `expiry`; providers only bind them;
 *   - verify the proof against `commitment`: a proof is valid for exactly one commitment and MUST NOT
 *     pass for any other commitment accepted by this provider. Otherwise one factor could satisfy
 *     several recoveries of the same provider in one request, silently weakening an M-of-N threshold.
 *
 * Canonical providers (shipped by JustaLab) MUST additionally be multichain — one guardian signature
 * valid on every enrolled chain:
 *   - derive the proven message exclusively from the chain-agnostic `(account, subject, salt, expiry)`
 *     tuple; never read `block.chainid` into it;
 *   - never route verification through a chain-binding intermediary (e.g. the ERC-1271 door of a
 *     contract the provider does not control);
 *   - be deployed deterministically at the same address on every chain (the signing domain binds the
 *     verifying contract's address);
 *   - keep any provider-internal freshness checks chain-independent.
 * Third-party providers MAY be chain-bound; their factors are then valid on a single chain only.
 *
 * Implementations MAY enforce stricter freshness than the manager's `expiry` (e.g. a DKIM timestamp
 * bound); the manager's check is the outer bound.
 *
 * @author JustaLab
 */
interface IRecoveryProvider {

    /**
     * @notice Verify that `proof` authorizes recovering `account` to the owner encoded in `subject`,
     *         against the recovery `commitment`. MUST revert if it does not.
     * @param account The smart account being recovered.
     * @param subject The new-owner payload (opaque to the provider; bound by the proof).
     * @param salt The ceremony's single-use salt; consumed per chain by the manager, bound by the proof.
     * @param expiry The ceremony's expiry timestamp; enforced by the manager, bound by the proof.
     * @param commitment The recovery commitment this proof is checked against (e.g. an EOA, a passkey
     *        public key, an email hash).
     * @param proof Provider-specific proof.
     */
    function verify(
        address account,
        bytes calldata subject,
        bytes32 salt,
        uint256 expiry,
        bytes calldata commitment,
        bytes calldata proof
    )
        external;

}
