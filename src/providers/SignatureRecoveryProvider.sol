// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EIP712 } from "solady/utils/EIP712.sol";

import { IRecoveryProvider } from "../interfaces/IRecoveryProvider.sol";
import { SignatureProofLib } from "../libraries/SignatureProofLib.sol";

/**
 * @title SignatureRecoveryProvider
 *
 * @notice Canonical multichain recovery verifier for JAW accounts: one guardian signature is valid on
 * every chain the account enrolled on. Two guardian classes, dispatched by commitment length:
 *
 *   - 32-byte commitment (`abi.encode(address)`) — an EOA guardian. The proof is a 64/65-byte ECDSA
 *     signature over the canonical digest, verified with STRICT `ecrecover` only. Deliberately no
 *     ERC-1271/6492 fallback: a smart-account signer's own `isValidSignature` door re-binds
 *     `block.chainid`, which would silently produce per-chain proofs and break the sign-once promise.
 *     A contract address enrolled as a 32-byte commitment is therefore a dead factor that never
 *     verifies — enrollment UIs must reject it.
 *
 *   - 64-byte commitment (`abi.encode(x, y)`) — a raw P-256 passkey public key. The proof is an
 *     ABI-encoded WebAuthn assertion whose challenge is the canonical digest, verified directly in
 *     this provider — byte-for-byte the convention JustanAccount uses for its own passkey owners
 *     (challenge = `abi.encode(digest)`, `requireUserVerification = false`). The guardian's own account
 *     contract is never consulted, so no chain binding applies, and undeployed passkey guardians work
 *     natively with no ERC-6492 dependency.
 *
 * @dev The EIP-712 domain deliberately omits `chainId` (`_hashTypedDataSansChainId`): with the
 *      deterministic same-address deployment on every chain, the digest is byte-identical everywhere.
 *      Replay safety is the manager's job — it consumes the ceremony `salt` per chain and enforces
 *      `expiry`; this provider only binds them into the digest. Signature malleability is accepted by
 *      design: a malleated ECDSA twin verifies the same digest, consumes the same salt, and produces
 *      the same request — no state anywhere keys off raw proof bytes. Passkey verification requires the
 *      RIP-7212 precompile or the canonical Solady P256 verifier on the chain (the same dependency
 *      JustanAccount itself has); without both, passkey proofs verify as invalid.
 *
 *      Holds no per-account state: the JustaRecoveryManager owns the commitment registry and passes the
 *      registered commitment in on each `verify` call, so a single deployment backs any number of
 *      guardians for any number of accounts.
 *
 * @author JustaLab
 */
contract SignatureRecoveryProvider is IRecoveryProvider, EIP712 {

    ////////////////////////////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Thrown when the commitment is not a canonical guardian encoding: exactly 32 bytes holding
     *         a non-zero address (EOA guardian) or exactly 64 bytes (raw passkey public key). Exact
     *         lengths keep one guardian mapped to exactly one commitment: `abi.decode` ignores trailing
     *         bytes, so without this check two encodings of the same guardian could register as two
     *         distinct recoveries and one signature could satisfy both — silently weakening an M-of-N
     *         threshold.
     */
    error SignatureRecoveryProvider_InvalidCommitment();

    /**
     * @notice Thrown when the proof is not a valid signature from the committed guardian over the
     *         canonical digest.
     */
    error SignatureRecoveryProvider_InvalidSignature();

    ////////////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice EIP-712 typehash for the Recover struct. All guardians of one ceremony sign this same
     *         message; `salt` and `expiry` are enforced by the manager and only bound here.
     */
    bytes32 public constant RECOVER_TYPEHASH =
        keccak256("Recover(address account,bytes subject,bytes32 salt,uint256 expiry)");

    ////////////////////////////////////////////////////////////////////////
    // EXTERNAL FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Verify a recovery proof against a committed guardian. Reverts on failure.
     * @dev Deliberately non-view to keep provider mutability semantics uniform across implementations
     *      (see IRecoveryProvider); this implementation performs no state changes.
     * @param account The smart account being recovered.
     * @param subject The new-owner payload bound by the signature.
     * @param salt The ceremony's single-use salt, bound by the signature; consumed per chain by the manager.
     * @param expiry The ceremony's expiry timestamp, bound by the signature; enforced by the manager.
     * @param commitment The registered guardian: 32-byte `abi.encode(address)` (EOA) or 64-byte
     *        `abi.encode(x, y)` (raw passkey public key).
     * @param proof A 64/65-byte ECDSA signature (EOA guardian), or an ABI-encoded WebAuthn assertion
     *        whose challenge is the canonical digest (passkey guardian).
     */
    function verify(
        address account,
        bytes calldata subject,
        bytes32 salt,
        uint256 expiry,
        bytes calldata commitment,
        bytes calldata proof
    )
        external
    {
        bytes32 digest = _recoverDigest(account, subject, salt, expiry);

        if (commitment.length == 32) {
            // EOA guardian — strict ecrecover only (no ERC-1271/6492 fallback so a chain-bound
            // smart-account envelope can never re-enter this provider); see SignatureProofLib.
            address signer = abi.decode(commitment, (address));
            if (signer == address(0)) {
                revert SignatureRecoveryProvider_InvalidCommitment();
            }
            if (!SignatureProofLib.isValidEoaProof(digest, signer, proof)) {
                revert SignatureRecoveryProvider_InvalidSignature();
            }
        } else if (commitment.length == 64) {
            // Raw passkey guardian — WebAuthn assertion verified directly against the committed public
            // key, mirroring JustanAccount's own owner verification; see SignatureProofLib. The
            // guardian's account contract is never consulted.
            (bytes32 x, bytes32 y) = abi.decode(commitment, (bytes32, bytes32));
            if (!SignatureProofLib.isValidPasskeyProof(digest, x, y, proof)) {
                revert SignatureRecoveryProvider_InvalidSignature();
            }
        } else {
            revert SignatureRecoveryProvider_InvalidCommitment();
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Compute the chain-agnostic EIP-712 digest the guardians of a ceremony must sign.
     * @dev EOA guardians sign this digest directly; passkey guardians produce a WebAuthn assertion with
     *      `challenge = abi.encode(digest)`. Identical on every chain (the domain omits chainId and this
     *      provider deploys at the same deterministic address everywhere).
     * @param account The smart account being recovered.
     * @param subject The new-owner payload.
     * @param salt The ceremony's single-use salt.
     * @param expiry The ceremony's expiry timestamp.
     * @return The EIP-712 digest to sign.
     */
    function recoverDigest(
        address account,
        bytes calldata subject,
        bytes32 salt,
        uint256 expiry
    )
        external
        view
        returns (bytes32)
    {
        return _recoverDigest(account, subject, salt, expiry);
    }

    ////////////////////////////////////////////////////////////////////////
    // INTERNAL HELPERS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Build the chain-agnostic EIP-712 digest for `(account, subject, salt, expiry)`.
     */
    function _recoverDigest(
        address account,
        bytes calldata subject,
        bytes32 salt,
        uint256 expiry
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(RECOVER_TYPEHASH, account, keccak256(subject), salt, expiry));
        return _hashTypedDataSansChainId(structHash);
    }

    /**
     * @dev EIP-712 domain name and version, consumed by Solady's EIP712 base. The domain binds
     *      `{name, version, verifyingContract}` — chainId is deliberately absent.
     */
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "SignatureRecoveryProvider";
        version = "1";
    }

}
