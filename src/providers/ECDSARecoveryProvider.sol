// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EIP712 } from "solady/utils/EIP712.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

import { IRecoveryProvider } from "../interfaces/IRecoveryProvider.sol";

/**
 * @title ECDSARecoveryProvider
 *
 * @notice Stateless signature-based recovery verifier for JAW accounts. The recovery commitment is a
 * signer address; the recovery proof is an EIP-712 signature over `(account, nonce, subject)`, validated
 * with Solady's `SignatureCheckerLib`: a raw ECDSA signature when the signer is an EOA, or an ERC-1271
 * `isValidSignature` check when the signer is a contract (e.g. a smart-account / passkey-backed guardian).
 * A single path therefore covers both EOA and smart-account guardians.
 *
 * @dev Holds no per-account state. The JustaRecoveryManager owns the commitment registry and the
 *      per-account replay nonce and passes them in on each `verify` call, so a single deployment of this
 *      provider can back any number of recovery signers for any number of accounts. The EIP-712 domain binds
 *      proofs to this contract, so a signature for this provider cannot be reused on another.
 *
 * @author JustaLab
 */
contract ECDSARecoveryProvider is IRecoveryProvider, EIP712 {

    ////////////////////////////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Thrown when the commitment is not a canonical 32-byte ABI-encoded non-zero signer address.
     *         The exact length is required so a single signer maps to exactly one commitment: `abi.decode`
     *         ignores trailing bytes, so without this check `abi.encode(signer)` and `abi.encode(signer) ||
     *         0x00…` would decode to the same signer under different recovery ids and one signature could
     *         satisfy several approvals — silently weakening an M-of-N threshold.
     */
    error ECDSARecoveryProvider_InvalidCommitment();

    /**
     * @notice Thrown when the proof is not a valid signature for the committed signer.
     */
    error ECDSARecoveryProvider_InvalidSignature();

    ////////////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice EIP-712 typehash for the Recover struct.
     */
    bytes32 public constant RECOVER_TYPEHASH = keccak256("Recover(address account,uint256 nonce,bytes subject)");

    ////////////////////////////////////////////////////////////////////////
    // EXTERNAL FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Verify a recovery proof against a committed signer. Reverts on failure.
     * @param account The smart account being recovered.
     * @param subject The new-owner payload bound by the signature.
     * @param nonce The manager's per-account recovery nonce, bound by the signature for replay safety.
     * @param commitment Canonical 32-byte ABI-encoded recovery signer (`abi.encode(address)`); an EOA or a contract.
     * @param proof The recovery signature over the canonical digest: a raw ECDSA signature for an EOA signer,
     *        or an ERC-1271 signature for a contract signer.
     */
    function verify(
        address account,
        bytes calldata subject,
        uint256 nonce,
        bytes calldata commitment,
        bytes calldata proof
    )
        external
    {
        if (commitment.length != 32) {
            revert ECDSARecoveryProvider_InvalidCommitment();
        }

        // Decode and validate the committed signer.
        address signer = abi.decode(commitment, (address));
        if (signer == address(0)) {
            revert ECDSARecoveryProvider_InvalidCommitment();
        }

        // Verify the proof against the committed signer over the canonical EIP-712 digest. SignatureCheckerLib
        // validates a raw ECDSA signature when `signer` is an EOA and falls back to an ERC-1271
        // `isValidSignature` call when `signer` is a contract, so one path covers EOA and smart-account guardians.
        if (!SignatureCheckerLib.isValidSignatureNowCalldata(signer, _recoverDigest(account, nonce, subject), proof)) {
            revert ECDSARecoveryProvider_InvalidSignature();
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Compute the EIP-712 digest the recovery signer must sign for a given recovery.
     * @dev Pass the manager's current `recoveryNonce(account)` as `nonce`.
     * @param account The smart account being recovered.
     * @param nonce The manager's current per-account recovery nonce.
     * @param subject The new-owner payload.
     * @return The EIP-712 digest to sign.
     */
    function recoverDigest(address account, uint256 nonce, bytes calldata subject) external view returns (bytes32) {
        return _recoverDigest(account, nonce, subject);
    }

    ////////////////////////////////////////////////////////////////////////
    // INTERNAL HELPERS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Build the EIP-712 digest for `(account, nonce, subject)`.
     */
    function _recoverDigest(address account, uint256 nonce, bytes calldata subject) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(RECOVER_TYPEHASH, account, nonce, keccak256(subject)));
        return _hashTypedData(structHash);
    }

    /**
     * @dev EIP-712 domain name and version, consumed by Solady's EIP712 base.
     */
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "ECDSARecoveryProvider";
        version = "1";
    }

}
