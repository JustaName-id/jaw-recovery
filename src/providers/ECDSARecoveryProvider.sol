// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { ECDSA } from "solady/utils/ECDSA.sol";
import { EIP712 } from "solady/utils/EIP712.sol";

import { IRecoveryProvider } from "../interfaces/IRecoveryProvider.sol";

/**
 * @title ECDSARecoveryProvider
 *
 * @notice Stateless ECDSA-EOA recovery verifier for JAW accounts. The recovery commitment is an EOA
 * address; the recovery proof is an EIP-712 signature from that EOA over `(account, nonce, subject)`.
 *
 * @dev Holds no per-account state. The JustaRecoveryManager owns the commitment registry and the
 *      per-account replay nonce and passes them in on each `verify` call, so a single deployment of this
 *      provider can back any number of recovery EOAs for any number of accounts. The EIP-712 domain binds
 *      proofs to this contract, so a signature for this provider cannot be reused on another.
 *
 * @author JustaLab
 */
contract ECDSARecoveryProvider is IRecoveryProvider, EIP712 {

    ////////////////////////////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Thrown when the commitment is not a canonical 32-byte ABI-encoded non-zero EOA. The exact
     *         length is required so a single EOA maps to exactly one commitment: `abi.decode` ignores
     *         trailing bytes, so without this check `abi.encode(eoa)` and `abi.encode(eoa) || 0x00…` would
     *         decode to the same EOA under different recovery ids and one signature could satisfy several
     *         approvals — silently weakening an M-of-N threshold.
     */
    error ECDSARecoveryProvider_InvalidCommitment();

    /**
     * @notice Thrown when the proof is not exactly a 65-byte ECDSA signature.
     * @param length The length of the supplied proof.
     */
    error ECDSARecoveryProvider_InvalidProofLength(uint256 length);

    /**
     * @notice Thrown when the recovered signer does not match the committed EOA.
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
     * @notice Verify an ECDSA recovery proof against a committed EOA. Reverts on failure.
     * @param account The smart account being recovered.
     * @param subject The new-owner payload bound by the signature.
     * @param nonce The manager's per-account recovery nonce, bound by the signature for replay safety.
     * @param commitment Canonical 32-byte ABI-encoded recovery EOA (`abi.encode(address)`).
     * @param proof A 65-byte ECDSA signature `(r, s, v)` over the canonical digest.
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

        // Decode and validate the committed EOA.
        address recoveryEoa = abi.decode(commitment, (address));
        if (recoveryEoa == address(0)) {
            revert ECDSARecoveryProvider_InvalidCommitment();
        }

        // Proof must be exactly a 65-byte ECDSA signature.
        if (proof.length != 65) {
            revert ECDSARecoveryProvider_InvalidProofLength(proof.length);
        }

        // Reconstruct the canonical EIP-712 digest and recover the signer.
        address signer = ECDSA.recover(_recoverDigest(account, nonce, subject), proof);
        if (signer != recoveryEoa) {
            revert ECDSARecoveryProvider_InvalidSignature();
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Compute the EIP-712 digest the recovery EOA must sign for a given recovery.
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
