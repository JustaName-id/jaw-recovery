// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { ECDSA } from "solady/utils/ECDSA.sol";
import { EIP712 } from "solady/utils/EIP712.sol";

import { IJustaRecoveryProvider } from "../interfaces/IJustaRecoveryProvider.sol";

/**
 * @title JustaECDSARecoveryProvider
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
contract JustaECDSARecoveryProvider is IJustaRecoveryProvider, EIP712 {

    ////////////////////////////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Thrown when the commitment does not decode to a non-zero EOA.
     */
    error JustaECDSARecoveryProvider_InvalidCommitment();

    /**
     * @notice Thrown when the proof is not exactly a 65-byte ECDSA signature.
     * @param length The length of the supplied proof.
     */
    error JustaECDSARecoveryProvider_InvalidProofLength(uint256 length);

    /**
     * @notice Thrown when the recovered signer does not match the committed EOA.
     */
    error JustaECDSARecoveryProvider_InvalidSignature();

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
     * @param commitment ABI-encoded recovery EOA (`abi.encode(address)`).
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
        view
    {
        // Decode and validate the committed EOA.
        address recoveryEoa = abi.decode(commitment, (address));
        if (recoveryEoa == address(0)) {
            revert JustaECDSARecoveryProvider_InvalidCommitment();
        }

        // Proof must be exactly a 65-byte ECDSA signature.
        if (proof.length != 65) {
            revert JustaECDSARecoveryProvider_InvalidProofLength(proof.length);
        }

        // Reconstruct the canonical EIP-712 digest and recover the signer.
        address signer = ECDSA.recover(_recoverDigest(account, nonce, subject), proof);
        if (signer != recoveryEoa) {
            revert JustaECDSARecoveryProvider_InvalidSignature();
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
        name = "JustaECDSARecoveryProvider";
        version = "1";
    }

}
