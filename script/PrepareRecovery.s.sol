// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Script } from "forge-std/Script.sol";

import { IRecoveryManager } from "../src/interfaces/IRecoveryManager.sol";
import { ECDSARecoveryProvider } from "../src/providers/ECDSARecoveryProvider.sol";
import { CodeConstants } from "./HelperConfig.s.sol";

/**
 * @title PrepareRecovery
 * @notice Helper contract for building recovery structs and signing recovery proofs in tests.
 */
contract PrepareRecovery is Script, CodeConstants {

    /**
     * @notice Creates a Recovery struct.
     * @param provider The recovery provider (a stateless verifier).
     * @param commitment Provider-specific commitment bytes.
     * @param delay The per-recovery time-lock in seconds.
     * @return recovery The constructed Recovery struct.
     */
    function createRecovery(
        address provider,
        bytes memory commitment,
        uint32 delay
    )
        public
        pure
        returns (IRecoveryManager.Recovery memory recovery)
    {
        return IRecoveryManager.Recovery({ provider: provider, commitment: commitment, delay: delay });
    }

    /**
     * @notice Creates an Approval struct.
     * @param recoveryId The id of the registered recovery being approved.
     * @param proof The provider-specific proof.
     * @return approval The constructed Approval struct.
     */
    function createApproval(
        bytes32 recoveryId,
        bytes memory proof
    )
        public
        pure
        returns (IRecoveryManager.Approval memory approval)
    {
        return IRecoveryManager.Approval({ recoveryId: recoveryId, proof: proof });
    }

    /**
     * @notice Encodes an EOA as a canonical 32-byte ECDSA recovery commitment (`abi.encode(eoa)`).
     */
    function encodeEoaCommitment(address eoa) public pure returns (bytes memory) {
        return abi.encode(eoa);
    }

    /**
     * @notice Encodes an EOA owner as a 32-byte recovery subject (`abi.encode(owner)`).
     */
    function encodeEoaSubject(address owner) public pure returns (bytes memory) {
        return abi.encode(owner);
    }

    /**
     * @notice Encodes a passkey public key as a 64-byte recovery subject (`abi.encode(x, y)`).
     */
    function encodePasskeySubject(bytes32 x, bytes32 y) public pure returns (bytes memory) {
        return abi.encode(x, y);
    }

    /**
     * @notice Produces a 65-byte ECDSA recovery proof signed by `privateKey` over the provider's canonical
     *         EIP-712 digest for `(account, nonce, subject)`.
     * @param provider The ECDSA recovery provider whose domain the proof is bound to.
     * @param account The smart account being recovered.
     * @param nonce The manager's current per-account recovery nonce.
     * @param subject The new-owner payload.
     * @param privateKey The signing key (the committed recovery EOA's key for a valid proof).
     * @return proof The 65-byte `(r, s, v)` signature.
     */
    function signRecoverProof(
        ECDSARecoveryProvider provider,
        address account,
        uint256 nonce,
        bytes memory subject,
        uint256 privateKey
    )
        public
        view
        returns (bytes memory proof)
    {
        bytes32 digest = provider.recoverDigest(account, nonce, subject);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /**
     * @notice Produces a 64-byte EIP-2098 compact ECDSA recovery proof signed by `privateKey` over the
     *         provider's canonical EIP-712 digest for `(account, nonce, subject)`.
     * @dev Mirrors `signRecoverProof` but returns the EIP-2098 short form `(r, vs)` that `SignatureCheckerLib`
     *      also accepts for EOA signers. `vm.sign` yields canonical low-s, so the top bit of `s` is free to
     *      carry the y-parity (`v - 27`).
     * @return proof The 64-byte `(r, vs)` compact signature.
     */
    function signRecoverProofCompact(
        ECDSARecoveryProvider provider,
        address account,
        uint256 nonce,
        bytes memory subject,
        uint256 privateKey
    )
        public
        view
        returns (bytes memory proof)
    {
        bytes32 digest = provider.recoverDigest(account, nonce, subject);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes32 vs = bytes32(uint256(s) | (uint256(v - 27) << 255));
        return abi.encodePacked(r, vs);
    }

}
