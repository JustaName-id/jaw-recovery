// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { ECDSA } from "solady/utils/ECDSA.sol";
import { EIP712 } from "solady/utils/EIP712.sol";

import { IJustaRecoveryProvider } from "../interfaces/IJustaRecoveryProvider.sol";

/**
 * @title JustaECDSARecoveryProvider
 *
 * @notice ECDSA-EOA recovery provider for JAW accounts. The recovery commitment is an EOA address;
 * the recovery proof is an EIP-712 signature from that EOA over `(account, nonce, subject)`.
 *
 * @dev State-changing functions (subscribe / unsubscribe / recover) are restricted to the
 *      JustaRecoveryManager singleton hard-coded at deploy time. Replay protection is per-account
 *      monotonic nonce — not reset on unsubscribe.
 *
 * @author JustaLab
 */
contract JustaECDSARecoveryProvider is IJustaRecoveryProvider, EIP712 {

    ////////////////////////////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Thrown when subscribe data does not decode to a valid EOA.
     */
    error JustaECDSARecoveryProvider_ZeroEoa();

    /**
     * @notice Thrown when subscribe is called for an account that already has a commitment.
     * @param account The smart account.
     */
    error JustaECDSARecoveryProvider_AlreadySubscribed(address account);

    /**
     * @notice Thrown when unsubscribe or recover is called for an account that has no commitment.
     * @param account The smart account.
     */
    error JustaECDSARecoveryProvider_NotSubscribed(address account);

    /**
     * @notice Thrown when the recovery proof signature does not match the stored commitment.
     */
    error JustaECDSARecoveryProvider_InvalidSignature();

    /**
     * @notice Thrown when the proof is not exactly a 65-byte ECDSA signature.
     * @param length The length of the supplied proof.
     */
    error JustaECDSARecoveryProvider_InvalidProofLength(uint256 length);

    ////////////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice EIP-712 typehash for the Recover struct.
     */
    bytes32 public constant RECOVER_TYPEHASH = keccak256("Recover(address account,uint256 nonce,bytes subject)");

    ////////////////////////////////////////////////////////////////////////
    // IMMUTABLES
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice The JustaRecoveryManager singleton — the only authorized caller of state-changing
     *         functions on this provider.
     */
    address public immutable JUSTA_RECOVERY_MANAGER;

    ////////////////////////////////////////////////////////////////////////
    // STORAGE
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Per-account recovery EOA commitment. `address(0)` means "not subscribed."
     */
    mapping(address account => address recoveryEoa) internal _commitments;

    /**
     * @notice Per-account replay-protection nonce. Monotonic; intentionally not reset on unsubscribe.
     */
    mapping(address account => uint256) internal _nonces;

    ////////////////////////////////////////////////////////////////////////
    // CONSTRUCTOR
    ////////////////////////////////////////////////////////////////////////

    constructor(address manager) {
        JUSTA_RECOVERY_MANAGER = manager;
    }

    ////////////////////////////////////////////////////////////////////////
    // MODIFIERS
    ////////////////////////////////////////////////////////////////////////

    modifier onlyManager() {
        if (msg.sender != JUSTA_RECOVERY_MANAGER) {
            revert JustaRecoveryProvider_NotManager(msg.sender);
        }
        _;
    }

    ////////////////////////////////////////////////////////////////////////
    // EXTERNAL FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Subscribe an account to this provider with the given recovery EOA.
     * @dev Callable only by the JustaRecoveryManager. `data` MUST be `abi.encode(address recoveryEoa)`
     *      where the EOA is non-zero. The per-account nonce is preserved across subscribe / unsubscribe
     *      cycles to prevent replay of stale signatures.
     * @param account The smart account being subscribed.
     * @param data ABI-encoded recovery EOA address.
     */
    function subscribe(address account, bytes calldata data) external payable onlyManager {
        // Reject re-subscription before unsubscribing
        if (_commitments[account] != address(0)) {
            revert JustaECDSARecoveryProvider_AlreadySubscribed(account);
        }

        // Decode and validate the recovery EOA
        address recoveryEoa = abi.decode(data, (address));
        if (recoveryEoa == address(0)) {
            revert JustaECDSARecoveryProvider_ZeroEoa();
        }

        // Store the commitment; nonce is preserved from any prior subscription
        _commitments[account] = recoveryEoa;

        emit AccountSubscribed(account);
    }

    /**
     * @notice Unsubscribe an account from this provider.
     * @dev Callable only by the JustaRecoveryManager. Clears the commitment but intentionally
     *      preserves the nonce — old signatures cannot be replayed even if the same EOA is later
     *      re-subscribed.
     * @param account The smart account being unsubscribed.
     */
    function unsubscribe(address account) external payable onlyManager {
        // Reject unsubscribing an account that was never subscribed
        if (_commitments[account] == address(0)) {
            revert JustaECDSARecoveryProvider_NotSubscribed(account);
        }

        // Clear commitment; nonce is intentionally not reset
        delete _commitments[account];

        emit AccountUnsubscribed(account);
    }

    /**
     * @notice Verify a recovery proof for an account.
     * @dev Callable only by the JustaRecoveryManager. Reverts if the proof is not a valid ECDSA
     *      signature of the canonical EIP-712 digest by the stored recovery EOA. Increments the
     *      per-account nonce on success.
     * @param account The smart account being recovered.
     * @param subject The recovery subject (opaque to this provider; bound by the proof).
     * @param proof A 65-byte ECDSA signature `(r, s, v)`.
     */
    function recover(address account, bytes calldata subject, bytes calldata proof) external onlyManager {
        // Account must be currently subscribed
        address recoveryEoa = _commitments[account];
        if (recoveryEoa == address(0)) {
            revert JustaECDSARecoveryProvider_NotSubscribed(account);
        }

        // Proof must be exactly a 65-byte ECDSA signature
        if (proof.length != 65) {
            revert JustaECDSARecoveryProvider_InvalidProofLength(proof.length);
        }

        // Reconstruct the canonical EIP-712 digest using the account's current nonce
        bytes32 digest = _digest(account, _nonces[account], subject);

        // Recover the signer and check it matches the stored commitment
        address signer = ECDSA.recover(digest, proof);
        if (signer != recoveryEoa) {
            revert JustaECDSARecoveryProvider_InvalidSignature();
        }

        // Bump the nonce to invalidate the just-used signature
        unchecked {
            _nonces[account]++;
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // VIEW FUNCTIONS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Return the ABI-encoded recovery commitment for an account.
     * @dev Decoded form is `(address recoveryEoa)`. Returns `abi.encode(address(0))` if the account
     *      is not subscribed.
     * @param account The smart account.
     * @return The ABI-encoded commitment.
     */
    function getRecoveryData(address account) external view returns (bytes memory) {
        return abi.encode(_commitments[account]);
    }

    /**
     * @notice Return the typed recovery EOA commitment for an account.
     * @param account The smart account.
     * @return The recovery EOA, or `address(0)` if not subscribed.
     */
    function commitment(address account) external view returns (address) {
        return _commitments[account];
    }

    /**
     * @notice Read the current replay-protection nonce for an account.
     * @param account The smart account.
     * @return The current nonce (the next value to be signed against).
     */
    function nonce(address account) external view returns (uint256) {
        return _nonces[account];
    }

    /**
     * @notice Compute the EIP-712 digest that the recovery EOA must sign to recover an account.
     * @dev Uses the account's current nonce. The returned digest is what a wallet should ask the
     *      recovery EOA to sign with personal_sign / EIP-712 typed-data signing.
     * @param account The smart account being recovered.
     * @param subject The recovery subject the signature will bind.
     * @return The EIP-712 digest to be signed.
     */
    function recoverDigest(address account, bytes calldata subject) external view returns (bytes32) {
        return _digest(account, _nonces[account], subject);
    }

    ////////////////////////////////////////////////////////////////////////
    // INTERNAL HELPERS
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Build the EIP-712 digest for a given (account, nonce, subject) tuple.
     */
    function _digest(address account, uint256 nonce_, bytes calldata subject) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(RECOVER_TYPEHASH, account, nonce_, keccak256(subject)));
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
