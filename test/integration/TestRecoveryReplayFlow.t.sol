// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { Test } from "forge-std/Test.sol";

import { JustanAccount } from "justanaccount/JustanAccount.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { ECDSARecoveryProvider } from "../../src/providers/ECDSARecoveryProvider.sol";

/**
 * @title TestRecoveryReplayFlow
 *
 * @notice Integration test for replay protection against a real stack and the real ECDSARecoveryProvider. A
 * successful `requestRecovery` consumes the account's nonce, so the same proof cannot be replayed: the real
 * provider rebuilds the EIP-712 digest over the bumped nonce, recovers a different signer, and rejects it.
 * This can only be proven across a real request that actually advances the nonce.
 */
contract TestRecoveryReplayFlow is Test, PrepareRecovery {

    JustaRecoveryManager public manager;
    ECDSARecoveryProvider public provider;
    JustanAccount public justanAccountImpl;
    EntryPoint public entryPoint;

    address payable internal account;

    function setUp() public {
        entryPoint = new EntryPoint();
        manager = new JustaRecoveryManager();
        provider = new ECDSARecoveryProvider();
        justanAccountImpl = new JustanAccount(address(entryPoint), address(0));
        account = TEST_ACCOUNT_ADDRESS;

        vm.deal(account, 10 ether);
        vm.signAndAttachDelegation(address(justanAccountImpl), TEST_ACCOUNT_PRIVATE_KEY);

        // Opt in: register the manager as an owner so it is authorized to add the recovered owner.
        vm.prank(account);
        JustanAccount(account).addOwnerAddress(address(manager));
    }

    /// @dev Runs one full instant (delay 0) recovery to `newOwner` via `recoveryId`, signing a fresh proof
    ///      over the account's current nonce with `recoveryEoaPk`.
    function _recoverTo(bytes32 recoveryId, uint256 recoveryEoaPk, address newOwner) private {
        bytes memory subject = encodeEoaSubject(newOwner);
        uint256 nonce = manager.recoveryNonce(account);
        bytes memory proof = signRecoverProof(provider, account, nonce, subject, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        bytes32 requestId = manager.requestRecovery(account, subject, approvals);
        manager.executeRecoveryRequest(requestId); // delay 0 -> executable immediately
    }

    /**
     * @notice A proof consumed by a successful request cannot be replayed once the nonce has advanced.
     * @dev The first request never executes, so the subject is still not an owner — proving the rejection is
     *      the nonce/replay defense firing (a stale-nonce digest recovers the wrong signer), not the
     *      already-owner fail-fast.
     */
    function test_ShouldRejectReplayedProofAfterNonceBump(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != address(manager));

        // Fuzz the committed recovery EOA via its signing key (vm.addr/vm.sign need a key in [1, n-1]).
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), delay);

        bytes memory subject = encodeEoaSubject(newOwner);
        uint256 nonce = manager.recoveryNonce(account);
        bytes memory proof = signRecoverProof(provider, account, nonce, subject, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        // A successful request consumes the nonce (0 -> 1), making the proof single-use.
        manager.requestRecovery(account, subject, approvals);
        assertEq(manager.recoveryNonce(account), nonce + 1);

        // Replaying the very same proof now fails against the bumped nonce.
        vm.expectRevert(ECDSARecoveryProvider.ECDSARecoveryProvider_InvalidSignature.selector);
        manager.requestRecovery(account, subject, approvals);
    }

    /**
     * @notice The same registered recovery can recover the account more than once: each request consumes the
     *         nonce, and a fresh proof over the advanced nonce authorizes the next recovery.
     * @dev The nonce makes each proof single-use, not the recovery one-shot — a user may recover repeatedly
     *      over the account's life (e.g. losing keys more than once).
     */
    function test_ShouldAllowSequentialRecoveriesWithFreshProofs(
        address owner1,
        address owner2,
        uint256 recoveryEoaPk
    )
        public
    {
        vm.assume(owner1 != address(0) && owner1 != account && owner1 != address(manager));
        vm.assume(owner2 != address(0) && owner2 != account && owner2 != address(manager));
        vm.assume(owner1 != owner2);
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        // One registered recovery (delay 0) backs both recoveries.
        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), 0);

        // First recovery: fresh proof over nonce 0.
        _recoverTo(recoveryId, recoveryEoaPk, owner1);
        assertTrue(JustanAccount(account).isOwnerAddress(owner1));
        assertEq(manager.recoveryNonce(account), 1);

        // Second recovery: same recovery, fresh proof over the advanced nonce.
        _recoverTo(recoveryId, recoveryEoaPk, owner2);
        assertTrue(JustanAccount(account).isOwnerAddress(owner2));
        assertEq(manager.recoveryNonce(account), 2);

        // Both recovered owners coexist alongside the manager.
        assertEq(JustanAccount(account).ownerCount(), 3);
    }

}
