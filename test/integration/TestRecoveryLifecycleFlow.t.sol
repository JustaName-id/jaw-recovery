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
 * @title TestRecoveryLifecycleFlow
 *
 * @notice Integration test for the full recovery lifecycle against a real stack: a 7702-delegated
 * JustanAccount that has opted in by registering the manager as an owner, the real ECDSARecoveryProvider,
 * and a real ECDSA proof. Where the unit tests mock `verify` and the account and only assert the
 * `addOwner*` selector was called, these prove the new owner is genuinely registered on the account after
 * `addRecovery -> requestRecovery -> warp -> executeRecoveryRequest`.
 */
contract TestRecoveryLifecycleFlow is Test, PrepareRecovery {

    JustaRecoveryManager public manager;
    ECDSARecoveryProvider public provider;
    JustanAccount public justanAccountImpl;
    EntryPoint public entryPoint;

    function setUp() public {
        entryPoint = new EntryPoint();
        manager = new JustaRecoveryManager();
        provider = new ECDSARecoveryProvider();
        justanAccountImpl = new JustanAccount(address(entryPoint), address(0));

        vm.deal(TEST_ACCOUNT_ADDRESS, 10 ether);
        vm.signAndAttachDelegation(address(justanAccountImpl), TEST_ACCOUNT_PRIVATE_KEY);

        // Opt in: register the manager as an owner so it is authorized to add the recovered owner during
        // execution (MultiOwnable's owner-add is gated to owners/the account itself).
        vm.prank(TEST_ACCOUNT_ADDRESS);
        JustanAccount(TEST_ACCOUNT_ADDRESS).addOwnerAddress(address(manager));
    }

    /**
     * @notice Recovers an account to a new EOA owner end to end and proves the owner is really registered.
     * @dev addRecovery (ECDSA commitment) -> requestRecovery with a real signed proof (real provider.verify
     *      + real isOwnerBytes) -> warp past the delay -> executeRecoveryRequest -> the new EOA is an owner.
     */
    function test_ShouldRecoverWithEoaOwnerEndToEnd(
        address newOwner,
        uint256 recoveryEoaPk,
        uint32 delay,
        address recipient
    )
        public
    {
        address payable account = TEST_ACCOUNT_ADDRESS;

        // The recovered owner must not already be on the account.
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));

        // The capstone recipient must be a plain EOA: exclude precompiles/zero (<= 0xff, incl. Prague's BLS
        // precompiles) and any contract (the account holds the funds; other contracts may reject the ETH).
        vm.assume(uint160(recipient) > 0xff);
        vm.assume(recipient.code.length == 0);

        // Fuzz the committed recovery EOA via its signing key (vm.addr/vm.sign need a key in [1, n-1]).
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        // Register a single ECDSA recovery committing to `recoveryEoa`.
        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), delay);

        // The committed EOA signs a real proof over the account's current nonce and the new owner.
        bytes memory subject = encodeEoaSubject(newOwner);
        uint256 nonce = manager.recoveryNonce(account);
        bytes memory proof = signRecoverProof(provider, account, nonce, subject, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        // Queue the request, then fast-forward to its execution time and finalize.
        bytes32 requestId = manager.requestRecovery(account, subject, approvals);
        vm.warp(manager.recoveryRequest(requestId).executeAt);
        manager.executeRecoveryRequest(requestId);

        // The new EOA is now a real owner (manager + newOwner = 2) and the proof has been consumed.
        assertTrue(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 2);
        assertEq(manager.recoveryNonce(account), nonce + 1);

        // Confirm recovered owner can control the account with an ETH transfer.
        uint256 recipientBefore = recipient.balance;
        uint256 accountBefore = account.balance;
        vm.prank(newOwner);
        JustanAccount(account).execute(recipient, 1 ether, "");
        assertEq(recipient.balance, recipientBefore + 1 ether);
        assertEq(account.balance, accountBefore - 1 ether);
    }

    /**
     * @notice Recovers an account to a new passkey owner end to end and proves the owner is really registered.
     * @dev Same flow with a 64-byte passkey subject, exercising the `addOwnerPublicKey` branch.
     */
    function test_ShouldRecoverWithPasskeyOwnerEndToEnd(
        bytes32 x,
        bytes32 y,
        uint256 recoveryEoaPk,
        uint32 delay
    )
        public
    {
        address payable account = TEST_ACCOUNT_ADDRESS;

        // The recovered passkey must not already be on the account.
        vm.assume(!JustanAccount(account).isOwnerPublicKey(x, y));

        // Fuzz the committed recovery EOA via its signing key (vm.addr/vm.sign need a key in [1, n-1]).
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);

        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, address(provider), encodeEoaCommitment(recoveryEoa), delay);

        bytes memory subject = encodePasskeySubject(x, y);
        uint256 nonce = manager.recoveryNonce(account);
        bytes memory proof = signRecoverProof(provider, account, nonce, subject, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        bytes32 requestId = manager.requestRecovery(account, subject, approvals);
        vm.warp(manager.recoveryRequest(requestId).executeAt);
        manager.executeRecoveryRequest(requestId);

        // The new passkey is now a real owner (manager + passkey = 2) and the proof has been consumed.
        assertTrue(JustanAccount(account).isOwnerPublicKey(x, y));
        assertEq(JustanAccount(account).ownerCount(), 2);
        assertEq(manager.recoveryNonce(account), nonce + 1);
    }

}
