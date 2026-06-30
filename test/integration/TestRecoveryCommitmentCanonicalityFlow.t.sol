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
 * @title TestRecoveryCommitmentCanonicalityFlow
 *
 * @notice Integration test for the ECDSA provider's commitment-canonicality defense against a real stack.
 * The manager keys recoveries by `keccak256(account, provider, commitment)` over the raw commitment bytes and
 * only rejects an empty commitment, so a non-canonical encoding of an EOA (the canonical 32-byte
 * `abi.encode(eoa)` with a trailing byte appended) registers as a *distinct* recovery. `abi.decode` ignores
 * the trailing byte, so both commitments name the same signer — without a guard, one signature could satisfy
 * two approvals and silently weaken an M-of-N threshold. The provider's `commitment.length != 32` check
 * blocks this: the non-canonical recovery is a dead slot that always reverts at verify, so the bypass fails.
 */
contract TestRecoveryCommitmentCanonicalityFlow is Test, PrepareRecovery {

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

    /**
     * @notice A non-canonical commitment (the 32-byte EOA encoding with a trailing byte) registers as a
     *         distinct recovery: the manager keys by raw commitment bytes and only rejects an empty one.
     * @dev Documents the accepted residual — the manager admits the dead slot at registration; the provider
     *      is what rejects it at verify (covered below). Both commitments `abi.decode` to the same signer.
     */
    function test_ShouldRegisterNonCanonicalCommitmentAsDistinctRecovery(address eoa, uint32 delay) public {
        vm.assume(eoa != address(0));

        bytes memory canonical = encodeEoaCommitment(eoa); // 32 bytes
        bytes memory nonCanonical = bytes.concat(canonical, hex"00"); // 33 bytes, still decodes to `eoa`

        vm.prank(account);
        bytes32 canonicalId = manager.addRecovery(account, address(provider), canonical, delay);
        vm.prank(account);
        bytes32 nonCanonicalId = manager.addRecovery(account, address(provider), nonCanonical, delay);

        // Same signer, but two distinct recoveries are registered side by side.
        assertTrue(canonicalId != nonCanonicalId);
        assertEq(manager.recoveryCount(account), 2);
        assertTrue(manager.hasRecovery(account, canonicalId));
        assertTrue(manager.hasRecovery(account, nonCanonicalId));
    }

    /**
     * @notice One signature cannot satisfy a 2-of-2 across a canonical and a non-canonical commitment of the
     *         same signer: the non-canonical slot reverts at verify, so the whole request reverts.
     * @dev The threshold bypass the canonicality guard exists to prevent. The account registers the same EOA
     *      twice (canonical + trailing-byte) — two distinct recoveryIds, so the manager's distinctness check
     *      is satisfied — sets threshold 2, and submits one valid signature for both slots. The provider
     *      rejects the non-canonical commitment before the signature is even checked, so nothing is queued.
     */
    function test_ShouldRejectThresholdBypassViaNonCanonicalCommitment(
        address newOwner,
        uint256 recoveryEoaPk
    )
        public
    {
        vm.assume(newOwner != address(0) && newOwner != account && newOwner != address(manager));
        recoveryEoaPk = bound(recoveryEoaPk, 1, SECP256K1_CURVE_ORDER - 1);
        address recoveryEoa = vm.addr(recoveryEoaPk);
        // Committed signer must be a code-free EOA so the canonical slot reaches verify via the ECDSA path:
        // a signer with code takes the ERC-1271 path and would revert InvalidSignature, not InvalidCommitment.
        vm.assume(recoveryEoa.code.length == 0);

        bytes memory canonical = encodeEoaCommitment(recoveryEoa);
        bytes memory nonCanonical = bytes.concat(canonical, hex"00");

        vm.prank(account);
        bytes32 canonicalId = manager.addRecovery(account, address(provider), canonical, 0);
        vm.prank(account);
        bytes32 nonCanonicalId = manager.addRecovery(account, address(provider), nonCanonical, 0);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        bytes memory subject = encodeEoaSubject(newOwner);
        uint256 nonce = manager.recoveryNonce(account);

        // The attacker holds one valid signature from `recoveryEoa` and reuses it for both slots.
        bytes memory proof = signRecoverProof(provider, account, nonce, subject, recoveryEoaPk);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = createApproval(canonicalId, proof);
        approvals[1] = createApproval(nonCanonicalId, proof);

        // The non-canonical slot reverts at verify (length != 32) before the signature is checked, so the
        // entire request reverts and nothing is queued.
        vm.expectRevert(ECDSARecoveryProvider.ECDSARecoveryProvider_InvalidCommitment.selector);
        manager.requestRecovery(account, subject, approvals);

        assertEq(manager.recoveryNonce(account), nonce);
        assertEq(manager.recoveryRequest(keccak256(abi.encode(account, subject, nonce))).account, address(0));
    }

}
