// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Test } from "forge-std/Test.sol";

import { MultiOwnable } from "justanaccount/MultiOwnable.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { IRecoveryProvider } from "../../src/interfaces/IRecoveryProvider.sol";

contract TestManagerWriteFunctions is Test, PrepareRecovery {

    JustaRecoveryManager public manager;

    function setUp() public {
        manager = new JustaRecoveryManager();
    }

    /// @dev Etches `target` with non-empty code so external calls into it pass the contract/extcodesize
    ///      check. Excludes the zero address and precompiles (`vm.etch` rejects precompiles; Prague's reach
    ///      up to 0x11) and the addresses whose code the test relies on (the manager, the test contract, the
    ///      VM), so a fuzzer landing on one is discarded rather than erroring or clobbering it.
    function _etchCode(address target) private {
        vm.assume(uint160(target) > 0xff);
        vm.assume(target != address(manager));
        vm.assume(target != address(this));
        vm.assume(target != address(vm));
        vm.etch(target, hex"00");
    }

    /// @dev Registers a recovery for `account` against a freshly-etched `provider`, pranked as the account.
    ///      Stubs the account as having the manager registered as an owner (the opt-in `addRecovery` now
    ///      requires), since callers of this helper are testing something other than that check.
    function _addRecovery(
        address account,
        address provider,
        bytes memory commitment,
        uint32 delay
    )
        private
        returns (bytes32 recoveryId)
    {
        _etchCode(provider);
        _stubManagerOwner(account, true);
        vm.prank(account);
        return manager.addRecovery(account, provider, commitment, delay);
    }

    /// @dev Stubs `verify` on `provider` to accept (return). Reachable only after the provider is etched.
    function _acceptVerify(address provider) private {
        vm.mockCall(provider, abi.encodeWithSelector(IRecoveryProvider.verify.selector), "");
    }

    /// @dev Etches `account` (so the `isOwnerAddress` call's extcodesize check passes) and stubs that call to
    ///      return `isManagerOwner`, i.e. whether the recovery manager is registered as an owner of `account`.
    function _stubManagerOwner(address account, bool isManagerOwner) private {
        _etchCode(account);
        vm.mockCall(account, abi.encodeWithSelector(MultiOwnable.isOwnerAddress.selector), abi.encode(isManagerOwner));
    }

    /// @dev Etches `account` (so the `isOwnerBytes`/`isOwnerAddress` calls' extcodesize checks pass), stubs
    ///      `isOwnerBytes` to return `isOwner`, and stubs the manager as registered as an owner (true) so the
    ///      `requestRecovery` opt-in check passes by default.
    function _stubAccount(address account, bool isOwner) private {
        _stubManagerOwner(account, true);
        vm.mockCall(account, abi.encodeWithSelector(MultiOwnable.isOwnerBytes.selector), abi.encode(isOwner));
    }

    /// @dev Registers one recovery and queues an accepted recovery request for `account` to take ownership
    ///      of `subject`, returning the request id. The account is stubbed as a non-owner and the provider's
    ///      verify is stubbed to accept.
    function _queueRequest(
        address account,
        address provider,
        bytes memory subject,
        uint32 delay
    )
        private
        returns (bytes32 requestId)
    {
        bytes32 recoveryId = _addRecovery(account, provider, hex"01", delay);
        _stubAccount(account, false);
        _acceptVerify(provider);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        return manager.requestRecovery(account, subject, approvals);
    }

    /*//////////////////////////////////////////////////////////////
                            addRecovery() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AddRecovery_RevertIfNotAccount(
        address account,
        address caller,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(caller != account);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_NotAccount.selector, caller, account)
        );

        vm.prank(caller);
        manager.addRecovery(account, provider, commitment, delay);
    }

    function test_AddRecovery_RevertIfZeroProvider(address account, bytes calldata commitment, uint32 delay) public {
        vm.expectRevert(IRecoveryManager.JustaRecoveryManager_ZeroProvider.selector);

        vm.prank(account);
        manager.addRecovery(account, address(0), commitment, delay);
    }

    function test_AddRecovery_RevertIfProviderNotContract(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(provider != address(0));
        vm.assume(provider.code.length == 0);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_ProviderNotContract.selector, provider)
        );

        vm.prank(account);
        manager.addRecovery(account, provider, commitment, delay);
    }

    function test_AddRecovery_RevertIfEmptyCommitment(address account, address provider, uint32 delay) public {
        _etchCode(provider);

        vm.expectRevert(IRecoveryManager.JustaRecoveryManager_EmptyCommitment.selector);

        vm.prank(account);
        manager.addRecovery(account, provider, "", delay);
    }

    function test_AddRecovery_RevertIfAlreadyAdded(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(commitment.length != 0);
        _etchCode(provider);
        _stubManagerOwner(account, true);

        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, provider, commitment, delay);

        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.JustaRecoveryManager_RecoveryAlreadyAdded.selector, account, recoveryId
            )
        );

        vm.prank(account);
        manager.addRecovery(account, provider, commitment, delay);
    }

    function test_AddRecovery_ShouldRegisterAndEmit(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(commitment.length != 0);
        _etchCode(provider);
        _stubManagerOwner(account, true);

        bytes32 expectedId = keccak256(abi.encode(account, provider, commitment));

        vm.expectEmit(true, true, false, true, address(manager));
        emit IRecoveryManager.RecoveryAdded(account, delay, expectedId);

        vm.prank(account);
        bytes32 recoveryId = manager.addRecovery(account, provider, commitment, delay);

        assertEq(recoveryId, expectedId);
        assertTrue(manager.hasRecovery(account, recoveryId));
        assertEq(manager.recoveryCount(account), 1);

        IRecoveryManager.Recovery memory recovery = manager.getRecovery(account, recoveryId);
        assertEq(recovery.provider, provider);
        assertEq(recovery.commitment, commitment);
        assertEq(recovery.delay, delay);
    }

    function test_AddRecovery_ShouldAllowSameProviderDifferentCommitments(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint32 delay1,
        uint32 delay2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));
        _etchCode(provider);
        _stubManagerOwner(account, true);

        vm.prank(account);
        bytes32 recoveryId1 = manager.addRecovery(account, provider, commitment1, delay1);

        vm.prank(account);
        bytes32 recoveryId2 = manager.addRecovery(account, provider, commitment2, delay2);

        assertTrue(recoveryId1 != recoveryId2);
        assertEq(manager.recoveryCount(account), 2);
        assertTrue(manager.hasRecovery(account, recoveryId1));
        assertTrue(manager.hasRecovery(account, recoveryId2));
    }

    function test_AddRecovery_RevertIfManagerNotAccountOwner(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(commitment.length != 0);
        _etchCode(provider);
        _stubManagerOwner(account, false);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_ManagerNotAccountOwner.selector, account)
        );

        vm.prank(account);
        manager.addRecovery(account, provider, commitment, delay);
    }

    /*//////////////////////////////////////////////////////////////
                          removeRecovery() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RemoveRecovery_RevertIfNotAccount(address account, address caller, bytes32 recoveryId) public {
        vm.assume(caller != account);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_NotAccount.selector, caller, account)
        );

        vm.prank(caller);
        manager.removeRecovery(account, recoveryId);
    }

    function test_RemoveRecovery_RevertIfNotRegistered(address account, bytes32 recoveryId) public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.JustaRecoveryManager_RecoveryNotRegistered.selector, account, recoveryId
            )
        );

        vm.prank(account);
        manager.removeRecovery(account, recoveryId);
    }

    function test_RemoveRecovery_RevertIfBelowThreshold(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        bytes32 recoveryId1 = _addRecovery(account, provider, commitment1, 0);
        _addRecovery(account, provider, commitment2, 0);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        // Removing one would drop the count to 1, below the threshold of 2.
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RemovalBelowThreshold.selector, 1, 2)
        );

        vm.prank(account);
        manager.removeRecovery(account, recoveryId1);
    }

    function test_RemoveRecovery_ShouldRemoveAndEmit(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint32 delay1,
        uint32 delay2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        // Two recoveries under the default threshold of 1: removing one leaves the other (count 1 >= 1).
        bytes32 recoveryId1 = _addRecovery(account, provider, commitment1, delay1);
        bytes32 recoveryId2 = _addRecovery(account, provider, commitment2, delay2);

        vm.expectEmit(true, true, false, false, address(manager));
        emit IRecoveryManager.RecoveryRemoved(account, recoveryId1);

        vm.prank(account);
        manager.removeRecovery(account, recoveryId1);

        // The removed recovery is gone; the other survives.
        assertFalse(manager.hasRecovery(account, recoveryId1));
        assertEq(manager.getRecovery(account, recoveryId1).provider, address(0));
        assertTrue(manager.hasRecovery(account, recoveryId2));
        assertEq(manager.recoveryCount(account), 1);
    }

    function test_RemoveRecovery_ShouldAllowFullOptOut(
        address account,
        address provider,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(commitment.length != 0);

        // A single recovery under the default threshold of 1: removing the last one (count -> 0) is allowed.
        bytes32 recoveryId = _addRecovery(account, provider, commitment, delay);

        vm.prank(account);
        manager.removeRecovery(account, recoveryId);

        assertEq(manager.recoveryCount(account), 0);
    }

    function test_RemoveRecovery_ShouldSucceedIfManagerNotAccountOwner(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        bytes32 recoveryId1 = _addRecovery(account, provider, commitment1, 0);
        bytes32 recoveryId2 = _addRecovery(account, provider, commitment2, 0);

        // The manager was removed as an owner after setup (e.g. the account opted out): teardown must still
        // work, or the account would be stuck with recoveries it can never remove.
        _stubManagerOwner(account, false);

        vm.prank(account);
        manager.removeRecovery(account, recoveryId1);
        assertEq(manager.recoveryCount(account), 1);

        vm.prank(account);
        manager.removeRecovery(account, recoveryId2);
        assertEq(manager.recoveryCount(account), 0);
    }

    /*//////////////////////////////////////////////////////////////
                       setRecoveryThreshold() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetRecoveryThreshold_RevertIfNotAccount(address account, address caller, uint256 threshold) public {
        vm.assume(caller != account);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_NotAccount.selector, caller, account)
        );

        vm.prank(caller);
        manager.setRecoveryThreshold(account, threshold);
    }

    function test_SetRecoveryThreshold_RevertIfZero(
        address account,
        address provider,
        bytes calldata commitment
    )
        public
    {
        vm.assume(commitment.length != 0);

        _addRecovery(account, provider, commitment, 0);

        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidThreshold.selector, 0, 1));

        vm.prank(account);
        manager.setRecoveryThreshold(account, 0);
    }

    function test_SetRecoveryThreshold_RevertIfAboveCount(
        address account,
        address provider,
        bytes calldata commitment,
        uint256 threshold
    )
        public
    {
        vm.assume(commitment.length != 0);
        vm.assume(threshold > 1);

        _addRecovery(account, provider, commitment, 0);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidThreshold.selector, threshold, 1)
        );

        vm.prank(account);
        manager.setRecoveryThreshold(account, threshold);
    }

    function test_SetRecoveryThreshold_ShouldSetAndEmit(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint256 threshold
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        _addRecovery(account, provider, commitment1, 0);
        _addRecovery(account, provider, commitment2, 0);

        // Valid threshold range is [1, recoveryCount] = [1, 2]; default (old) threshold is 1.
        threshold = bound(threshold, 1, 2);

        vm.expectEmit(true, false, false, true, address(manager));
        emit IRecoveryManager.RecoveryThresholdChanged(account, 1, threshold);

        vm.prank(account);
        manager.setRecoveryThreshold(account, threshold);

        assertEq(manager.recoveryThreshold(account), threshold);
    }

    function test_SetRecoveryThreshold_ShouldSucceedIfManagerNotAccountOwner(
        address account,
        address provider,
        bytes calldata commitment1,
        bytes calldata commitment2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        _addRecovery(account, provider, commitment1, 0);
        _addRecovery(account, provider, commitment2, 0);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        // The manager was removed as an owner after setup (e.g. the account opted out): lowering the
        // threshold must stay possible, or `removeRecovery`'s below-threshold guard would make stale
        // recoveries permanently impossible to clean up.
        _stubManagerOwner(account, false);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 1);

        assertEq(manager.recoveryThreshold(account), 1);
    }

    /*//////////////////////////////////////////////////////////////
                          requestRecovery() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RequestRecovery_RevertIfInvalidApprovalCount(
        address account,
        bytes calldata subject,
        uint8 count
    )
        public
    {
        // The effective threshold defaults to 1; any other approval count is rejected before anything else.
        vm.assume(count != 1);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](count);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidApprovalCount.selector, count, 1)
        );
        manager.requestRecovery(account, subject, approvals);
    }

    function test_RequestRecovery_RevertIfInvalidSubjectLength(address account, bytes calldata subject) public {
        vm.assume(subject.length != 32 && subject.length != 64);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidSubjectLength.selector, subject.length)
        );
        manager.requestRecovery(account, subject, approvals);
    }

    function test_RequestRecovery_RevertIfInvalidSubject(address account, uint256 dirtySubject) public {
        // A 32-byte subject whose upper bits do not fit in an address.
        vm.assume(dirtySubject > type(uint160).max);
        bytes memory subject = abi.encode(dirtySubject);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);

        vm.expectRevert(abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_InvalidSubject.selector, subject));
        manager.requestRecovery(account, subject, approvals);
    }

    function test_RequestRecovery_RevertIfSubjectAlreadyOwner(address account, address newOwner) public {
        bytes memory subject = encodeEoaSubject(newOwner);
        _stubAccount(account, true);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_SubjectAlreadyOwner.selector, subject)
        );
        manager.requestRecovery(account, subject, approvals);
    }

    function test_RequestRecovery_RevertIfManagerNotAccountOwner(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment
    )
        public
    {
        vm.assume(commitment.length != 0);

        // Otherwise-fully-valid setup: a registered recovery, the correct approval count, and an accepting
        // provider — the manager opt-in check is the only reason this reverts.
        bytes32 recoveryId = _addRecovery(account, provider, commitment, 0);
        _stubAccount(account, false);
        _stubManagerOwner(account, false);
        _acceptVerify(provider);

        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_ManagerNotAccountOwner.selector, account)
        );
        manager.requestRecovery(account, subject, approvals);

        // The proof was not consumed: the nonce never bumped.
        assertEq(manager.recoveryNonce(account), 0);
    }

    function test_RequestRecovery_RevertIfRecoveryNotRegistered(
        address account,
        address newOwner,
        bytes32 recoveryId
    )
        public
    {
        bytes memory subject = encodeEoaSubject(newOwner);
        _stubAccount(account, false);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        vm.expectRevert(
            abi.encodeWithSelector(
                IRecoveryManager.JustaRecoveryManager_RecoveryNotRegistered.selector, account, recoveryId
            )
        );
        manager.requestRecovery(account, subject, approvals);
    }

    function test_RequestRecovery_RevertIfDuplicateRecovery(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment1,
        bytes calldata commitment2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        bytes32 recoveryId1 = _addRecovery(account, provider, commitment1, 0);
        _addRecovery(account, provider, commitment2, 0);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        _stubAccount(account, false);
        _acceptVerify(provider);

        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = createApproval(recoveryId1, "");
        approvals[1] = createApproval(recoveryId1, "");

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_DuplicateRecovery.selector, recoveryId1)
        );
        manager.requestRecovery(account, subject, approvals);
    }

    function test_RequestRecovery_RevertIfProofRejected(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment
    )
        public
    {
        vm.assume(commitment.length != 0);

        bytes32 recoveryId = _addRecovery(account, provider, commitment, 0);
        _stubAccount(account, false);

        // The provider rejects the proof; its revert must bubble up unchanged.
        bytes memory rejection = abi.encodeWithSignature("ProofRejected()");
        vm.mockCallRevert(provider, abi.encodeWithSelector(IRecoveryProvider.verify.selector), rejection);

        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        vm.expectRevert(rejection);
        manager.requestRecovery(account, subject, approvals);
    }

    function test_RequestRecovery_ShouldUseMaxDelay(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint32 delay1,
        uint32 delay2
    )
        public
    {
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        bytes32 recoveryId1 = _addRecovery(account, provider, commitment1, delay1);
        bytes32 recoveryId2 = _addRecovery(account, provider, commitment2, delay2);

        vm.prank(account);
        manager.setRecoveryThreshold(account, 2);

        _stubAccount(account, false);
        _acceptVerify(provider);

        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](2);
        approvals[0] = createApproval(recoveryId1, "");
        approvals[1] = createApproval(recoveryId2, "");

        uint256 maxDelay = delay1 > delay2 ? delay1 : delay2;

        bytes32 requestId = manager.requestRecovery(account, subject, approvals);

        assertEq(manager.recoveryRequest(requestId).executeAt, uint64(block.timestamp + maxDelay));
    }

    function test_RequestRecovery_ShouldIncrementNonce(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment
    )
        public
    {
        vm.assume(commitment.length != 0);

        bytes32 recoveryId = _addRecovery(account, provider, commitment, 0);
        _stubAccount(account, false);
        _acceptVerify(provider);

        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        assertEq(manager.recoveryNonce(account), 0);
        manager.requestRecovery(account, subject, approvals);
        assertEq(manager.recoveryNonce(account), 1);
    }

    function test_RequestRecovery_ShouldQueueEoaSubjectAndEmit(
        address account,
        address provider,
        address newOwner,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(commitment.length != 0);

        bytes32 recoveryId = _addRecovery(account, provider, commitment, delay);
        _stubAccount(account, false);
        _acceptVerify(provider);

        bytes memory subject = encodeEoaSubject(newOwner);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        bytes32[] memory expectedIds = new bytes32[](1);
        expectedIds[0] = recoveryId;
        bytes32 expectedRequestId = keccak256(abi.encode(account, subject, uint256(0)));
        uint64 expectedExecuteAt = uint64(block.timestamp + delay);

        vm.expectEmit(true, true, false, true, address(manager));
        emit IRecoveryManager.RecoveryRequested(account, expectedRequestId, expectedIds, subject, expectedExecuteAt);

        bytes32 requestId = manager.requestRecovery(account, subject, approvals);

        assertEq(requestId, expectedRequestId);

        IRecoveryManager.RecoveryRequest memory request = manager.recoveryRequest(requestId);
        assertEq(request.account, account);
        assertEq(request.executeAt, expectedExecuteAt);
        assertEq(request.subject, subject);
    }

    function test_RequestRecovery_ShouldQueuePasskeySubject(
        address account,
        address provider,
        bytes32 x,
        bytes32 y,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(commitment.length != 0);

        bytes32 recoveryId = _addRecovery(account, provider, commitment, delay);
        _stubAccount(account, false);
        _acceptVerify(provider);

        bytes memory subject = encodePasskeySubject(x, y);
        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        bytes32 requestId = manager.requestRecovery(account, subject, approvals);

        IRecoveryManager.RecoveryRequest memory request = manager.recoveryRequest(requestId);
        assertEq(request.subject, subject);
        assertEq(request.subject.length, 64);
    }

    function test_RequestRecovery_ShouldSupportMultipleSimultaneousRequests(
        address account,
        address provider,
        address ownerA,
        address ownerB,
        uint32 delay
    )
        public
    {
        vm.assume(ownerA != ownerB);

        // A single registered recovery backs both requests; the account is a non-owner and verify accepts.
        bytes32 recoveryId = _addRecovery(account, provider, hex"01", delay);
        _stubAccount(account, false);
        _acceptVerify(provider);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, "");

        bytes memory subjectA = encodeEoaSubject(ownerA);
        bytes memory subjectB = encodeEoaSubject(ownerB);

        // Queue request A over nonce 0, then request B over the bumped nonce 1: both coexist under distinct
        // ids (requestId binds the nonce, which advances between them).
        bytes32 requestIdA = manager.requestRecovery(account, subjectA, approvals);
        bytes32 requestIdB = manager.requestRecovery(account, subjectB, approvals);

        assertTrue(requestIdA != requestIdB);
        assertEq(manager.recoveryRequest(requestIdA).subject, subjectA);
        assertEq(manager.recoveryRequest(requestIdB).subject, subjectB);
        assertEq(manager.recoveryNonce(account), 2);

        // Execute A: only request A is consumed; request B stays pending and independently executable.
        vm.warp(manager.recoveryRequest(requestIdA).executeAt);
        vm.mockCall(account, abi.encodeWithSelector(MultiOwnable.addOwnerAddress.selector), "");
        vm.expectCall(account, abi.encodeCall(MultiOwnable.addOwnerAddress, (ownerA)));
        manager.executeRecoveryRequest(requestIdA);
        assertEq(manager.recoveryRequest(requestIdA).account, address(0));
        assertEq(manager.recoveryRequest(requestIdB).account, account);

        // Cancel B: consumed independently, with request A already gone.
        vm.prank(account);
        manager.cancelRecoveryRequest(requestIdB);
        assertEq(manager.recoveryRequest(requestIdB).account, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                      executeRecoveryRequest() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ExecuteRecoveryRequest_RevertIfNotPending(bytes32 requestId) public {
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotPending.selector, requestId)
        );
        manager.executeRecoveryRequest(requestId);
    }

    function test_ExecuteRecoveryRequest_RevertIfNotReady(
        address account,
        address provider,
        address newOwner,
        uint32 delay
    )
        public
    {
        vm.assume(delay > 0);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 requestId = _queueRequest(account, provider, subject, delay);

        uint64 executeAt = manager.recoveryRequest(requestId).executeAt;

        // Still before `executeAt` (no warp).
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotReady.selector, requestId, executeAt)
        );
        manager.executeRecoveryRequest(requestId);
    }

    function test_ExecuteRecoveryRequest_ShouldAddEoaOwnerAndEmit(
        address account,
        address provider,
        address newOwner,
        uint32 delay
    )
        public
    {
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 requestId = _queueRequest(account, provider, subject, delay);

        vm.warp(manager.recoveryRequest(requestId).executeAt);

        vm.mockCall(account, abi.encodeWithSelector(MultiOwnable.addOwnerAddress.selector), "");

        vm.expectCall(account, abi.encodeCall(MultiOwnable.addOwnerAddress, (newOwner)));
        vm.expectEmit(true, true, false, true, address(manager));
        emit IRecoveryManager.RecoveryRequestExecuted(account, requestId, subject);

        manager.executeRecoveryRequest(requestId);

        // The pending entry is consumed.
        assertEq(manager.recoveryRequest(requestId).account, address(0));
    }

    function test_ExecuteRecoveryRequest_ShouldAddPasskeyOwnerAndEmit(
        address account,
        address provider,
        bytes32 x,
        bytes32 y,
        uint32 delay
    )
        public
    {
        bytes memory subject = encodePasskeySubject(x, y);
        bytes32 requestId = _queueRequest(account, provider, subject, delay);

        vm.warp(manager.recoveryRequest(requestId).executeAt);

        vm.mockCall(account, abi.encodeWithSelector(MultiOwnable.addOwnerPublicKey.selector), "");

        vm.expectCall(account, abi.encodeCall(MultiOwnable.addOwnerPublicKey, (x, y)));
        vm.expectEmit(true, true, false, true, address(manager));
        emit IRecoveryManager.RecoveryRequestExecuted(account, requestId, subject);

        manager.executeRecoveryRequest(requestId);

        assertEq(manager.recoveryRequest(requestId).account, address(0));
    }

    function test_ExecuteRecoveryRequest_ShouldKeepRequestIfOwnerAddReverts(
        address account,
        address provider,
        address newOwner,
        uint32 delay
    )
        public
    {
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 requestId = _queueRequest(account, provider, subject, delay);

        vm.warp(manager.recoveryRequest(requestId).executeAt);

        bytes memory addOwnerSel = abi.encodeWithSelector(MultiOwnable.addOwnerAddress.selector);

        // The account rejects the owner-add; the manager does not catch it, so the whole tx reverts and the
        // CEI delete is rolled back, leaving the request executable.
        bytes memory accountRevert = abi.encodeWithSelector(MultiOwnable.MultiOwnable_AlreadyOwner.selector, subject);
        vm.mockCallRevert(account, addOwnerSel, accountRevert);

        vm.expectRevert(accountRevert);
        manager.executeRecoveryRequest(requestId);

        // The request survived the failed execution.
        assertEq(manager.recoveryRequest(requestId).account, account);

        // A later successful execution consumes it.
        vm.mockCall(account, addOwnerSel, "");
        manager.executeRecoveryRequest(requestId);
        assertEq(manager.recoveryRequest(requestId).account, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       cancelRecoveryRequest() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CancelRecoveryRequest_RevertIfNotPending(address caller, bytes32 requestId) public {
        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_RequestNotPending.selector, requestId)
        );
        vm.prank(caller);
        manager.cancelRecoveryRequest(requestId);
    }

    function test_CancelRecoveryRequest_RevertIfNotAccount(
        address account,
        address provider,
        address caller,
        address newOwner,
        uint32 delay
    )
        public
    {
        vm.assume(caller != account);

        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 requestId = _queueRequest(account, provider, subject, delay);

        vm.expectRevert(
            abi.encodeWithSelector(IRecoveryManager.JustaRecoveryManager_NotAccount.selector, caller, account)
        );
        vm.prank(caller);
        manager.cancelRecoveryRequest(requestId);
    }

    function test_CancelRecoveryRequest_ShouldCancelAndEmit(
        address account,
        address provider,
        address newOwner,
        uint32 delay
    )
        public
    {
        bytes memory subject = encodeEoaSubject(newOwner);
        bytes32 requestId = _queueRequest(account, provider, subject, delay);

        vm.expectEmit(true, true, false, false, address(manager));
        emit IRecoveryManager.RecoveryRequestCancelled(account, requestId);

        vm.prank(account);
        manager.cancelRecoveryRequest(requestId);

        assertEq(manager.recoveryRequest(requestId).account, address(0));
    }

}
