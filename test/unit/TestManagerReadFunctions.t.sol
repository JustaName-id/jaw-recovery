// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Test } from "forge-std/Test.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { JustaRecoveryManager } from "../../src/JustaRecoveryManager.sol";
import { IRecoveryManager } from "../../src/interfaces/IRecoveryManager.sol";
import { ECDSARecoveryProvider } from "../../src/providers/ECDSARecoveryProvider.sol";

// TODO: Test nonce incrementation with requestRecovery
// TODO: Test recoveryRequest return value
contract TestManagerReadFunctions is Test, PrepareRecovery {

    JustaRecoveryManager public manager;
    ECDSARecoveryProvider public provider;

    function setUp() public {
        manager = new JustaRecoveryManager();
        provider = new ECDSARecoveryProvider();
    }

    /// @dev Registers a recovery for `account` (pranked as the registrant) against the deployed provider.
    function _addRecovery(address account, bytes memory commitment, uint32 delay) private returns (bytes32 recoveryId) {
        vm.prank(account);
        return manager.addRecovery(account, address(provider), commitment, delay);
    }

    /*//////////////////////////////////////////////////////////////
                        computeRecoveryId() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ComputeRecoveryId_ShouldMatchExpectedHash(
        address account,
        address provider_,
        bytes calldata commitment
    )
        public
        view
    {
        assertEq(
            manager.computeRecoveryId(account, provider_, commitment),
            keccak256(abi.encode(account, provider_, commitment))
        );
    }

    /*//////////////////////////////////////////////////////////////
                            hasRecovery() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_HasRecovery_ShouldReturnFalseForUnregistered(address account, bytes32 recoveryId) public view {
        assertFalse(manager.hasRecovery(account, recoveryId));
    }

    function test_HasRecovery_ShouldReturnTrueForRegistered(
        address account,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(account != address(0));
        vm.assume(commitment.length != 0);

        bytes32 recoveryId = _addRecovery(account, commitment, delay);

        assertTrue(manager.hasRecovery(account, recoveryId));
    }

    /*//////////////////////////////////////////////////////////////
                            getRecoveries() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetRecoveries_ShouldReturnEmptyWhenNoneRegistered(address account) public view {
        assertEq(manager.getRecoveries(account).length, 0);
    }

    function test_GetRecoveries_ShouldReturnRegisteredRecoveries(
        address account,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint32 delay1,
        uint32 delay2
    )
        public
    {
        vm.assume(account != address(0));
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        _addRecovery(account, commitment1, delay1);
        _addRecovery(account, commitment2, delay2);

        IRecoveryManager.Recovery[] memory recoveries = manager.getRecoveries(account);

        // EnumerableSet preserves insertion order with no removals.
        assertEq(recoveries.length, 2);
        assertEq(recoveries[0].provider, address(provider));
        assertEq(recoveries[0].commitment, commitment1);
        assertEq(recoveries[0].delay, delay1);
        assertEq(recoveries[1].provider, address(provider));
        assertEq(recoveries[1].commitment, commitment2);
        assertEq(recoveries[1].delay, delay2);
    }

    /*//////////////////////////////////////////////////////////////
                            getRecovery() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetRecovery_ShouldReturnZeroedForUnregistered(address account, bytes32 recoveryId) public view {
        IRecoveryManager.Recovery memory recovery = manager.getRecovery(account, recoveryId);

        assertEq(recovery.provider, address(0));
        assertEq(recovery.commitment.length, 0);
        assertEq(recovery.delay, 0);
    }

    function test_GetRecovery_ShouldReturnRegisteredRecovery(
        address account,
        bytes calldata commitment,
        uint32 delay
    )
        public
    {
        vm.assume(account != address(0));
        vm.assume(commitment.length != 0);

        bytes32 recoveryId = _addRecovery(account, commitment, delay);

        IRecoveryManager.Recovery memory recovery = manager.getRecovery(account, recoveryId);

        assertEq(recovery.provider, address(provider));
        assertEq(recovery.commitment, commitment);
        assertEq(recovery.delay, delay);
    }

    /*//////////////////////////////////////////////////////////////
                            recoveryCount() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoveryCount_ShouldBeZeroInitially(address account) public view {
        assertEq(manager.recoveryCount(account), 0);
    }

    function test_RecoveryCount_ShouldReflectRegistrations(
        address account,
        bytes calldata commitment1,
        bytes calldata commitment2
    )
        public
    {
        vm.assume(account != address(0));
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        _addRecovery(account, commitment1, 0);
        assertEq(manager.recoveryCount(account), 1);

        _addRecovery(account, commitment2, 0);
        assertEq(manager.recoveryCount(account), 2);
    }

    /*//////////////////////////////////////////////////////////////
                        recoveryThreshold() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoveryThreshold_ShouldDefaultToOne(address account) public view {
        assertEq(manager.recoveryThreshold(account), 1);
    }

    function test_RecoveryThreshold_ShouldReflectSetValue(
        address account,
        bytes calldata commitment1,
        bytes calldata commitment2,
        uint256 threshold
    )
        public
    {
        vm.assume(account != address(0));
        vm.assume(commitment1.length != 0 && commitment2.length != 0);
        vm.assume(keccak256(commitment1) != keccak256(commitment2));

        _addRecovery(account, commitment1, 0);
        _addRecovery(account, commitment2, 0);

        // Valid threshold range is [1, recoveryCount] = [1, 2].
        threshold = bound(threshold, 1, 2);

        vm.prank(account);
        manager.setRecoveryThreshold(account, threshold);

        assertEq(manager.recoveryThreshold(account), threshold);
    }

    /*//////////////////////////////////////////////////////////////
                            recoveryNonce() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoveryNonce_ShouldBeZeroInitially(address account) public view {
        assertEq(manager.recoveryNonce(account), 0);
    }

    /*//////////////////////////////////////////////////////////////
                        recoveryRequest() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoveryRequest_ShouldReturnZeroedForUnknownId(bytes32 requestId) public view {
        IRecoveryManager.RecoveryRequest memory request = manager.recoveryRequest(requestId);

        assertEq(request.account, address(0));
        assertEq(request.executeAt, 0);
        assertEq(request.subject.length, 0);
    }

}
