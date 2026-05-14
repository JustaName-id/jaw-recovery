// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { Script, console2 } from "forge-std/Script.sol";
import { SafeSingletonDeployer } from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";

import { JustaRecoveryManager } from "../src/JustaRecoveryManager.sol";

/**
 * @notice Deploy the JustaRecoveryManager contract.
 */
contract DeployJustaRecoveryManager is Script {

    /// @dev Set to address(0) until the first deterministic deploy; the assert
    /// below is guarded so the first run succeeds. Update with the real address
    /// afterwards to enforce the same address across every chain.
    address constant EXPECTED_MANAGER = address(0);

    bytes32 constant MANAGER_SALT = 0x0000000000000000000000000000000000000000000000000000000000000001;

    function run() public {
        console2.log("Deploying on chain ID", block.chainid);

        if (block.chainid == 31_337) {
            vm.startBroadcast();
            deploy();
            vm.stopBroadcast();
        } else {
            deployWithSafeSingleton();
        }
    }

    function deploy() internal {
        JustaRecoveryManager manager = new JustaRecoveryManager{ salt: 0 }();

        logAddress("JustaRecoveryManager", address(manager));
    }

    function deployWithSafeSingleton() internal {
        address manager = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(JustaRecoveryManager).creationCode, args: "", salt: MANAGER_SALT
        });

        console2.log("Deployed JustaRecoveryManager:", manager);
        if (EXPECTED_MANAGER != address(0)) {
            assert(manager == EXPECTED_MANAGER);
        }

        logAddress("JustaRecoveryManager", manager);
    }

    function logAddress(string memory name, address addr) internal pure {
        console2.logString(string.concat(name, ": ", Strings.toHexString(addr)));
    }

}
