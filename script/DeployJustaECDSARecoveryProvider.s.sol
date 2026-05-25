// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { Script, console2 } from "forge-std/Script.sol";
import { SafeSingletonDeployer } from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";

import { JustaECDSARecoveryProvider } from "../src/providers/JustaECDSARecoveryProvider.sol";

/**
 * @notice Deploy the JustaECDSARecoveryProvider contract.
 */
contract DeployJustaECDSARecoveryProvider is Script {

    /// @dev The JustaRecoveryManager address. Must match the deterministic deployment of the manager
    /// on this chain. Fill in once the manager has been first-deployed.
    address constant JUSTA_RECOVERY_MANAGER = address(0);

    /// @dev Set to address(0) until the first deterministic deploy; the assert below is guarded so
    /// the first run succeeds. Update with the real address afterwards to enforce the same address
    /// across every chain.
    address constant EXPECTED_PROVIDER = address(0);

    bytes32 constant PROVIDER_SALT = 0x0000000000000000000000000000000000000000000000000000000000000001;

    function run() public {
        console2.log("Deploying JustaECDSARecoveryProvider on chain ID", block.chainid);
        require(JUSTA_RECOVERY_MANAGER != address(0), "Set JUSTA_RECOVERY_MANAGER before deploying");

        if (block.chainid == 31_337) {
            vm.startBroadcast();
            deploy();
            vm.stopBroadcast();
        } else {
            deployWithSafeSingleton();
        }
    }

    function deploy() internal {
        JustaECDSARecoveryProvider provider = new JustaECDSARecoveryProvider{ salt: 0 }(JUSTA_RECOVERY_MANAGER);

        logAddress("JustaECDSARecoveryProvider", address(provider));
    }

    function deployWithSafeSingleton() internal {
        address provider = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(JustaECDSARecoveryProvider).creationCode,
            args: abi.encode(JUSTA_RECOVERY_MANAGER),
            salt: PROVIDER_SALT
        });

        console2.log("Deployed JustaECDSARecoveryProvider:", provider);
        if (EXPECTED_PROVIDER != address(0)) {
            assert(provider == EXPECTED_PROVIDER);
        }

        logAddress("JustaECDSARecoveryProvider", provider);
    }

    function logAddress(string memory name, address addr) internal pure {
        console2.logString(string.concat(name, ": ", Strings.toHexString(addr)));
    }

}
