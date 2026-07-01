// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { Test } from "forge-std/Test.sol";

import { P256 } from "solady/utils/P256.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";

import { JustanAccount } from "justanaccount/JustanAccount.sol";
import { JustanAccountFactory } from "justanaccount/JustanAccountFactory.sol";

import { Base64Url } from "../../lib/justanaccount/lib/FreshCryptoLib/solidity/src/utils/Base64Url.sol";
import { ERC7739Utils } from "../../lib/justanaccount/test/utils/ERC7739Utils.sol";

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
    JustanAccountFactory public factory;
    JustanAccount public guardian;
    EntryPoint public entryPoint;

    /// @dev The guardian's passkey private key
    uint256 public constant GUARDIAN_PASSKEY_PK = 0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2;

    /// @dev A fresh factory nonce for the counterfactual (undeployed) guardian in the ERC-6492 test.
    uint256 internal constant GUARDIAN_CF_NONCE = 1;

    /// @dev The ERC-6492 magic suffix that marks a wrapped (predeploy) signature.
    bytes32 internal constant ERC6492_MAGIC = 0x6492649264926492649264926492649264926492649264926492649264926492;

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

        // Deploy a passkey-backed JustanAccount to act as a recovery guardian. WebAuthn verification needs
        // the P256 verifier etched at the addresses Solady's WebAuthn library staticcalls.
        vm.etch(P256.VERIFIER, P256_VERIFIER_BYTECODE);
        vm.etch(P256.RIP_PRECOMPILE, P256_VERIFIER_BYTECODE);

        (uint256 x, uint256 y) = vm.publicKeyP256(GUARDIAN_PASSKEY_PK);
        factory = new JustanAccountFactory(address(entryPoint));
        bytes[] memory guardianOwners = new bytes[](1);
        guardianOwners[0] = abi.encode(bytes32(x), bytes32(y));
        guardian = factory.createAccount(guardianOwners, 0);
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
        // Committed signer must be a code-free EOA (else SignatureCheckerLib takes the ERC-1271 path).
        vm.assume(recoveryEoa.code.length == 0);

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
        // Committed signer must be a code-free EOA (else SignatureCheckerLib takes the ERC-1271 path).
        vm.assume(recoveryEoa.code.length == 0);

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

    /**
     * @notice Recovers an account end to end where the recovery factor is a passkey-backed smart-account
     *         guardian, proving the new owner is genuinely registered.
     * @dev Distinct from recovering *to* a passkey above: here the passkey is the guardian (the recovery
     *      `commitment`), so the proof is a WebAuthn signature the guardian validates via ERC-1271 — the
     *      `SignatureCheckerLib` contract-signer path in the provider.
     */
    function test_ShouldRecoverWithPasskeyGuardianEndToEnd(address newOwner, uint32 delay) public {
        address payable account = TEST_ACCOUNT_ADDRESS;

        // The recovered owner must not already be on the account.
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));

        // Register the passkey-backed guardian as the recovery (commitment = the guardian contract address).
        vm.prank(account);
        bytes32 recoveryId =
            manager.addRecovery(account, address(provider), encodeEoaCommitment(address(guardian)), delay);

        bytes memory subject = encodeEoaSubject(newOwner);
        uint256 nonce = manager.recoveryNonce(account);

        // The guardian's passkey signs a real WebAuthn proof over the provider's digest.
        bytes memory proof = _signPasskeyGuardianProof(account, nonce, subject);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        bytes32 requestId = manager.requestRecovery(account, subject, approvals);
        vm.warp(manager.recoveryRequest(requestId).executeAt);
        manager.executeRecoveryRequest(requestId);

        // The new EOA is a real owner (manager + newOwner = 2) and the proof has been consumed.
        assertTrue(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 2);
        assertEq(manager.recoveryNonce(account), nonce + 1);
    }

    /**
     * @notice Recovers an account using a COUNTERFACTUAL (not-yet-deployed) passkey-backed smart-account
     *         guardian, exercising the provider's ERC-6492 path.
     * @dev The guardian address is predicted but never deployed. The proof is an ERC-6492 wrapper
     *      (create2 factory + `createAccount` calldata + inner WebAuthn signature). Solady's reverting
     *      verifier deploys the guardian in a reverted context to run its ERC-1271 check, so the guardian
     *      is validated without ending up persistently deployed.
     */
    function test_ShouldRecoverWithUndeployedPasskeyGuardianEndToEnd(address newOwner, uint32 delay) public {
        address payable account = TEST_ACCOUNT_ADDRESS;

        vm.assume(newOwner != address(0));
        vm.assume(newOwner != account);
        vm.assume(newOwner != address(manager));

        // Etch Solady's canonical ERC-6492 reverting verifier so the undeployed-signer path resolves.
        _etchErc6492RevertingVerifier();

        // A counterfactual passkey guardian: address predicted from a fresh nonce, deliberately NOT deployed.
        (uint256 gx, uint256 gy) = vm.publicKeyP256(GUARDIAN_PASSKEY_PK);
        bytes[] memory guardianOwners = new bytes[](1);
        guardianOwners[0] = abi.encode(bytes32(gx), bytes32(gy));
        address undeployedGuardian = factory.getAddress(guardianOwners, GUARDIAN_CF_NONCE);
        assertEq(undeployedGuardian.code.length, 0);

        vm.prank(account);
        bytes32 recoveryId =
            manager.addRecovery(account, address(provider), encodeEoaCommitment(undeployedGuardian), delay);

        bytes memory subject = encodeEoaSubject(newOwner);
        uint256 nonce = manager.recoveryNonce(account);

        // ERC-6492 wrapper: abi.encode(create2Factory, factoryCalldata, innerSig) ++ magic. The inner proof is
        // a WebAuthn signature over the guardian's *predicted* EIP-712 domain (it isn't deployed to query).
        bytes memory innerProof = _webAuthnProof(_guardian7739Hash(undeployedGuardian, account, nonce, subject));
        bytes memory factoryCalldata =
            abi.encodeCall(JustanAccountFactory.createAccount, (guardianOwners, GUARDIAN_CF_NONCE));
        bytes memory proof = abi.encodePacked(abi.encode(address(factory), factoryCalldata, innerProof), ERC6492_MAGIC);

        IRecoveryManager.Approval[] memory approvals = new IRecoveryManager.Approval[](1);
        approvals[0] = createApproval(recoveryId, proof);

        bytes32 requestId = manager.requestRecovery(account, subject, approvals);
        vm.warp(manager.recoveryRequest(requestId).executeAt);
        manager.executeRecoveryRequest(requestId);

        // The new EOA is a real owner, and the guardian was validated WITHOUT being persistently deployed.
        assertTrue(JustanAccount(account).isOwnerAddress(newOwner));
        assertEq(JustanAccount(account).ownerCount(), 2);
        assertEq(manager.recoveryNonce(account), nonce + 1);
        assertEq(undeployedGuardian.code.length, 0);
    }

    /**
     * @dev Builds the guardian's ERC-1271 proof: a WebAuthn signature from the guardian's passkey over the
     *      provider's `(account, nonce, subject)` digest, wrapped in ERC-7739 (PersonalSign) using the
     *      guardian account's own EIP-712 domain — the form the guardian re-derives in `isValidSignature`.
     */
    function _signPasskeyGuardianProof(
        address account,
        uint256 nonce,
        bytes memory subject
    )
        internal
        view
        returns (bytes memory)
    {
        return _webAuthnProof(_guardian7739Hash(address(guardian), account, nonce, subject));
    }

    /**
     * @dev The ERC-7739 (PersonalSign) hash a JustanAccount `signer` validates in `isValidSignature`, built
     *      from the signer's *predicted* EIP-712 domain (name/version/chainId/address). Computing the domain
     *      from the address rather than querying `eip712Domain()` lets it work for a not-yet-deployed guardian.
     */
    function _guardian7739Hash(
        address signer,
        address account,
        uint256 nonce,
        bytes memory subject
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 digest = provider.recoverDigest(account, nonce, subject);

        ERC7739Utils.DomainData memory domainData;
        domainData.name = "JustanAccount";
        domainData.version = "1";
        domainData.chainId = block.chainid;
        domainData.verifyingContract = signer;
        domainData.domainSeparator = ERC7739Utils.computeDomainSeparator(domainData);

        return ERC7739Utils.erc7739HashFromPersonalSignHash(digest, domainData);
    }

    /// @dev Wraps `erc7739Hash` in a WebAuthn assertion signed by the guardian's passkey, ABI-encoded as a
    ///      JustanAccount `SignatureWrapper` at owner index 0.
    function _webAuthnProof(bytes32 erc7739Hash) internal pure returns (bytes memory) {
        bytes memory authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";
        string memory clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                Base64Url.encode(abi.encode(erc7739Hash)),
                '","origin":"https://keys.jaw.id","crossOrigin":false}'
            )
        );
        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));

        (bytes32 r, bytes32 s) = vm.signP256(GUARDIAN_PASSKEY_PK, messageHash);
        s = bytes32(_normalizeP256S(uint256(s)));

        return abi.encode(
            JustanAccount.SignatureWrapper({
                ownerIndex: 0,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: authenticatorData,
                        clientDataJSON: clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: r,
                        s: s
                    })
                )
            })
        );
    }

    /// @dev Normalizes a P-256 `s` value to low-s so the verifier accepts it.
    function _normalizeP256S(uint256 s) private pure returns (uint256) {
        uint256 n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
        return s > n / 2 ? n - s : s;
    }

    /// @dev Deploys Solady's canonical reverting ERC-6492 verifier (initcode taken from Solady's own tests)
    ///      at the hardcoded address `SignatureCheckerLib` calls, so the undeployed-signer path resolves.
    function _etchErc6492RevertingVerifier() internal {
        bytes memory initcode =
            hex"6040600b3d3960403df3fe36383d373d3d6020515160208051013d3d515af160203851516084018038385101606037303452813582523838523490601c34355afa34513060e01b141634fd";
        address deployed;
        assembly {
            deployed := create(0, add(initcode, 0x20), mload(initcode))
        }
        require(deployed != address(0), "verifier deploy failed");
        vm.etch(0x00007bd799e4A591FeA53f8A8a3E9f931626Ba7e, deployed.code);
    }

}
