// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Test } from "forge-std/Test.sol";

import { PrepareRecovery } from "../../script/PrepareRecovery.s.sol";
import { ECDSARecoveryProvider } from "../../src/providers/ECDSARecoveryProvider.sol";

contract TestECDSARecoveryProvider is Test, PrepareRecovery {

    ECDSARecoveryProvider public provider;

    address public recoveryEoa;
    uint256 public recoveryEoaPk;

    /// @dev ERC-1271 magic value, equal to the `isValidSignature(bytes32,bytes)` selector.
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    function setUp() public {
        provider = new ECDSARecoveryProvider();
        (recoveryEoa, recoveryEoaPk) = makeAddrAndKey("recoveryEoa");
    }

    /// @dev Etches `signer` with code so `SignatureCheckerLib` takes the ERC-1271 contract-signer branch,
    ///      then mocks its `isValidSignature` to return `magic`. Excludes the zero address, precompiles, and
    ///      the addresses the test relies on so a fuzzer landing on one is discarded.
    function _stubContractSigner(address signer, bytes4 magic) private {
        vm.assume(uint160(signer) > 0xff);
        vm.assume(signer != address(provider) && signer != address(this) && signer != address(vm));
        vm.etch(signer, hex"00");
        vm.mockCall(signer, abi.encodeWithSelector(ERC1271_MAGIC_VALUE), abi.encode(magic));
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTANT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ShouldReturnCorrectRecoverTypehash() public view {
        assertEq(provider.RECOVER_TYPEHASH(), keccak256("Recover(address account,uint256 nonce,bytes subject)"));
    }

    /*//////////////////////////////////////////////////////////////
                            recoverDigest() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoverDigest_ShouldMatchEip712Digest(
        address account,
        uint256 nonce,
        bytes calldata subject
    )
        public
        view
    {
        bytes32 typeHash = keccak256("Recover(address account,uint256 nonce,bytes subject)");
        bytes32 structHash = keccak256(abi.encode(typeHash, account, nonce, keccak256(subject)));

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("ECDSARecoveryProvider")),
                keccak256(bytes("1")),
                block.chainid,
                address(provider)
            )
        );

        bytes32 expectedDigest = keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));

        assertEq(provider.recoverDigest(account, nonce, subject), expectedDigest);
    }

    /*//////////////////////////////////////////////////////////////
                            verify() TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Verify_RevertIfCommitmentNot32Bytes(
        address account,
        bytes calldata subject,
        uint256 nonce,
        bytes calldata commitment,
        bytes calldata proof
    )
        public
    {
        vm.assume(commitment.length != 32);

        vm.expectRevert(ECDSARecoveryProvider.ECDSARecoveryProvider_InvalidCommitment.selector);
        provider.verify(account, subject, nonce, commitment, proof);
    }

    function test_Verify_RevertIfCommitmentIsZeroAddress(
        address account,
        bytes calldata subject,
        uint256 nonce,
        bytes calldata proof
    )
        public
    {
        bytes memory commitment = encodeEoaCommitment(address(0));

        vm.expectRevert(ECDSARecoveryProvider.ECDSARecoveryProvider_InvalidCommitment.selector);
        provider.verify(account, subject, nonce, commitment, proof);
    }

    function test_Verify_RevertIfMalformedProof(
        address account,
        bytes calldata subject,
        uint256 nonce,
        address commitmentEoa,
        bytes calldata proof
    )
        public
    {
        // A proof whose length is not a valid ECDSA signature (64 or 65 bytes) cannot be a valid signature
        // for an EOA signer, so `SignatureCheckerLib` returns false and `verify` reverts with the generic
        // InvalidSignature — the dedicated InvalidProofLength error was removed along with the length check.
        vm.assume(proof.length != 64 && proof.length != 65);
        vm.assume(commitmentEoa != address(0));
        vm.assume(commitmentEoa.code.length == 0);

        bytes memory commitment = encodeEoaCommitment(commitmentEoa);

        vm.expectRevert(ECDSARecoveryProvider.ECDSARecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, nonce, commitment, proof);
    }

    function test_Verify_RevertIfWrongSigner(address account, uint256 nonce, bytes calldata subject) public {
        // A valid 65-byte signature, but from a key other than the committed EOA.
        (, uint256 wrongPk) = makeAddrAndKey("wrongSigner");

        bytes memory commitment = encodeEoaCommitment(recoveryEoa);
        bytes memory proof = signRecoverProof(provider, account, nonce, subject, wrongPk);

        vm.expectRevert(ECDSARecoveryProvider.ECDSARecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, nonce, commitment, proof);
    }

    function test_Verify_RevertIfNonceMismatch(address account, uint256 nonce, bytes calldata subject) public {
        vm.assume(nonce != type(uint256).max);

        bytes memory commitment = encodeEoaCommitment(recoveryEoa);
        bytes memory proof = signRecoverProof(provider, account, nonce, subject, recoveryEoaPk);

        // A proof bound to `nonce` must not verify against `nonce + 1` (replay safety).
        vm.expectRevert(ECDSARecoveryProvider.ECDSARecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, nonce + 1, commitment, proof);
    }

    function test_Verify_RevertIfAccountMismatch(
        address account,
        address otherAccount,
        uint256 nonce,
        bytes calldata subject
    )
        public
    {
        vm.assume(account != otherAccount);

        bytes memory commitment = encodeEoaCommitment(recoveryEoa);
        bytes memory proof = signRecoverProof(provider, account, nonce, subject, recoveryEoaPk);

        // A proof bound to `account` must not verify for a different account (cross-account replay safety).
        vm.expectRevert(ECDSARecoveryProvider.ECDSARecoveryProvider_InvalidSignature.selector);
        provider.verify(otherAccount, subject, nonce, commitment, proof);
    }

    function test_Verify_RevertIfSubjectMismatch(
        address account,
        uint256 nonce,
        bytes calldata subject,
        bytes calldata otherSubject
    )
        public
    {
        vm.assume(keccak256(subject) != keccak256(otherSubject));

        bytes memory commitment = encodeEoaCommitment(recoveryEoa);
        bytes memory proof = signRecoverProof(provider, account, nonce, subject, recoveryEoaPk);

        // A proof bound to `subject` must not verify for a different subject (no new-owner substitution).
        vm.expectRevert(ECDSARecoveryProvider.ECDSARecoveryProvider_InvalidSignature.selector);
        provider.verify(account, otherSubject, nonce, commitment, proof);
    }

    function test_Verify_RevertIfDomainMismatch(address account, uint256 nonce, bytes calldata subject) public {
        // A second deployment has a different EIP-712 domain (verifyingContract), so a proof signed for
        // `provider` must not verify on `otherProvider`.
        ECDSARecoveryProvider otherProvider = new ECDSARecoveryProvider();

        bytes memory commitment = encodeEoaCommitment(recoveryEoa);
        bytes memory proof = signRecoverProof(provider, account, nonce, subject, recoveryEoaPk);

        vm.expectRevert(ECDSARecoveryProvider.ECDSARecoveryProvider_InvalidSignature.selector);
        otherProvider.verify(account, subject, nonce, commitment, proof);
    }

    function test_Verify_ShouldAcceptValidSignature(address account, uint256 nonce, bytes calldata subject) public {
        bytes memory commitment = encodeEoaCommitment(recoveryEoa);
        bytes memory proof = signRecoverProof(provider, account, nonce, subject, recoveryEoaPk);

        provider.verify(account, subject, nonce, commitment, proof);
    }

    function test_Verify_ShouldAcceptCompactSignature(address account, uint256 nonce, bytes calldata subject) public {
        // `SignatureCheckerLib` accepts the 64-byte EIP-2098 short form for EOA signers, so a compact proof
        // from the committed EOA verifies just like the 65-byte `(r, s, v)` form.
        bytes memory commitment = encodeEoaCommitment(recoveryEoa);
        bytes memory proof = signRecoverProofCompact(provider, account, nonce, subject, recoveryEoaPk);

        assertEq(proof.length, 64);
        provider.verify(account, subject, nonce, commitment, proof);
    }

    /*//////////////////////////////////////////////////////////////
                      verify() ERC-1271 SIGNER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Verify_ShouldAcceptContractSigner(
        address account,
        uint256 nonce,
        bytes calldata subject,
        address signer,
        bytes calldata proof
    )
        public
    {
        // A committed contract signer whose ERC-1271 `isValidSignature` returns the magic value: the
        // `SignatureCheckerLib` contract-signer path accepts, so `verify` passes. The proof bytes are opaque
        // to this path — a real guardian validates them internally.
        _stubContractSigner(signer, ERC1271_MAGIC_VALUE);

        provider.verify(account, subject, nonce, encodeEoaCommitment(signer), proof);
    }

    function test_Verify_RevertIfContractSignerRejects(
        address account,
        uint256 nonce,
        bytes calldata subject,
        address signer,
        bytes4 magic,
        bytes calldata proof
    )
        public
    {
        // A committed contract signer whose ERC-1271 `isValidSignature` returns anything but the magic value:
        // the contract-signer path returns false, so `verify` reverts with the provider's InvalidSignature.
        vm.assume(magic != ERC1271_MAGIC_VALUE);
        _stubContractSigner(signer, magic);

        vm.expectRevert(ECDSARecoveryProvider.ECDSARecoveryProvider_InvalidSignature.selector);
        provider.verify(account, subject, nonce, encodeEoaCommitment(signer), proof);
    }

}
