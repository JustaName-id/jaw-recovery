# JustaRecoveryManager

> **🚧 Active development — not audited, not deployed.** This module is under active design and review. Interfaces, storage layout, and behavior may change without notice. Do not deploy to production or integrate against it until it has completed a security audit and a versioned release is tagged.

## Overview

`JustaRecoveryManager` is a Solidity smart contract that provides M-of-N, time-locked account recovery for [JustanAccount](https://github.com/justaname-id/justanaccount) smart accounts. An account opts in by registering the manager as one of its owners; if its keys are later lost, a pre-configured set of recovery factors can — after a per-factor time-lock — register a new owner (a WebAuthn passkey or an EOA) on the account.

The manager is a non-ownable, non-upgradeable singleton (one deployment serves every account on a chain). It owns all per-account recovery state and treats recovery providers as **stateless verifiers**: on each approval it calls `provider.verify(...)`, which reverts on an invalid proof. Provider trust is therefore equivalent to provider correctness. This repository ships the first provider, `ECDSARecoveryProvider`, which verifies an EIP-712 signature from a committed backup EOA.

## Features

- **M-of-N Threshold**: Require any `M` of an account's `N` registered recoveries to approve, defaulting to 1. Counted by distinct recovery, not by provider.
- **Per-Recovery Time-Lock**: Each recovery carries its own delay (in seconds), set at registration. A queued request uses the **largest** delay among the approving recoveries, so a request is only as fast as its most-cautious factor.
- **Owner-Type Agnostic**: A recovery can install a new WebAuthn passkey (64-byte `subject`) or a new EOA (32-byte `subject`); the manager dispatches on length at execution.
- **Stateless, Pluggable Providers**: Any contract implementing `IRecoveryProvider` can serve as a factor. The manager owns the commitments and the replay nonce and passes them in on every call, so one provider deployment backs any number of factors for any number of accounts.
- **Single-Use Proofs**: A per-account replay nonce is bound into every proof and bumped on each successful request, making proofs single-use across accounts, nonces, and target owners.
- **Two-Step Flow with Veto**: `requestRecovery` queues a request; after the delay, anyone may `executeRecoveryRequest`. During the window the account itself may `cancelRecoveryRequest` to abort.
- **Permissionless Initiation/Execution**: The proofs carry authorization, so a relayer can request and execute on behalf of a locked-out user.
- **Lockout Prevention**: A threshold can never exceed the registered count, and a recovery cannot be removed below the threshold (except a full opt-out to zero).
- **Fail-Fast Subject Validation**: A new-owner `subject` is validated at request time (canonical address, and rejected if it is already an owner) so a request cannot silently queue and then revert at execution.
- **Reentrancy Protection**: State-changing recovery functions are guarded by a contract-wide reentrancy lock.

## Architecture

The system consists of a coordinator, a provider interface, and one concrete provider.

### JustaRecoveryManager (Main Contract)

The singleton coordinator that owns all per-account state (registered recoveries, approval threshold, replay nonce) and queued recovery requests. It inherits from:

- `IRecoveryManager` (the manager's interface — errors, events, types, and function signatures)
- `ReentrancyGuard` (Solady's reentrancy protection)

#### Key Libraries Used

- `EnumerableSet` (OpenZeppelin) — per-account set of registered recovery ids
- `MultiOwnable` (JustanAccount) — owner registration on the target account (`addOwnerAddress` / `addOwnerPublicKey` / `isOwnerBytes`)

### IRecoveryProvider (Interface)

The stateless verifier standard every provider implements:

```solidity
interface IRecoveryProvider {
    function verify(
        address account,
        bytes calldata subject,
        uint256 nonce,
        bytes calldata commitment,
        bytes calldata proof
    ) external;
}
```

Implementations MUST revert on an invalid proof, bind the proof to `(account, nonce, subject)` so it cannot be replayed, and verify against exactly one `commitment` (so one proof cannot satisfy several recoveries of the same provider).

### ECDSARecoveryProvider (First Provider)

A stateless ECDSA-EOA verifier. The commitment is a backup EOA address; the proof is an EIP-712 signature from that EOA over `(account, nonce, subject)`. It inherits from:

- `IRecoveryProvider`
- `EIP712` (Solady) — the EIP-712 domain binds proofs to this contract and chain

#### Key Libraries Used

- `ECDSA` (Solady) — signature recovery

## Data Structures

### Recovery

A registered recovery factor:

```solidity
struct Recovery {
    address provider;     // the verifier contract
    bytes commitment;     // provider-specific identity (e.g. abi.encode(eoa))
    uint32 delay;         // per-recovery time-lock in seconds
}
```

### Approval

One recovery's approval submitted to `requestRecovery`:

```solidity
struct Approval {
    bytes32 recoveryId;   // identifies a registered recovery for the account
    bytes proof;          // provider-specific proof (verified against the stored commitment)
}
```

### RecoveryRequest

A queued recovery awaiting execution (`account == address(0)` means "not present"):

```solidity
struct RecoveryRequest {
    address account;      // the account being recovered
    uint64 executeAt;     // timestamp the request becomes executable
    bytes subject;        // the new owner: abi.encode(address) (32B) or abi.encode(x, y) (64B)
}
```

## Identifiers

- **`recoveryId`** = `keccak256(abi.encode(account, provider, commitment))` — identifies a registered recovery. Account-scoped, so the same factor under two accounts yields different ids.
- **`requestId`** = `keccak256(abi.encode(account, subject, nonce))` — identifies a queued request; deterministic and single-use (the nonce only advances).
- **`ECDSARecoveryProvider.RECOVER_TYPEHASH`** = `keccak256("Recover(address account,uint256 nonce,bytes subject)")`.

## Key Functions

### Account Owner Functions

Callable only by the account (`msg.sender == account`):

- `addRecovery(address account, address provider, bytes commitment, uint32 delay)`: Register a recovery and return its `recoveryId`. The provider must be a contract; the commitment must be non-empty.
- `removeRecovery(address account, bytes32 recoveryId)`: Unregister a recovery. Rejected if it would drop the count below the threshold, unless it removes the last one (full opt-out).
- `setRecoveryThreshold(address account, uint256 threshold)`: Set the approval threshold, bounded to `[1, recoveryCount(account)]`.

### Execution Functions

- `requestRecovery(address account, bytes subject, Approval[] approvals)`: Queue a request. Unrestricted caller; the proofs carry authorization. Requires exactly `recoveryThreshold(account)` distinct, registered recoveries, each verifying a proof over the same `subject` at the account's current nonce. `subject` must be a canonical 32-byte EOA or 64-byte passkey and not already an owner. Returns `requestId`.
- `executeRecoveryRequest(bytes32 requestId)`: After the delay elapses, register the new owner on the account. Unrestricted caller.
- `cancelRecoveryRequest(bytes32 requestId)`: Abort a queued request. Callable only by the account the request is for.

### View Functions

- `computeRecoveryId(address account, address provider, bytes commitment)`: The deterministic recovery id.
- `hasRecovery(address account, bytes32 recoveryId)`: Whether a recovery id is registered.
- `getRecovery(address account, bytes32 recoveryId)`: A single registered recovery (zeroed if absent).
- `getRecoveries(address account)`: All registered recoveries.
- `recoveryCount(address account)`: Number of registered recoveries.
- `recoveryThreshold(address account)`: The effective approval threshold (1 if never set).
- `recoveryNonce(address account)`: The current replay nonce (bind this into proofs).
- `recoveryRequest(bytes32 requestId)`: The pending request (zeroed if not pending).

## Security Model

### Two-Step Time-Lock

Recovery is intentionally a queue-then-execute flow with a delay, giving the legitimate owner a window to notice and `cancelRecoveryRequest` a malicious request. The pending entry is deleted before the external owner-add call (checks-effects-interactions).

### Replay Protection

A per-account nonce is bound into every proof and advanced on each successful request, making proofs single-use. The ECDSA provider's EIP-712 domain binds proofs to the specific provider deployment and chain, so a signature cannot be reused on another provider or chain.

### Same-Subject, Atomic Approval

Every approval in a request verifies the **same** `subject`, so all `M` approvals authorize the same new owner. Verification is atomic: one invalid proof reverts the whole request, with no partial state and no stray nonce advance.

### Distinctness & Canonical Commitments

Distinctness is enforced by `recoveryId`. To keep one factor from counting twice, the ECDSA provider requires a canonical 32-byte commitment (otherwise `abi.decode` would accept trailing bytes and let one EOA appear under several ids). Every provider must enforce a one-to-one mapping between a commitment's bytes and its underlying identity.

### Lockout Prevention

`setRecoveryThreshold` cannot exceed the registered count, and `removeRecovery` cannot drop the count below the threshold (except a full opt-out to zero). Together these maintain the invariant `count == 0 || count >= threshold`.

### Open Provider Model

Any contract may be a provider and any account may register any provider (gated only by `msg.sender == account`). The manager does not whitelist providers; trust equals provider correctness, curated by audits and UI guidance. Consequences to keep in mind:

- **M-of-N counts distinct registered recoveries, not distinct real-world identities.** Registering the same underlying identity under two provider deployments (or, for a provider that did not enforce canonical commitments, under two encodings) lets one key satisfy two factors. Use one canonical provider deployment per chain and let the UI curate what gets registered.
- A registered provider that is not a contract is rejected at registration; commitment-format validity is each provider's responsibility (enforced in its `verify`).

### Pending Requests Are Not Auto-Cancelled

Changing recovery configuration — `removeRecovery`, `setRecoveryThreshold` — does **not** cancel already-queued requests. A queued `RecoveryRequest` keeps its `executeAt` and still executes after its delay. To stop a pending request, call `cancelRecoveryRequest(requestId)` (the dedicated veto, callable by the account at any point in the window). Removing a compromised factor prevents *future* requests from it but does not stop one already in flight.

## Storage Layout

```solidity
// Per-account set of registered recovery ids
mapping(address account => EnumerableSet.Bytes32Set recoveryIds) internal _recoveryIds;

// Per-account recovery data, keyed by recovery id
mapping(address account => mapping(bytes32 recoveryId => Recovery recovery)) internal _recoveries;

// Per-account approval threshold (0 => default of 1)
mapping(address account => uint256 threshold) internal _recoveryThreshold;

// Per-account replay nonce
mapping(address account => uint256 nonce) internal _recoveryNonce;

// Pending recovery requests, keyed by request id
mapping(bytes32 requestId => RecoveryRequest request) internal _recoveryRequests;
```

## Events

```solidity
event RecoveryAdded(address indexed account, uint32 delay, bytes32 indexed recoveryId);
event RecoveryRemoved(address indexed account, bytes32 indexed recoveryId);
event RecoveryThresholdChanged(address indexed account, uint256 oldThreshold, uint256 newThreshold);
event RecoveryRequested(
    address indexed account, bytes32 indexed requestId, bytes32[] recoveryIds, bytes subject, uint64 executeAt
);
event RecoveryRequestExecuted(address indexed account, bytes32 indexed requestId, bytes subject);
event RecoveryRequestCancelled(address indexed account, bytes32 indexed requestId);
```

Events reference recoveries by `recoveryId` only; resolve an id to its `(provider, commitment)` via `getRecoveries(account)`.

## Integration with JustanAccount

JustaRecoveryManager acts as an owner of JustanAccount instances:

1. Deploy (or use) a JustanAccount instance.
2. Add JustaRecoveryManager as an owner via `addOwnerAddress(manager)`.
3. Register one or more recoveries via `addRecovery(account, provider, commitment, delay)` (e.g. the ECDSA provider with a backup EOA).
4. Optionally raise the threshold via `setRecoveryThreshold(account, m)`.
5. On key loss, a relayer calls `requestRecovery(account, subject, approvals)` with the new owner and the required proofs.
6. After the delay, anyone calls `executeRecoveryRequest(requestId)` to register the new owner; during the delay the account may `cancelRecoveryRequest(requestId)`.

## Influences & Acknowledgments

This implementation was influenced by and builds upon:

- **[JustanAccount](https://github.com/justaname-id/justanaccount)**: The target smart account whose owners JustaRecoveryManager manages.
- **[Solady](https://github.com/Vectorized/solady)**: Optimized utilities — `ECDSA`, `EIP712`, and `ReentrancyGuard`.
- **[OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)**: `EnumerableSet`.
- **[Safe Singleton Deployer](https://github.com/wilsoncusack/safe-singleton-deployer-sol)**: Deterministic cross-chain deployment.
```