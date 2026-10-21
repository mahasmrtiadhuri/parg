# PARG · Policy-Attested RPC Gateway

### A signed decision is useful only when the exact authorized change commits once.

PARG is a Rust research prototype separating an untrusted application worker from a policy signer and an authoritative PostgreSQL ledger. It explores transaction-bound authorization, replay prevention, optimistic state checks, and failure recovery.

**Rust · Ed25519 · PostgreSQL · Axum · adversarial integration tests**

> **Security boundary:** the prototype assumes a trusted host kernel, policy process, ledger, database, clock, and provisioned public keyring. It implements process separation, not SGX/SEV-SNP attestation or proof of non-compromise. All transfers use synthetic demo credits.

[![Verify PARG](https://github.com/mahasmrtiadhuri/parg/actions/workflows/ci.yml/badge.svg)](https://github.com/mahasmrtiadhuri/parg/actions/workflows/ci.yml)

## Run the demonstration

Prerequisites: Docker with Compose and Python 3.

```bash
git clone https://github.com/mahasmrtiadhuri/parg.git
cd parg
python3 scripts/setup.py
docker compose up --build -d ledger policy
docker compose run --rm demo
```

The setup script creates fresh local credentials in an ignored `.env`, without printing them. A one-shot keygen service creates a private signing seed and public keyring. The worker receives neither the signing key nor database credentials nor the core-to-ledger token.

The demo exercises:

```text
PASS: unauthenticated request rejected
PASS: missing receipt rejected
PASS: altered amount rejected
PASS: compliant transfer committed
PASS: exact replay returned original outcome without a second debit
```

These lines are expected assertions, not a substitute for the CI run. Run `docker compose down` to stop services; add `-v` only when intentionally discarding the demo ledger and keys. Re-running preserves prior state and matching key material; synthetic daily limits still apply.

## Architecture

```mermaid
flowchart TD
    Worker[Untrusted worker] -->|Intent| Ledger[Authoritative ledger]
    Ledger -->|Scoped challenge| Worker
    Worker -->|Authorization request| Policy[Policy signer]
    Policy -->|Authenticated state read| Ledger
    Policy -->|Signed receipt| Worker
    Worker -->|Exact intent and receipt| Ledger
    Ledger -->|Atomic redemption and mutation| DB[(PostgreSQL)]
```

| Crate | Responsibility |
|---|---|
| `parg-protocol` | Stable intent encoding, 224-byte receipt encoding, Ed25519 signatures, policy predicates |
| `policy-core` | Private key ownership; authoritative state retrieval; authorization HTTP endpoint |
| `ledger-service` | Challenge issuance, caller binding, signature verification, atomic operation claims and mutation |
| `adversarial-worker` | Normal flow and explicit malicious HTTP submissions |

## Implemented invariant

Every committed transfer must have a matching authorized receipt, satisfy current ledger policy/state checks, and apply at most once per operation ID. This is a tested implementation property under the documented model, not a mechanically verified theorem or hardware guarantee.

The ledger independently checks source ownership, target, balance, destination capacity, daily spend, policy version, key validity, challenge binding, and all relevant state versions. A valid signature is necessary for a new transfer but never sufficient to guarantee a commit.

## The important engineering decisions

- **Intent versus receipt identity:** a stable SHA-256 intent digest excludes nonce, expiry, epoch, and state versions. Reauthorization changes the receipt digest without changing the business intent.
- **Concurrent retries:** insert an operation claim with a unique primary key before touching balances. Competing inserts wait; subsequent statements read the committed cached outcome. Failed transactions remove the claim and all side effects.
- **Atomicity:** operation claim, account balances, spend counter, challenge deletion, and cached outcome share one database transaction.
- **Lock order:** operation claim → sorted account UUIDs → principal limit → challenge. Only code following the same ordering is covered by the deadlock-avoidance reasoning.
- **Expiry:** actual database wall-clock time is checked after locks are acquired. Expiry is defined at the authorization acceptance check, not as a hard deadline for durable COMMIT.
- **Freshness:** both account versions and the principal limit version must match. The daily window is UTC and can be reset only through authoritative challenge issuance.
- **Canonical bytes:** manual big-endian serialization; no native packed-struct layout. A golden byte fixture is independently generated and signature tests flip every encoded byte.
- **Key epochs:** a trusted local keyring supports overlapping public keys and validity intervals. Rotation is explicit configuration plus process restart, not an automatic key-management service.

See [protocol](docs/protocol.md), [threat model](SECURITY.md), and [operating guide](docs/operations.md).

## Verify from source

Install a current stable Rust toolchain. Start a disposable PostgreSQL database; for example:

```bash
docker run --rm --name parg-test -p 127.0.0.1:55432:5432 \
  -e POSTGRES_USER=parg -e POSTGRES_PASSWORD=local-test-password \
  -e POSTGRES_DB=parg_test postgres:16
```

In a second terminal:

```bash
export PARG_TEST_DATABASE_URL=postgres://parg:local-test-password@127.0.0.1:55432/parg_test
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Integration tests require that environment variable and fail loudly if it is absent. Each fixture uses distinct account/principal/operation IDs. Use a disposable database: the suite creates its schema and synthetic records.

## Adversarial coverage

| Scenario | Required outcome |
|---|---|
| Valid transfer, exact retry | Same cached result; one debit |
| Amount/destination tampering | Rejected |
| Forged signature or wrong service | Rejected |
| Stale, unconsumed receipt | Conflict; reauthorization can succeed |
| Same intent, new authorization after commit | Original cached result |
| Same operation ID, divergent intent | Conflict |
| Sixteen simultaneous duplicate submissions | One debit; identical results |
| Disjoint accounts and distinct principals | Both operations succeed |
| Disjoint accounts sharing a limit | One initial-version operation becomes stale |
| Opposite transfers | One commit and one stale-version rejection |
| Failure after debit / before commit | Balances, claim, limit, and challenge roll back |
| Lock wait crosses expiry | Rejected after acquiring the lock |
| Wrong authenticated principal | No cached-result disclosure |
| Key rotation / retired or unknown epoch | Enforce configured key policy |
| Reconnected ledger | Durable replay protection persists |

CI runs Rust checks, PostgreSQL-backed tests, the real HTTP demonstration, and the Compose build/demo. Check the actual run before relying on a particular commit.

## Deliberate limits

One configured worker identity, one synthetic asset, and fixed policy version 1. This is not a payment network or production IAM system. The demo uses HTTP on local/container networks; external deployment needs authenticated TLS and hardened ingress. There is no enclave integration, remote attestation, formal proof, dual-control approval workflow, automatic key rotation, database rollback resistance, rate limiting, challenge-retention job, or measured latency guarantee.

A compromised worker can still request operations permitted by its identity and policy. The design constrains effects; it does not establish the client's true intent or prevent denial of service. A compromise of the trusted ledger, database, policy signer, or host is outside this version's guarantee.
