# PARG v1 protocol

## Stable intent

All operations transfer a positive integer number of a single synthetic asset's base units. Values are bounded to `1..=1_000_000_000_000`; account balances use the same upper bound. There is no floating point or caller-selectable currency.

The intent digest is SHA-256 over `PARGINT1`, followed by five raw 16-byte UUIDs (operation, principal, target, source, destination), followed by the amount encoded as a 16-byte big-endian unsigned integer. Operation IDs must be RFC4122 UUIDv4. Self-transfers are rejected.

The HTTP JSON is only a transport. Unknown fields are rejected. Each service uses the same typed intent; the ledger requires exact equality between the submitted intent and receipt intent. The signed digest covers the normalized intent, not raw HTTP whitespace or object key order.

## Receipt bytes

| Offset | Size | Field |
|---|---:|---|
| 0 | 8 | ASCII `PARG-V01` |
| 8 | 8 | Schema version 1, unsigned big-endian |
| 16 | 8 | Key epoch |
| 24 | 8 | Policy version |
| 32 | 32 | Random challenge nonce |
| 64 | 8 | Signed big-endian Unix expiry seconds |
| 72 | 16 | Operation UUID |
| 88 | 16 | Principal UUID |
| 104 | 16 | Target-service UUID |
| 120 | 16 | Source-account UUID |
| 136 | 16 | Destination-account UUID |
| 152 | 16 | Amount |
| 168 | 8 | Expected source version |
| 176 | 8 | Expected destination version |
| 184 | 8 | Expected limit version |
| 192 | 32 | Stable intent digest |

BLAKE3 of these exact 224 bytes is signed using ordinary Ed25519. This is an application-defined hashed-message protocol, not Ed25519ph. Verification uses `verify_strict`. JSON receipts contain the typed fields and a hex-encoded 64-byte signature; unsupported policy versions or unknown epochs cannot authorize new transfers.

`crates/parg-protocol/golden.hex` fixes all canonical bytes independently of Rust struct layout. It replaces the unverified proposed digest and invalid version-10 operation UUID from the initial design.

## Challenge lifecycle

Challenges are issued from locked authoritative resource state, bind the stable intent digest and three versions, and expire after 60 seconds over HTTP. A successful mutation deletes the challenge inside the same transaction. Rollback restores the challenge. A stale receipt remains unspent but requires fresh authorization against new state to succeed.

## Operation identity and retry semantics

A unique operation claim serializes concurrent requests with the same operation ID. An authenticated, cryptographically verified request with a matching principal and stable intent receives its original outcome after a commit. New signatures, nonces, or epochs do not change business identity. A divergent intent conflicts.

Cached retries are not new authorization decisions: they do not require an unexpired challenge or active signing epoch, but do require a recognized public key and valid signature. Retain retired public keys when cached retry availability is desired. Removing a key invalidates retries signed solely by it.

## Authority and state

The policy signer obtains state directly from the ledger's internal authenticated endpoint. No worker-supplied balance or Merkle root is accepted. Source ownership, balances, limit predicates, and all state versions are checked again under transaction locks. A day-window rollover or competing update invalidates old snapshots. Version increments are checked for overflow.
