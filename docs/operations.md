# Operations and recovery

## Trust and provisioning

Provision the signing seed only to the policy process, the public keyring to the ledger, and distinct worker/core bearer tokens. The included Compose setup places PostgreSQL on an internal authority network and does not mount the signing key into the worker or ledger. This limits accidental capability exposure under a trusted host; it is not kernel-resistant isolation.

`python3 scripts/setup.py` exclusively creates `.env` with mode 0600. Keygen exclusively creates the private seed with mode 0600. Existing matching key material is preserved. A mismatching public keyring causes startup failure rather than replacement. Treat both the database and keyring configuration as trusted infrastructure.

## Native services

Build with `cargo build --workspace`. Use the environment variables in `compose.yaml` as the configuration contract. `policy-core keygen PRIVATE_SEED PUBLIC_KEYRING` provisions initial files. Start `ledger-service`, then `policy-core`, then `adversarial-worker`.

The ledger exposes `/health`, `POST /v1/challenges`, and `POST /v1/commit`. `POST /internal/snapshot` requires the separate core token. The policy service exposes `/health` and `POST /v1/authorize`. JSON bodies are limited to 16 KiB. Health endpoints expose no credentials or balances.

## Fail closed

Missing receipts, unknown keys, invalid signatures, wrong identities, invalid challenges, unavailable authority, and database failures do not authorize new transfers. Database lock waits have a three-second timeout for commits. A timeout may reduce availability; it must not be reclassified as success.

A network failure after COMMIT is an unknown outcome. Retry the same operation ID and intent; the cached outcome resolves it without a second debit. For stale state, obtain a fresh challenge and authorization while retaining the business operation ID. Do not change operation semantics under an existing ID.

## Key epochs

The trusted JSON keyring holds epoch ID, public key, and validity interval. To rotate: provision a new seed separately; add its public key with a new epoch and explicit interval to the trusted keyring; restart the ledger to load that ring; then restart the signer with the new seed and `PARG_EPOCH`. Preserve old public keys for cached retry verification. Exercise overlap and rollback procedures before real deployment. The repository tests key-epoch behavior; it does not automate secret distribution or rotation.

## Backup and retention

Back up PostgreSQL and the signer key through independent protected procedures. Restoration of an older database can restore spent receipts to an unspent state: external rollback resistance is out of scope. Restore tests, key custody, access control, and retention are deployment responsibilities. Challenges accumulate until redeemed; production needs bounded issuance and expiry cleanup.

The test suite injects application failures within transactions. It does not certify filesystem power-loss behavior, compromised databases, cross-region replication, or arbitrary administrator SQL. All mutators must follow the documented lock order and versioning discipline.
