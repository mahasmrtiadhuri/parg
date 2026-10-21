# Contributing

Changes to protocol bytes require versioning analysis and independent test vectors. Changes to transaction flow require tests for concurrency, rollback, retries, and stale state. Preserve the documented lock order and never treat a storage error as a successful authorization.

Run formatting, Clippy, protocol tests, PostgreSQL integration tests, and the HTTP demo. Integration tests must not silently skip for lack of a database. Keep claims proportional to the checks actually run. Never add real credentials, private input, or signing seeds to examples.
