# Security model

PARG is a research prototype, not a production security certification.

## Adversary

The worker may submit missing receipts, alter fields, use old receipts, race requests, request fresh authorization, stop communicating, or replay committed operations. It possesses only its configured worker bearer token. The trusted policy process, ledger, PostgreSQL, keyring provisioning, and host kernel remain correct and uncompromised.

## Claims and exclusions

The implementation is designed to authorize exact, version-bound transfers at most once through atomic ledger transactions. A compromised worker may still perform anything its configured principal and policy legitimately allow. Signatures do not establish user intent, absence of compromise, confidentiality, or availability.

There is no SGX, SEV-SNP, VMPL, eBPF trust root, hardware attestation, or resistance to a malicious host administrator. Process/container boundaries are the prototype deployment mechanism. Remote deployment requires authenticated TLS; the Compose demonstration uses local HTTP and a dedicated internal database network.

Use synthetic inputs only. Never commit `.env`, private seeds, database dumps, or tokens. Do not post secrets or private payloads in public issues. Report reproducible vulnerabilities through the owner's published private contact channel.
