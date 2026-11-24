# SG-TTL-001: Missing TTL Extension

- **Severity**: High
- **Category**: Storage Lifecycle / State Archival

## Description
Under Soroban's state archival mechanism, entries in persistent or instance storage have a Time To Live (TTL) in ledger sequences. If a contract modifies storage without extending its TTL via `extend_ttl`, the entry will eventually be archived, causing user transactions to fail unexpectedly.

## Remediation
Schedule an `extend_ttl` invocation on the modified storage key:

```rust
env.storage().persistent().set(&key, &value);
env.storage().persistent().extend_ttl(&key, 10_000, 50_000);
```
