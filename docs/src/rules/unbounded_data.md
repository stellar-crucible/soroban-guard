# SG-DATA-001: Unbounded State Collection Growth

- **Severity**: High
- **Category**: Storage Scalability / Resource Limits

## Description
Soroban contracts pay CPU and memory budget for every byte deserialized from storage, subject to a strict 64KB per-entry ledger limit. Modifying contract storage inside loops or continually appending to unbounded `Vec` or `Map` collections causes transactions to fail permanently once the size threshold is reached.

## Remediation
Avoid iterative writes in loops. Structure entries using composite indexed keys (e.g. `DataKey::UserBalance(Address)`) to allow fine-grained, constant-sized storage operations:

```rust
// Write directly to discrete partition key instead of array appending
env.storage().persistent().set(&DataKey::Record(id), &data);
```
