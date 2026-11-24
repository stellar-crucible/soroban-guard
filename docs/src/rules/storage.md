# SG-STOR-001: Temporary Storage Hazard

- **Severity**: High
- **Category**: Storage Lifecycle / Data Persistence

## Description
Soroban contracts provide three distinct storage tiers:
1. `instance()`: Lives as long as the contract instance.
2. `persistent()`: Kept alive across transactions, can be archived and restored.
3. `temporary()`: Discarded upon TTL expiry without any restoration mechanism.

Using temporary storage for user balances or allowance records risks irreversible token loss if TTL elapses.

## Remediation
Use persistent or instance storage for balances and actively extend entry TTLs:

```rust
env.storage().persistent().set(&balance_key, &new_balance);
env.storage().persistent().extend_ttl(&balance_key, 10_000, 50_000);
```
