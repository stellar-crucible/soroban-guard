# SG-MINT-001: Unbounded Minting Routine

- **Severity**: Critical
- **Category**: Tokenomics / Access Control

## Description
Detects public contract functions with names like `mint` or `issue` that modify storage without requiring authentication (`caller.require_auth()`) or validating against a maximum total supply cap.

## Remediation
Enforce administrator verification and validate supply caps before minting:

```rust
pub fn mint(env: Env, admin: Address, to: Address, amount: i128) {
    admin.require_auth();
    let current_supply = get_supply(&env);
    assert!(current_supply.checked_add(amount).unwrap() <= MAX_SUPPLY, "Supply cap breached");
    // ... logic
}
```
