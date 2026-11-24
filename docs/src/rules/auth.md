# SG-AUTH-001: Missing Authentication Verification

- **Severity**: Critical
- **Category**: Authorization / Access Control

## Description
This rule detects public functions exposed via `#[contractimpl]` that perform storage mutations or asset balance updates without verifying caller authority via `require_auth()` or `require_auth_for_args()`.

## Remediation
Enforce authentication on all signer arguments before executing any state changes:

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    // ... logic
}
```
