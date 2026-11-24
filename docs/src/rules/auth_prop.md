# SG-AUTH-002: Cross-Contract Auth Propagation

- **Severity**: High
- **Category**: Authorization / Cross-Contract Invocations

## Description
When invoking an external contract via a generated client (`client.transfer(...)`), the caller's authorization context does not propagate implicitly. Unless `env.authorize_as_current_contract(...)` or explicit sub-invocations are configured, downstream calls risk authorization failure or permission spoofing.

## Remediation
Authorize sub-invocations explicitly before calling downstream contracts:

```rust
env.authorize_as_current_contract(vec![&env, ...]);
client.transfer(&to, &amount);
```
