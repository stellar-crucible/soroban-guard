# SG-UPG-001: Unprotected Contract Upgrade

- **Severity**: Critical
- **Category**: Governance / Contract Upgradeability

## Description
Soroban allows contract bytecode replacement using `env.deployer().update_current_contract_wasm(new_wasm_hash)`. If this call is reachable without strict admin access control or multisig authorization, any caller can hijack the contract logic.

## Remediation
Enforce admin authentication and verify admin credentials against stored state:

```rust
pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) {
    admin.require_auth();
    let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
    if admin != stored_admin {
        panic!("Unauthorized upgrade attempt");
    }
    env.deployer().update_current_contract_wasm(new_wasm_hash);
}
```
