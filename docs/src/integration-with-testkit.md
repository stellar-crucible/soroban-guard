# Integration with soroban-testkit

One of the foundational principles of the Stellar Crucible ecosystem is that **static analysis and dynamic property testing must reinforce each other**.

When `soroban-guard` identifies a potential security hazard in your contract, you can automatically synthesize a `soroban-testkit` invariant harness:

```bash
soroban-guard synth-testkit contracts/ --output tests/security_invariants.rs
```

The synthesized test harness generates concrete mock test cases using `soroban-testkit` assertions:

```rust
#[test]
fn test_deposit_unauthorized_fails() {
    let env = Env::default();
    let client = VaultContractClient::new(&env, &contract_id);
    let attacker = Address::generate(&env);

    // Verified by soroban-testkit
    let result = client.try_deposit(&attacker, &1_000);
    assert!(result.is_err(), "Unauthorized deposit must fail");
}
```

By adding the synthesized tests to your test suite, any future regression is caught both statically by `soroban-guard` and dynamically in property tests by `soroban-testkit`.
