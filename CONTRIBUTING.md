# Contributing to Soroban Guard

Thank you for your interest in contributing to **Soroban Guard**, part of the **Stellar Crucible** developer tooling ecosystem!

## Development Setup

1. **Prerequisites**:
   - Rust 1.85+ (`rustup toolchain install stable`)
   - Components: `rustfmt`, `clippy`

2. **Clone and Build**:
   ```bash
   git clone https://github.com/stellar-crucible/soroban-guard.git
   cd soroban-guard
   cargo build --workspace
   ```

3. **Run Tests & Lints**:
   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```

## Adding a New Security Rule

1. Create a new module under `crates/soroban-guard-core/src/rules/<rule_name>.rs`.
2. Implement the `AuditRule` trait.
3. Register the rule in `crates/soroban-guard-core/src/rules/mod.rs` inside `RuleRegistry::default_rules()`.
4. Add comprehensive unit and integration tests under `crates/soroban-guard-core/tests/`.
5. Add documentation for the rule in `docs/src/rules/<rule_name>.md` and register it in `docs/src/SUMMARY.md`.
6. Include remediation code patches and `soroban-testkit` invariant test snippets.
