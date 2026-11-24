# Soroban Guard

**Soroban Guard** is an advanced static security analysis and invariant synthesis engine purpose-built for Soroban smart contracts on the Stellar network.

Part of the **Stellar Crucible** triad:
- [soroban-testkit](https://github.com/stellar-crucible/soroban-testkit): Contract testing harnesses, property testing, and mock ledger environments.
- [soroban-guard](https://github.com/stellar-crucible/soroban-guard): AST static security auditing and testkit invariant synthesizer.
- [soroban-bench](https://github.com/stellar-crucible/soroban-bench): Continuous macro-benchmarking and storage rent stress simulation.

## Key Features

- **Static AST Analysis**: Detects Soroban-specific anti-patterns and vulnerabilities without compiling to WASM.
- **Rule Engine**: Includes checks for missing authorization, temporary storage balance hazards, checks-effects-interactions reentrancy violations, division precision dust, and unprotected contract upgrades.
- **Automatic Test Synthesis**: Turns discovered vulnerabilities directly into runnable `soroban-testkit` invariant regression test cases.
- **CI / SARIF Ready**: Emits GitHub Code Scanning SARIF or Markdown reports for pull request comments.
