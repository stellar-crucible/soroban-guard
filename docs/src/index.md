# Soroban Guard

**Soroban Guard** is an advanced static security analysis and invariant synthesis engine purpose-built for Soroban smart contracts on the Stellar network.

Part of the **Stellar Crucible** smart contract engineering triad:
- [soroban-testkit](https://github.com/stellar-crucible/soroban-testkit): Dynamic property testing, mock ledger environments, and budget snapshots.
- [soroban-guard](https://github.com/stellar-crucible/soroban-guard): Static AST security auditing and testkit invariant synthesizer.
- [soroban-bench](https://github.com/stellar-crucible/soroban-bench): Continuous macro-benchmarking, gas regression baselines, and storage rent simulations.

---

## Why Soroban Guard?

Smart contracts on Stellar (Soroban) run as compiled WebAssembly (WASM) inside a host-metered environment. While functional unit testing is essential, relying solely on runtime tests and compiled WASM audits leaves critical security vulnerabilities undiscovered:

1. **Opaque WASM Bytecode**: Once Rust contract code is compiled to WebAssembly, rich semantic information—type definitions, variable lifetimes, struct field visibility, and high-level authorization annotations like `require_auth()`—is stripped or obscured.
2. **Runtime Test Blind Spots**: Unit and property test suites only verify execution paths that test authors deliberately design. Critical vulnerabilities—such as missing caller authentication on administrative functions, unauthenticated contract upgrades, or arithmetic precision loss in token distributions—routinely pass standard tests unnoticed.
3. **Soroban-Specific Storage Hazards**: Soroban features three distinct storage tiers (**Persistent**, **Instance**, and **Temporary**) with active TTL lifecycles. Storing financial balances in Temporary storage or writing to Persistent storage without TTL renewal will lock or destroy contract state.
4. **Sub-second Feedback Loop**: Full WASM compilation and test suites take minutes. `soroban-guard` parses raw Rust Abstract Syntax Trees (AST) directly, providing sub-second feedback inside developer IDEs and GitHub pull request CI gates before WASM binaries are ever produced.

---

## How It Works

Soroban Guard operates as a multi-stage static analysis and automated verification pipeline:

1. **AST Extraction (`syn`)**: Rust source files are parsed into strongly typed syntax trees via `syn`, identifying contract implementations marked with `#[contractimpl]` and struct configurations marked with `#[contracttype]`.
2. **Contextual Analysis (`ContractVisitor` & `FunctionAnalyzer`)**: The engine walks through every method body, recording state-modifying operations, authorization assertions (`require_auth`), cross-contract calls, and loop / arithmetic patterns.
3. **Rule Matching & Severity Scoring**: Discovered patterns are checked against specialized security rules (`SG-*`). Findings are assigned standardized severity ratings (**Critical**, **High**, **Warning**, **Info**) with file and line annotations.
4. **Multi-Format Export**: Findings are serialized into GitHub Markdown, SARIF v2.1.0 for automatic code scanning PR annotations, and standalone responsive HTML reports.
5. **Symbiotic Invariant Synthesis (`synth-testkit`)**: When a potential vulnerability is identified, `soroban-guard` synthesizes runnable `soroban-testkit` invariant regression tests to prove and guard against the issue in runtime test suites.
