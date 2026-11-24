# soroban-guard

> Static analysis, AST vulnerability rules, and automated security audit linter for Soroban smart contracts.

`soroban-guard` inspects Soroban Rust smart contracts and checks for common security antipatterns, missing authentication checks, storage TTL pitfalls, reentrancy hazards, and arithmetic rounding flaws before deployment.

It is part of the **Stellar Crucible** developer suite, designed to work directly alongside [`soroban-testkit`](https://github.com/stellar-crucible/soroban-testkit) and [`soroban-bench`](https://github.com/stellar-crucible/soroban-bench).

---

## Features

- **Auth Rule Engine**: Detects state-mutating functions lacking `require_auth()` checks on addresses or invokers.
- **Storage & TTL Auditing**: Identifies unsafe usage of temporary storage for critical balances, unmetered collections, and missing TTL bump routines.
- **Reentrancy Analysis**: Flags external cross-contract calls executed prior to local storage mutations without protective state locks.
- **Precision & Arithmetic Checks**: Detects division-before-multiplication patterns and unhandled rounding dust.
- **Test Invariant Synthesis**: Generates runnable [`soroban-testkit`](https://github.com/stellar-crucible/soroban-testkit) invariant property test templates to verify identified risks.
- **CI / SARIF Output**: Produces GitHub code scanning SARIF, Markdown summary reports, and colored terminal outputs.

---

## Installation

```bash
cargo install --locked soroban-guard-cli
```

Or add the analysis library to your development harness:

```toml
[dev-dependencies]
soroban-guard-core = "0.1.0"
```

---

## Quick Start

Run an audit on a contract crate:

```bash
soroban-guard check --path ./contracts/my-token
```

Output formats:
```bash
soroban-guard check --path . --format sarif --output audit-results.sarif
soroban-guard check --path . --format markdown --output security-report.md
```

---

## Documentation

Full documentation, rule specifications, and remediation guides are available at [stellar-crucible.github.io/soroban-guard](https://stellar-crucible.github.io/soroban-guard/).
