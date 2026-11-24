# Getting Started

## Installation

Install the CLI tool with `cargo`:

```bash
cargo install --path crates/soroban-guard-cli
```

Or add the core analysis library to your build/audit pipeline:

```toml
[dependencies]
soroban-guard-core = { git = "https://github.com/stellar-crucible/soroban-guard" }
```

## Running an Audit

Audit all contracts in your workspace:

```bash
soroban-guard check .
```

Generate a Markdown summary:

```bash
soroban-guard check contracts/ --format markdown > audit-report.md
```

Produce SARIF for GitHub Code Scanning:

```bash
soroban-guard check contracts/ --format sarif > results.sarif
```
