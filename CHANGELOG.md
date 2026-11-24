# Changelog

All notable changes to `soroban-guard` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-24

### Added
- **Generative Proptest Synthesis (`--proptest`)**: Generates runnable `proptest!` macro blocks connecting synthesized invariants to `soroban_testkit_generators` strategies (`arb_address`, `arb_i128`, `arb_symbol`) (closes #5).
- Configurable proptest case iterations (`--cases 500`).

## [0.3.0] - 2026-11-24

### Added
- **Diff-Audit Mode (`--diff`)**: Supports auditing contract changes against baseline commits or files, reporting only newly introduced security findings (closes #9).
- **Example Contracts**: `examples/contracts/vulnerable_vault.rs` and hardened `examples/contracts/secure_vault.rs`.
- **End-to-End Triad Tutorial**: Published comprehensive tutorial connecting `soroban-guard`, `soroban-testkit`, and `soroban-bench`.
- Community governance policies: `SECURITY.md` and `CODE_OF_CONDUCT.md`.

## [0.2.0] - 2026-11-24

### Added
- **SG-AUTH-002**: Cross-contract invocation sub-authentication propagation audit rule.
- **SG-DATA-001**: Unbounded storage collection growth and loops performing repeated state writes.
- **Interactive HTML Report**: Single-page responsive HTML report with vulnerability severity breakdown (`render_html()`).
- High-level Mermaid architecture flowchart in `README.md`.

## [0.1.0] - 2026-11-24

### Added
- Initial release of Soroban Guard AST security analysis engine.
- Rules: `SG-AUTH-001`, `SG-STOR-001`, `SG-REENT-001`, `SG-ARITH-001`, `SG-UPG-001`, `SG-TTL-001`, `SG-MINT-001`.
- Exporters: GitHub-flavored Markdown, SARIF v2.1.0, terminal colorized diagnostics.
- `synth-testkit` invariant synthesis engine.
