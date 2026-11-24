# Stellar Crucible Triad: End-to-End Tutorial

This tutorial demonstrates the end-to-end workflow connecting **`soroban-guard`**, **`soroban-testkit`**, and **`soroban-bench`** in a continuous smart contract development and security lifecycle.

---

## The Workflow Overview

```text
[Contract Source]
       │
       ▼
 1. soroban-guard check ──► AST Static Security Audit
       │
       ▼
 2. soroban-guard synth-testkit ──► Synthesize Property Invariants
       │
       ▼
 3. soroban-testkit ──► Run Dynamic Tests & Mock Host Ledger
       │
       ▼
 4. soroban-bench run & profile ──► Macro-Benchmark & Gas Call-Tree Attribution
       │
       ▼
 5. soroban-bench export-testkit ──► Lock Budget Ceilings into CI Invariant Tests
```

---

## Step 1: Static Security Auditing with `soroban-guard`

Run an AST audit against your contract source files before compiling to WebAssembly:

```bash
soroban-guard check examples/contracts/ --format html > audit_report.html
```

If hazards are detected (e.g. `SG-AUTH-001` missing auth or `SG-STOR-001` temporary storage hazard), synthesize runnable invariant tests:

```bash
soroban-guard synth-testkit examples/contracts/ --output tests/security_invariants.rs
```

---

## Step 2: Invariant Verification with `soroban-testkit`

Execute the synthesized property tests against mock Soroban host environments:

```bash
cargo test --test security_invariants
```

`soroban-testkit` generates randomized accounts, assets, and storage states to prove that unauthorized callers cannot execute protected operations.

---

## Step 3: Performance & Gas Profiling with `soroban-bench`

Define your production user journey in a scenario TOML file (e.g. `examples/scenarios/liquidity_pool.toml`):

```bash
# Execute macro benchmark with HTML dashboard
soroban-bench run examples/scenarios/liquidity_pool.toml --format html --output perf_report.html

# Profile nested cross-contract invocation gas attribution
soroban-bench profile examples/scenarios/liquidity_pool.toml
```

---

## Step 4: Storage Rent & Archival Forecasting

Calculate 30, 90, and 365-day TTL retention fees and Stellar Protocol 20–22 restoration costs:

```bash
soroban-bench rent --bytes 2048 --tier persistent --ttl 100000 --protocol 22
```

---

## Step 5: Exporting Budget Boundaries to `soroban-testkit`

Lock your benchmark findings into automated regression tests:

```bash
soroban-bench export-testkit examples/scenarios/liquidity_pool.toml --output tests/benchmark_invariant.rs
```

Running `cargo test` now automatically validates both security invariants (from `soroban-guard`) and budget limits (from `soroban-bench`) inside `soroban-testkit`.
