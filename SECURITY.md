# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Only the latest published minor is supported. This crate is pre-1.0, so minor bumps may enhance rule engines or change public APIs; security fixes land in a new release rather than being back-ported to older minors.

## Reporting a Vulnerability

If you discover a security vulnerability in Soroban Guard, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email the maintainers directly or use GitHub's private vulnerability reporting feature on this repository.

We aim to acknowledge reports within 48 hours and provide an initial assessment within one week.

## Automated Pull Request Security Gates

`main` is protected. Four required automated security checks report on every pull request:

| Check | Workflow | Purpose |
| ----- | -------- | ------- |
| `Malware guard` | `ci.yml` | Scans the git diff against anomalous process execution, network reaches, or obfuscated payloads before code is compiled. |
| `Secret scan` | `security.yml` | Scans added lines for tokens, credentials, and private key shapes. |
| `CI integrity` | `security.yml` | Verifies pipeline permissions, action commit SHA pins, and trigger safety. |
| `Supply chain audit` | `ci.yml` | Runs `cargo-deny` checking RustSec advisories, licenses, sources, and bans. |
