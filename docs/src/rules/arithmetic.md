# SG-ARITH-001: Division Precision Loss

- **Severity**: Warning
- **Category**: Arithmetic / Tokenomics

## Description
Detects integer division operations `/` that truncate fractional values, potentially causing precision loss, rounding dust leaks, or zeroed transaction fees.

## Remediation
Perform all multiplications prior to divisions and preserve remaining fractions or dust:

```rust
let fee = amount.checked_mul(fee_bps).ok_or(Error::Overflow)?
    .checked_div(10_000).ok_or(Error::DivisionByZero)?;
```
