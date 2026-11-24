# SG-REENT-001: State Mutation After External Call

- **Severity**: High
- **Category**: Checks-Effects-Interactions

## Description
Flags functions where contract storage writes occur after cross-contract invocations. Cross-contract calls can introduce external reentrancy vulnerabilities or unpredictable ledger state changes.

## Remediation
Follow the checks-effects-interactions pattern:
1. Validate inputs and preconditions.
2. Mutate contract state locally.
3. Invoke external contracts.
