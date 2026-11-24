use crate::report::{Finding, FindingLevel, Remediation};
use crate::rules::{AuditRule, RuleId};
use crate::visitor::ContractVisitor;

/// SG-AUTH-001: Missing require_auth on state-mutating contract functions.
pub struct MissingAuthRule;

impl AuditRule for MissingAuthRule {
    fn id(&self) -> RuleId {
        RuleId::from("SG-AUTH-001")
    }

    fn name(&self) -> &str {
        "Missing Authentication Verification"
    }

    fn description(&self) -> &str {
        "Detects state-modifying Soroban functions that write to contract storage without calling `require_auth()` or `require_auth_for_args()` on caller addresses."
    }

    fn check(&self, visitor: &ContractVisitor) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &visitor.functions {
            // Only inspect public contractimpl methods
            if !func.has_contractimpl {
                continue;
            }

            // Exclude read-only initialization queries or views without writes
            if func.storage_writes.is_empty() {
                continue;
            }

            // If storage writes exist but no auth check was recorded
            if func.auth_checks.is_empty() {
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    title: format!("Missing require_auth check in `{}`", func.name),
                    level: FindingLevel::Critical,
                    description: format!(
                        "Function `{}` executes {} storage write(s) without enforcing caller authentication via `require_auth()`.",
                        func.name,
                        func.storage_writes.len()
                    ),
                    file: String::new(),
                    line: func.line,
                    target: func.name.clone(),
                    remediation: Remediation {
                        advice: "Verify that the caller or authorized signer invokes `address.require_auth()` before persisting state mutations.".to_string(),
                        code_patch: Some(format!(
                            "pub fn {}(env: Env, caller: Address, ...) {{\n    caller.require_auth();\n    // ... state mutations\n}}",
                            func.name
                        )),
                        testkit_invariant: Some(format!(
                            "#[test]\nfn test_{}_unauthorized_fails() {{\n    let env = Env::default();\n    let client = ContractClient::new(&env, &contract_id);\n    let impostor = Address::generate(&env);\n    // soroban-testkit assert auth failure\n    let res = client.try_{}(&impostor);\n    assert!(res.is_err());\n}}",
                            func.name, func.name
                        )),
                    },
                });
            }
        }

        findings
    }
}
