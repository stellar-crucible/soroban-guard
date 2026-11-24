use crate::report::{Finding, FindingLevel, Remediation};
use crate::rules::{AuditRule, RuleId};
use crate::visitor::ContractVisitor;

/// SG-UPG-001: Unprotected or untracked contract upgrade logic.
pub struct UnprotectedUpgradeRule;

impl AuditRule for UnprotectedUpgradeRule {
    fn id(&self) -> RuleId {
        RuleId::from("SG-UPG-001")
    }

    fn name(&self) -> &str {
        "Unprotected Contract WASM Upgrade"
    }

    fn description(&self) -> &str {
        "Detects calls to `update_current_contract_wasm` without rigorous administrator authorization or governance verification."
    }

    fn check(&self, visitor: &ContractVisitor) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &visitor.functions {
            if func.has_upgrade_call && func.auth_checks.is_empty() {
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    title: format!("Unprotected contract upgrade in `{}`", func.name),
                    level: FindingLevel::Critical,
                    description: format!(
                        "Function `{}` executes `update_current_contract_wasm` without requiring caller authentication. Any malicious caller could overwrite contract logic.",
                        func.name
                    ),
                    file: String::new(),
                    line: func.line,
                    target: func.name.clone(),
                    remediation: Remediation {
                        advice: "Enforce admin signature verification (`admin.require_auth()`) or a multi-signature timelock before invoking `env.deployer().update_current_contract_wasm(new_wasm_hash)`.".to_string(),
                        code_patch: Some(
                            "pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) {\n    admin.require_auth();\n    assert_admin(&env, &admin);\n    env.deployer().update_current_contract_wasm(new_wasm_hash);\n}".to_string(),
                        ),
                        testkit_invariant: Some(
                            "soroban_testkit::upgrade::assert_upgrade_auth_required(&env, &contract_id);".to_string(),
                        ),
                    },
                });
            }
        }

        findings
    }
}
