use crate::report::{Finding, FindingLevel, Remediation};
use crate::rules::{AuditRule, RuleId};
use crate::visitor::ContractVisitor;

/// SG-MINT-001: Unbounded minting or unchecked total supply cap.
pub struct UnboundedMintRule;

impl AuditRule for UnboundedMintRule {
    fn id(&self) -> RuleId {
        RuleId::from("SG-MINT-001")
    }

    fn name(&self) -> &str {
        "Unbounded Minting Routine Lacking Supply Cap"
    }

    fn description(&self) -> &str {
        "Detects token minting or asset creation functions that execute without verifying total supply limits or validating maximum mint caps."
    }

    fn check(&self, visitor: &ContractVisitor) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &visitor.functions {
            if !func.has_contractimpl {
                continue;
            }

            let name_lower = func.name.to_lowercase();
            let is_mint_function = name_lower.contains("mint") || name_lower.contains("issue");

            if is_mint_function {
                // If it writes to storage and lacks auth checks or cap guards
                let has_writes = !func.storage_writes.is_empty();
                if has_writes && func.auth_checks.is_empty() {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        title: format!("Unrestricted token mint in `{}`", func.name),
                        level: FindingLevel::Critical,
                        description: format!(
                            "Function `{}` mints new assets and modifies contract storage without enforcing caller authorization (`require_auth`). Anyone can mint unlimited tokens.",
                            func.name
                        ),
                        file: String::new(),
                        line: func.line,
                        target: func.name.clone(),
                        remediation: Remediation {
                            advice: "Enforce strict minter authorization and assert that the minted amount does not breach the protocol supply cap.".to_string(),
                            code_patch: Some(
                                "pub fn mint(env: Env, admin: Address, to: Address, amount: i128) {\n    admin.require_auth();\n    let supply = get_total_supply(&env);\n    assert!(supply.checked_add(amount).unwrap() <= MAX_SUPPLY, \"Cap exceeded\");\n    // ... mint logic\n}".to_string(),
                            ),
                            testkit_invariant: Some(
                                "soroban_testkit::proptest::assert_total_supply_cap(&env, &token_id, MAX_SUPPLY);".to_string(),
                            ),
                        },
                    });
                }
            }
        }

        findings
    }
}
