use crate::report::{Finding, FindingLevel, Remediation};
use crate::rules::{AuditRule, RuleId};
use crate::visitor::ContractVisitor;

/// SG-DATA-001: Unbounded Vec and Map state growth hazard detection.
pub struct UnboundedDataGrowthRule;

impl AuditRule for UnboundedDataGrowthRule {
    fn id(&self) -> RuleId {
        RuleId::from("SG-DATA-001")
    }

    fn name(&self) -> &str {
        "Unbounded State Collection Growth Hazard"
    }

    fn description(&self) -> &str {
        "Detects loops performing iterative storage writes or unbounded collection appends (`push_back`, `insert`) inside state-modifying functions. Under Soroban, exceeding the 64KB ledger entry size limit causes irrecoverable transaction reverts."
    }

    fn check(&self, visitor: &ContractVisitor) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &visitor.functions {
            if !func.has_contractimpl {
                continue;
            }

            if !func.writes_in_loop.is_empty() {
                let write_line = func.writes_in_loop[0].line;
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    title: format!("Iterative storage modification in loop in `{}`", func.name),
                    level: FindingLevel::High,
                    description: format!(
                        "Function `{}` executes {} storage write(s) inside a loop starting at line {}. Iterative storage updates consume excessive write bytes and risk hitting entry size caps.",
                        func.name,
                        func.writes_in_loop.len(),
                        write_line
                    ),
                    file: String::new(),
                    line: write_line,
                    target: func.name.clone(),
                    remediation: Remediation {
                        advice: "Avoid writing to storage inside loops. Batch updates into a single composite struct or partition data using discrete indexed keys (e.g. `DataKey::Item(u32)`).".to_string(),
                        code_patch: Some(
                            "// Instead of writing in a loop, write to a discrete indexed key:\nenv.storage().persistent().set(&DataKey::UserRecord(user_id), &record);".to_string(),
                        ),
                        testkit_invariant: Some(
                            "soroban_testkit::budget::assert_entry_size_under(&env, &contract_id, &key, 10_000);".to_string(),
                        ),
                    },
                });
            }
        }

        findings
    }
}
