use crate::report::{Finding, FindingLevel, Remediation};
use crate::rules::{AuditRule, RuleId};
use crate::visitor::ContractVisitor;

/// SG-REENT-001: State mutation after external contract invocation.
pub struct StateMutationAfterCallRule;

impl AuditRule for StateMutationAfterCallRule {
    fn id(&self) -> RuleId {
        RuleId::from("SG-REENT-001")
    }

    fn name(&self) -> &str {
        "State Mutation Following External Call (Checks-Effects-Interactions Violation)"
    }

    fn description(&self) -> &str {
        "Flags methods where storage updates occur on lines subsequent to an external cross-contract call. While Soroban uses reentrancy prevention at the host level, cross-contract callback state discrepancies remain hazardous."
    }

    fn check(&self, visitor: &ContractVisitor) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &visitor.functions {
            if func.external_calls.is_empty() || func.storage_writes.is_empty() {
                continue;
            }

            let first_ext_call = func.external_calls.iter().min_by_key(|c| c.line);
            if let Some(ext) = first_ext_call {
                let subsequent_writes: Vec<_> = func
                    .storage_writes
                    .iter()
                    .filter(|w| w.line > ext.line)
                    .collect();

                if !subsequent_writes.is_empty() {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        title: format!("State mutation after external call in `{}`", func.name),
                        level: FindingLevel::High,
                        description: format!(
                            "Function `{}` executes an external contract call at line {} before committing storage modifications at line {}. This violates the checks-effects-interactions pattern.",
                            func.name, ext.line, subsequent_writes[0].line
                        ),
                        file: String::new(),
                        line: subsequent_writes[0].line,
                        target: func.name.clone(),
                        remediation: Remediation {
                            advice: "Reorganize the function body so all storage checks and updates execute before initiating any cross-contract invocations.".to_string(),
                            code_patch: Some(
                                "// 1. Check conditions\n// 2. Effect: update local contract storage\nenv.storage().persistent().set(&key, &new_val);\n// 3. Interaction: invoke external contract\nclient.transfer(&to, &amount);".to_string(),
                            ),
                            testkit_invariant: Some(
                                "soroban_testkit::mock::assert_no_state_mutation_during_callback(&env);".to_string(),
                            ),
                        },
                    });
                }
            }
        }

        findings
    }
}
