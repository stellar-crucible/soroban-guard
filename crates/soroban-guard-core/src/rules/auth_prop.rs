use crate::report::{Finding, FindingLevel, Remediation};
use crate::rules::{AuditRule, RuleId};
use crate::visitor::ContractVisitor;

/// SG-AUTH-002: Cross-contract invocation authorization propagation audit.
pub struct AuthPropagationRule;

impl AuditRule for AuthPropagationRule {
    fn id(&self) -> RuleId {
        RuleId::from("SG-AUTH-002")
    }

    fn name(&self) -> &str {
        "Cross-Contract Authorization Propagation Hazard"
    }

    fn description(&self) -> &str {
        "Detects public functions that forward caller actions to external contracts without explicitly verifying sub-invocation authorization or invoking authorize_as_current_contract."
    }

    fn check(&self, visitor: &ContractVisitor) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &visitor.functions {
            if !func.has_contractimpl {
                continue;
            }

            // If function performs external contract calls
            if !func.external_calls.is_empty() && !func.has_auth_propagation {
                let call_line = func.external_calls[0].line;
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    title: format!("Missing sub-invocation auth propagation in `{}`", func.name),
                    level: FindingLevel::High,
                    description: format!(
                        "Function `{}` invokes external contract `{}` at line {} without explicit sub-invocation authorization. Downstream contract may fail authorization checks.",
                        func.name, func.external_calls[0].callee, call_line
                    ),
                    file: String::new(),
                    line: call_line,
                    target: func.name.clone(),
                    remediation: Remediation {
                        advice: "Explicitly grant contract authorization using `env.authorize_as_current_contract(...)` or verify `require_auth_for_args` for delegated signer payloads.".to_string(),
                        code_patch: Some(
                            "// Authorize downstream contract call on behalf of current contract\nenv.authorize_as_current_contract(vec![&env, ...]);\nclient.transfer(&to, &amount);".to_string(),
                        ),
                        testkit_invariant: Some(
                            "soroban_testkit::mock::assert_sub_invocations_authorized(&env, &contract_id);".to_string(),
                        ),
                    },
                });
            }
        }

        findings
    }
}
