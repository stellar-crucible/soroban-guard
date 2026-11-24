use crate::report::{Finding, FindingLevel, Remediation};
use crate::rules::{AuditRule, RuleId};
use crate::visitor::ContractVisitor;

/// SG-ARITH-001: Division precision loss and dust vulnerabilities.
pub struct DivisionPrecisionRule;

impl AuditRule for DivisionPrecisionRule {
    fn id(&self) -> RuleId {
        RuleId::from("SG-ARITH-001")
    }

    fn name(&self) -> &str {
        "Division Before Multiplication / Integer Precision Loss"
    }

    fn description(&self) -> &str {
        "Detects integer division operators `/` in contract code without explicit remainder or scale handling. Division in integer arithmetic truncates fractions, potentially leading to zeroed fees or stolen dust."
    }

    fn check(&self, visitor: &ContractVisitor) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &visitor.functions {
            if !func.division_calls.is_empty() {
                for div_op in &func.division_calls {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        title: format!("Integer division precision hazard in `{}`", func.name),
                        level: FindingLevel::Warning,
                        description: format!(
                            "Integer division (`/`) detected in `{}` at line {}. Integer division truncates towards zero. If subsequent multiplications occur or remainders are discarded, value leakages may arise.",
                            func.name, div_op.line
                        ),
                        file: String::new(),
                        line: div_op.line,
                        target: func.name.clone(),
                        remediation: Remediation {
                            advice: "Multiply before dividing or use checked fixed-point math libraries (e.g. basis points with 10_000 denominator) and explicitly account for remainder dust.".to_string(),
                            code_patch: Some(
                                "// Calculate: (amount * fee_bps) / 10_000\nlet fee = amount.checked_mul(fee_bps).ok_or(Error::Overflow)?.checked_div(10_000).ok_or(Error::DivisionByZero)?;".to_string(),
                            ),
                            testkit_invariant: Some(
                                "soroban_testkit::proptest::check_rounding_invariants(|amount, fee_bps| ...);".to_string(),
                            ),
                        },
                    });
                }
            }
        }

        findings
    }
}
