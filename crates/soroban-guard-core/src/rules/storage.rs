use crate::report::{Finding, FindingLevel, Remediation};
use crate::rules::{AuditRule, RuleId};
use crate::visitor::{ContractVisitor, StorageTier};

/// SG-STOR-001: Temporary storage used for persistent contract state / account balances.
pub struct TemporaryStorageHazardRule;

impl AuditRule for TemporaryStorageHazardRule {
    fn id(&self) -> RuleId {
        RuleId::from("SG-STOR-001")
    }

    fn name(&self) -> &str {
        "Hazardous Use of Temporary Storage for Critical State"
    }

    fn description(&self) -> &str {
        "Detects temporary storage allocations in functions modifying user balances or allowance records. Temporary storage entries are purged upon TTL expiration and cannot be restored."
    }

    fn check(&self, visitor: &ContractVisitor) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &visitor.functions {
            let temp_writes: Vec<_> = func
                .storage_writes
                .iter()
                .filter(|s| s.tier == StorageTier::Temporary)
                .collect();

            if !temp_writes.is_empty() {
                let name_lower = func.name.to_lowercase();
                let is_critical_domain = name_lower.contains("balance")
                    || name_lower.contains("transfer")
                    || name_lower.contains("mint")
                    || name_lower.contains("deposit")
                    || name_lower.contains("stake")
                    || name_lower.contains("vault");

                if is_critical_domain {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        title: format!("Temporary storage write in balance/asset function `{}`", func.name),
                        level: FindingLevel::High,
                        description: format!(
                            "Function `{}` writes to temporary storage (`env.storage().temporary()`). Temporary storage is subject to ledger eviction when TTL expires, risking loss of user balances.",
                            func.name
                        ),
                        file: String::new(),
                        line: temp_writes[0].line,
                        target: func.name.clone(),
                        remediation: Remediation {
                            advice: "Store persistent user balances using `env.storage().persistent()` or `instance()`, and manage TTL extension explicitly via `extend_ttl`.".to_string(),
                            code_patch: Some(
                                "env.storage().persistent().set(&key, &balance);\nenv.storage().persistent().extend_ttl(&key, 10_000, 50_000);".to_string(),
                            ),
                            testkit_invariant: Some(
                                "soroban_testkit::budget::assert_storage_tier_persistent(&env, &contract_id, &key);".to_string(),
                            ),
                        },
                    });
                }
            }
        }

        findings
    }
}
