use crate::report::{Finding, FindingLevel, Remediation};
use crate::rules::{AuditRule, RuleId};
use crate::visitor::{ContractVisitor, StorageTier};

/// SG-TTL-001: Missing TTL auto-renewal on persistent storage mutations.
pub struct MissingTtlExtensionRule;

impl AuditRule for MissingTtlExtensionRule {
    fn id(&self) -> RuleId {
        RuleId::from("SG-TTL-001")
    }

    fn name(&self) -> &str {
        "Missing TTL Extension on Persistent Storage Mutation"
    }

    fn description(&self) -> &str {
        "Detects persistent or instance storage writes in public functions where no `extend_ttl` call is scheduled. Under Soroban state archival, unextended storage entries risk being archived upon TTL expiration."
    }

    fn check(&self, visitor: &ContractVisitor) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &visitor.functions {
            if !func.has_contractimpl {
                continue;
            }

            let has_persistent_writes = func
                .storage_writes
                .iter()
                .any(|s| s.tier == StorageTier::Persistent || s.tier == StorageTier::Instance);

            if has_persistent_writes && func.ttl_extensions.is_empty() {
                let write_line = func
                    .storage_writes
                    .iter()
                    .find(|s| s.tier == StorageTier::Persistent || s.tier == StorageTier::Instance)
                    .map(|s| s.line)
                    .unwrap_or(func.line);

                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    title: format!("Missing extend_ttl for storage write in `{}`", func.name),
                    level: FindingLevel::High,
                    description: format!(
                        "Function `{}` writes to persistent or instance storage at line {} without executing `extend_ttl`. Entries may become archived and inaccessible to callers if TTL is depleted.",
                        func.name, write_line
                    ),
                    file: String::new(),
                    line: write_line,
                    target: func.name.clone(),
                    remediation: Remediation {
                        advice: "Schedule a TTL extension on the affected storage key using `env.storage().persistent().extend_ttl(&key, threshold, extend_to)` to avoid state archival.".to_string(),
                        code_patch: Some(
                            "env.storage().persistent().set(&key, &val);\nenv.storage().persistent().extend_ttl(&key, 10_000, 50_000);".to_string(),
                        ),
                        testkit_invariant: Some(
                            "#[test]\nfn test_ttl_retention() {\n    let env = Env::default();\n    // Verify TTL threshold in soroban-testkit\n    soroban_testkit::fixtures::advance_ledgers(&env, 10_000);\n    assert!(client.try_get_data().is_ok());\n}".to_string(),
                        ),
                    },
                });
            }
        }

        findings
    }
}
