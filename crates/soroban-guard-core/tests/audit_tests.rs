use soroban_guard_core::report::FindingLevel;
use soroban_guard_core::{AuditConfig, SorobanAuditor};

const VULNERABLE_CONTRACT: &str = r#"
use soroban_sdk::{contract, contractimpl, Address, Env, BytesN};

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    pub fn deposit(env: Env, caller: Address, amount: i128) {
        // Missing caller.require_auth()!
        // Storage write to temporary storage for balance
        env.storage().temporary().set(&caller, &amount);
    }

    pub fn calculate_fee(amount: i128, bps: i128) -> i128 {
        // Division precision loss
        amount / bps
    }

    pub fn upgrade_contract(env: Env, new_wasm: BytesN<32>) {
        // Unprotected upgrade
        env.deployer().update_current_contract_wasm(new_wasm);
    }
}
"#;

const SECURE_CONTRACT: &str = r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    pub fn deposit(env: Env, caller: Address, amount: i128) {
        caller.require_auth();
        env.storage().persistent().set(&caller, &amount);
    }
}
"#;

#[test]
fn test_auditor_detects_vulnerabilities() {
    let auditor = SorobanAuditor::new(AuditConfig::default());
    let report = auditor
        .audit_source("vulnerable.rs", VULNERABLE_CONTRACT)
        .expect("audit should succeed");

    assert!(!report.is_empty());

    // Should detect missing auth (SG-AUTH-001)
    let has_auth_finding = report.findings.iter().any(|f| f.rule_id == "SG-AUTH-001");
    assert!(has_auth_finding, "Missing auth finding expected");

    // Should detect temporary storage (SG-STOR-001)
    let has_storage_finding = report.findings.iter().any(|f| f.rule_id == "SG-STOR-001");
    assert!(has_storage_finding, "Temporary storage finding expected");

    // Should detect division precision (SG-ARITH-001)
    let has_arith_finding = report.findings.iter().any(|f| f.rule_id == "SG-ARITH-001");
    assert!(has_arith_finding, "Arithmetic finding expected");

    // Should detect unprotected upgrade (SG-UPG-001)
    let has_upgrade_finding = report.findings.iter().any(|f| f.rule_id == "SG-UPG-001");
    assert!(has_upgrade_finding, "Unprotected upgrade finding expected");

    // Verify markdown rendering
    let md = report.render_markdown();
    assert!(md.contains("Security Audit Report"));
    assert!(md.contains("SG-AUTH-001"));
}

#[test]
fn test_auditor_passes_clean_contract() {
    let auditor = SorobanAuditor::new(AuditConfig {
        min_level: FindingLevel::High,
        enabled_rules: vec!["SG-AUTH-001".into(), "SG-STOR-001".into()],
    });
    let report = auditor
        .audit_source("secure.rs", SECURE_CONTRACT)
        .expect("audit should succeed");

    assert!(report.is_empty(), "Secure contract should have 0 findings");
}
