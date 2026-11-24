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

    pub fn mint_tokens(env: Env, to: Address, amount: i128) {
        // Unrestricted minting without caller auth or supply cap
        // Also missing extend_ttl
        env.storage().persistent().set(&to, &amount);
    }

    pub fn batch_insert(env: Env, count: u32) {
        // Iterative storage writes inside loop (SG-DATA-001)
        for i in 0..count {
            env.storage().persistent().set(&i, &i);
        }
    }

    pub fn forward_transfer(env: Env, client: TokenClient, to: Address, amount: i128) {
        // Missing sub-invocation auth propagation (SG-AUTH-002)
        client.transfer(&to, &amount);
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
        env.storage().persistent().extend_ttl(&caller, 10_000, 50_000);
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

    // Should detect missing TTL extension (SG-TTL-001)
    let has_ttl_finding = report.findings.iter().any(|f| f.rule_id == "SG-TTL-001");
    assert!(has_ttl_finding, "Missing TTL finding expected");

    // Should detect unbounded mint (SG-MINT-001)
    let has_mint_finding = report.findings.iter().any(|f| f.rule_id == "SG-MINT-001");
    assert!(has_mint_finding, "Unbounded mint finding expected");

    // Should detect unbounded collection growth in loop (SG-DATA-001)
    let has_data_finding = report.findings.iter().any(|f| f.rule_id == "SG-DATA-001");
    assert!(has_data_finding, "Unbounded data finding expected");

    // Should detect missing cross-contract auth propagation (SG-AUTH-002)
    let has_auth_prop = report.findings.iter().any(|f| f.rule_id == "SG-AUTH-002");
    assert!(has_auth_prop, "Auth propagation finding expected");

    // Verify markdown rendering
    let md = report.render_markdown();
    assert!(md.contains("Security Audit Report"));
    assert!(md.contains("SG-AUTH-001"));

    // Verify SARIF v2.1.0 rendering
    let sarif = report.render_sarif();
    assert!(sarif.contains("\"version\": \"2.1.0\""));
    assert!(sarif.contains("\"ruleId\": \"SG-AUTH-001\""));

    // Verify HTML rendering
    let html = report.render_html();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("Soroban Guard Security Report"));
    assert!(html.contains("SG-DATA-001"));
}

#[test]
fn test_auditor_passes_clean_contract() {
    let auditor = SorobanAuditor::new(AuditConfig {
        min_level: FindingLevel::High,
        enabled_rules: vec![
            "SG-AUTH-001".into(),
            "SG-STOR-001".into(),
            "SG-TTL-001".into(),
            "SG-MINT-001".into(),
            "SG-AUTH-002".into(),
            "SG-DATA-001".into(),
        ],
    });
    let report = auditor
        .audit_source("secure.rs", SECURE_CONTRACT)
        .expect("audit should succeed");

    assert!(report.is_empty(), "Secure contract should have 0 findings");
}
