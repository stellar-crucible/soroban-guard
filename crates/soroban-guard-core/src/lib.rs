//! Static analysis and security rule verification engine for Soroban smart contracts.

pub mod report;
pub mod rules;
pub mod visitor;

pub use report::{AuditReport, Finding, FindingLevel, Remediation};
pub use rules::{AuditRule, RuleContext, RuleId, RuleRegistry};
pub use visitor::ContractVisitor;

use std::path::Path;
use thiserror::Error;

/// Error encountered during an audit pass.
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Failed to read file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse Rust syntax in {0}: {1}")]
    Syntax(String, syn::Error),
}

/// Configuration options for the audit engine.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Minimum finding severity to report.
    pub min_level: FindingLevel,
    /// List of rule IDs to run (empty means all registered rules).
    pub enabled_rules: Vec<RuleId>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            min_level: FindingLevel::Info,
            enabled_rules: Vec::new(),
        }
    }
}

/// Security auditor for Soroban contract codebases.
pub struct SorobanAuditor {
    registry: RuleRegistry,
    config: AuditConfig,
}

impl Default for SorobanAuditor {
    fn default() -> Self {
        Self::new(AuditConfig::default())
    }
}

impl SorobanAuditor {
    /// Create a new auditor with the specified configuration.
    pub fn new(config: AuditConfig) -> Self {
        Self {
            registry: RuleRegistry::default_rules(),
            config,
        }
    }

    /// Audit a single Rust source string representing contract code.
    pub fn audit_source(&self, filename: &str, content: &str) -> Result<AuditReport, AuditError> {
        let file = syn::parse_file(content)
            .map_err(|err| AuditError::Syntax(filename.to_string(), err))?;

        let visitor = ContractVisitor::analyze(&file);
        let mut report = AuditReport::new(filename);

        for rule in self.registry.rules() {
            if !self.config.enabled_rules.is_empty()
                && !self.config.enabled_rules.contains(&rule.id())
            {
                continue;
            }

            let findings = rule.check(&visitor);
            for finding in findings {
                if finding.level >= self.config.min_level {
                    report.add(finding);
                }
            }
        }

        Ok(report)
    }

    /// Recursively audit all Rust source files in a directory.
    pub fn audit_path<P: AsRef<Path>>(&self, path: P) -> Result<Vec<AuditReport>, AuditError> {
        let mut reports = Vec::new();
        let path = path.as_ref();

        if path.is_file() {
            let content = std::fs::read_to_string(path)?;
            let filename = path.to_string_lossy().to_string();
            reports.push(self.audit_source(&filename, &content)?);
            return Ok(reports);
        }

        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| {
                e.path().extension().is_some_and(|ext| ext == "rs")
                    && !e.path().to_string_lossy().contains("target")
            })
        {
            let file_path = entry.path();
            let content = std::fs::read_to_string(file_path)?;
            let filename = file_path.to_string_lossy().to_string();
            let report = self.audit_source(&filename, &content)?;
            if !report.is_empty() {
                reports.push(report);
            }
        }

        Ok(reports)
    }
}
