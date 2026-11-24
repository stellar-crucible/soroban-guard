use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity classification for a security audit finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingLevel {
    Info = 0,
    Warning = 1,
    High = 2,
    Critical = 3,
}

impl fmt::Display for FindingLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRIT"),
        }
    }
}

/// Suggested fix or verification strategy for a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    /// Human-readable explanation of how to fix the issue.
    pub advice: String,
    /// Optional Rust code example demonstrating the patch.
    pub code_patch: Option<String>,
    /// Optional testkit invariant property test snippet.
    pub testkit_invariant: Option<String>,
}

/// An individual security issue discovered by an audit rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Rule identifier (e.g., "SG-AUTH-001").
    pub rule_id: String,
    /// Short summary of the issue.
    pub title: String,
    /// Severity level.
    pub level: FindingLevel,
    /// Detailed description of the vulnerability.
    pub description: String,
    /// File path where the finding occurred.
    pub file: String,
    /// Line number in the source file.
    pub line: usize,
    /// Name of the affected function or struct.
    pub target: String,
    /// Recommended remediation.
    pub remediation: Remediation,
}

/// Complete collection of findings for a given file or module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// File or target audited.
    pub file: String,
    /// Discovered findings.
    pub findings: Vec<Finding>,
}

impl AuditReport {
    /// Create a new empty report.
    pub fn new(file: &str) -> Self {
        Self {
            file: file.to_string(),
            findings: Vec::new(),
        }
    }

    /// Add a finding to the report.
    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Check if the report has any findings.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Number of findings.
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Render report as GitHub-flavored Markdown.
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("## Security Audit Report: `{}`\n\n", self.file));

        if self.findings.is_empty() {
            out.push_str("No security issues detected.\n");
            return out;
        }

        out.push_str("| Rule ID | Level | Target | Line | Issue |\n");
        out.push_str("|---|---|---|---|---|\n");
        for f in &self.findings {
            out.push_str(&format!(
                "| `{}` | **{}** | `{}` | {} | {} |\n",
                f.rule_id, f.level, f.target, f.line, f.title
            ));
        }
        out.push('\n');

        for f in &self.findings {
            out.push_str(&format!("### [{}] {}\n\n", f.rule_id, f.title));
            out.push_str(&format!(
                "- **Severity:** {}\n- **Target:** `{}` (line {})\n\n",
                f.level, f.target, f.line
            ));
            out.push_str(&format!("{}\n\n", f.description));
            out.push_str(&format!("**Remediation:**\n{}\n\n", f.remediation.advice));

            if let Some(patch) = &f.remediation.code_patch {
                out.push_str(&format!("```rust\n{}\n```\n\n", patch));
            }

            if let Some(invariant) = &f.remediation.testkit_invariant {
                out.push_str(&format!(
                    "**Recommended soroban-testkit property test:**\n```rust\n{}\n```\n\n",
                    invariant
                ));
            }
        }

        out
    }

    /// Render SARIF JSON compatible with GitHub Code Scanning.
    pub fn render_sarif(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}
