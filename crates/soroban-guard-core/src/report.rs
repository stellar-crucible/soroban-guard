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

    /// Render SARIF v2.1.0 JSON compatible with GitHub Code Scanning.
    pub fn render_sarif(&self) -> String {
        let results: Vec<serde_json::Value> = self
            .findings
            .iter()
            .map(|f| {
                let level = match f.level {
                    FindingLevel::Critical | FindingLevel::High => "error",
                    FindingLevel::Warning => "warning",
                    FindingLevel::Info => "note",
                };
                serde_json::json!({
                    "ruleId": f.rule_id,
                    "level": level,
                    "message": {
                        "text": f.description
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": self.file
                                },
                                "region": {
                                    "startLine": f.line,
                                    "startColumn": 1
                                }
                            }
                        }
                    ]
                })
            })
            .collect();

        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "soroban-guard",
                            "informationUri": "https://github.com/stellar-crucible/soroban-guard",
                            "semanticVersion": "0.1.0"
                        }
                    },
                    "results": results
                }
            ]
        });

        serde_json::to_string_pretty(&sarif).unwrap_or_default()
    }

    /// Render standalone interactive HTML report.
    pub fn render_html(&self) -> String {
        let crit_count = self
            .findings
            .iter()
            .filter(|f| f.level == FindingLevel::Critical)
            .count();
        let high_count = self
            .findings
            .iter()
            .filter(|f| f.level == FindingLevel::High)
            .count();
        let warn_count = self
            .findings
            .iter()
            .filter(|f| f.level == FindingLevel::Warning)
            .count();

        let mut cards = String::new();
        for f in &self.findings {
            let color = match f.level {
                FindingLevel::Critical => "#e53e3e",
                FindingLevel::High => "#dd6b20",
                FindingLevel::Warning => "#d69e2e",
                FindingLevel::Info => "#3182ce",
            };
            let patch_html = f.remediation.code_patch.as_deref().map(|p| {
                format!("<div class=\"code-block\"><div class=\"code-title\">Suggested Remediation</div><pre><code>{}</code></pre></div>", p)
            }).unwrap_or_default();

            cards.push_str(&format!(
                "<div class=\"finding-card\">\n\
                    <div class=\"finding-header\">\n\
                        <span class=\"badge\" style=\"background:{};\">{}</span>\n\
                        <span class=\"rule-id\">{}</span>\n\
                        <span class=\"target-fn\">Function: <code>{}</code> (line {})</span>\n\
                    </div>\n\
                    <h3>{}</h3>\n\
                    <p>{}</p>\n\
                    <div class=\"advice\"><strong>Advice:</strong> {}</div>\n\
                    {}\n\
                </div>\n",
                color,
                f.level,
                f.rule_id,
                f.target,
                f.line,
                f.title,
                f.description,
                f.remediation.advice,
                patch_html
            ));
        }

        format!(
            "<!DOCTYPE html>\n\
            <html lang=\"en\">\n\
            <head>\n\
            <meta charset=\"UTF-8\">\n\
            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n\
            <title>Soroban Guard Security Report - {file}</title>\n\
            <style>\n\
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 2rem; background: #0f172a; color: #e2e8f0; }}\n\
            .container {{ max-width: 1000px; margin: 0 auto; }}\n\
            header {{ border-bottom: 1px solid #334155; padding-bottom: 1.5rem; margin-bottom: 2rem; }}\n\
            h1 {{ margin: 0 0 0.5rem 0; color: #38bdf8; }}\n\
            .summary-bar {{ display: flex; gap: 1rem; margin-bottom: 2rem; }}\n\
            .stat-box {{ flex: 1; padding: 1rem; border-radius: 8px; background: #1e293b; border: 1px solid #334155; text-align: center; }}\n\
            .stat-number {{ font-size: 2rem; font-weight: bold; margin-bottom: 0.25rem; }}\n\
            .stat-label {{ font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; }}\n\
            .finding-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}\n\
            .finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; }}\n\
            .badge {{ color: white; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}\n\
            .rule-id {{ color: #94a3b8; font-family: monospace; font-size: 0.9rem; }}\n\
            .target-fn {{ margin-left: auto; font-size: 0.85rem; color: #cbd5e1; }}\n\
            .advice {{ background: #0f172a; padding: 0.75rem 1rem; border-left: 3px solid #38bdf8; margin: 1rem 0; border-radius: 0 4px 4px 0; }}\n\
            .code-block {{ background: #020617; border-radius: 6px; overflow: hidden; border: 1px solid #1e293b; margin-top: 1rem; }}\n\
            .code-title {{ background: #1e293b; padding: 0.4rem 0.8rem; font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; }}\n\
            pre {{ margin: 0; padding: 1rem; overflow-x: auto; }}\n\
            code {{ font-family: 'Fira Code', monospace; font-size: 0.9rem; color: #a5f3fc; }}\n\
            </style>\n\
            </head>\n\
            <body>\n\
            <div class=\"container\">\n\
            <header>\n\
                <h1>Soroban Guard Security Report</h1>\n\
                <p>Audited Source: <code>{file}</code></p>\n\
            </header>\n\
            <div class=\"summary-bar\">\n\
                <div class=\"stat-box\"><div class=\"stat-number\" style=\"color:#e53e3e;\">{crit}</div><div class=\"stat-label\">Critical</div></div>\n\
                <div class=\"stat-box\"><div class=\"stat-number\" style=\"color:#dd6b20;\">{high}</div><div class=\"stat-label\">High</div></div>\n\
                <div class=\"stat-box\"><div class=\"stat-number\" style=\"color:#d69e2e;\">{warn}</div><div class=\"stat-label\">Warning</div></div>\n\
                <div class=\"stat-box\"><div class=\"stat-number\" style=\"color:#38bdf8;\">{total}</div><div class=\"stat-label\">Total Findings</div></div>\n\
            </div>\n\
            {cards}\n\
            </div>\n\
            </body>\n\
            </html>",
            file = self.file,
            crit = crit_count,
            high = high_count,
            warn = warn_count,
            total = self.findings.len(),
            cards = cards
        )
    }
}
