use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use soroban_guard_core::{AuditConfig, FindingLevel, RuleRegistry, SorobanAuditor};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "soroban-guard",
    about = "Security static analyzer and invariant synthesizer for Soroban smart contracts",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan smart contract source files for security vulnerabilities
    Check {
        /// Target path (file or directory) to audit
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,

        /// Minimum finding severity to report
        #[arg(long, value_enum, default_value_t = SeverityArg::Info)]
        min_level: SeverityArg,

        /// Exit with non-zero code if findings are present
        #[arg(long, default_value_t = true)]
        deny_warnings: bool,

        /// Baseline path to diff against (only newly introduced findings will trigger failures)
        #[arg(long)]
        diff: Option<PathBuf>,
    },

    /// List all registered security rules
    Rules,

    /// Synthesize soroban-testkit invariant tests for detected security issues
    SynthTestkit {
        /// Target path to scan and generate test scaffolding for
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output test file destination
        #[arg(short, long, default_value = "tests/generated_invariants.rs")]
        output: PathBuf,

        /// Generate proptest fuzzing blocks with soroban-testkit-generators
        #[arg(long)]
        proptest: bool,

        /// Number of generative proptest cases
        #[arg(long, default_value_t = 500)]
        cases: u32,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputFormat {
    Text,
    Markdown,
    Sarif,
    Html,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum SeverityArg {
    Info,
    Warn,
    High,
    Crit,
}

impl From<SeverityArg> for FindingLevel {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Info => FindingLevel::Info,
            SeverityArg::Warn => FindingLevel::Warning,
            SeverityArg::High => FindingLevel::High,
            SeverityArg::Crit => FindingLevel::Critical,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Rules => {
            println!("{}", "Registered Soroban-Guard Rules:".bold().green());
            println!();
            let registry = RuleRegistry::default_rules();
            for rule in registry.rules() {
                println!(
                    "{} [{}] {}",
                    "•".cyan(),
                    rule.id().to_string().yellow().bold(),
                    rule.name().bold()
                );
                println!("  {}\n", rule.description());
            }
        }
        Commands::Check {
            path,
            format,
            min_level,
            deny_warnings,
            diff,
        } => {
            let config = AuditConfig {
                min_level: min_level.into(),
                enabled_rules: Vec::new(),
            };
            let auditor = SorobanAuditor::new(config);
            let reports = auditor.audit_path(&path)?;

            let baseline_findings: Vec<soroban_guard_core::Finding> = if let Some(base_path) = diff
            {
                let base_reports = auditor.audit_path(&base_path)?;
                base_reports.into_iter().flat_map(|r| r.findings).collect()
            } else {
                Vec::new()
            };

            let is_diff_mode = !baseline_findings.is_empty();
            let mut new_findings_count = 0;
            let total_findings: usize = reports.iter().map(|r| r.len()).sum();

            match format {
                OutputFormat::Markdown => {
                    for report in &reports {
                        if !report.is_empty() {
                            println!("{}", report.render_markdown());
                        }
                    }
                }
                OutputFormat::Sarif => {
                    println!("{}", serde_json::to_string_pretty(&reports)?);
                }
                OutputFormat::Html => {
                    for report in &reports {
                        println!("{}", report.render_html());
                    }
                }
                OutputFormat::Text => {
                    println!("{}", format!("Audited {} file(s)...", reports.len()).bold());
                    if is_diff_mode {
                        println!(
                            "{}",
                            format!("Running in Diff-Audit Mode against baseline: {} findings found in base.", baseline_findings.len()).cyan().bold()
                        );
                    }
                    println!();

                    for report in &reports {
                        if report.is_empty() {
                            continue;
                        }
                        println!("File: {}", report.file.bold().underline());
                        for f in &report.findings {
                            let is_pre_existing = baseline_findings
                                .iter()
                                .any(|bf| bf.rule_id == f.rule_id && bf.target == f.target);
                            if !is_pre_existing {
                                new_findings_count += 1;
                            }

                            let diff_tag = if is_diff_mode {
                                if is_pre_existing {
                                    "[BASELINE] ".dimmed()
                                } else {
                                    "[NEW] ".red().bold()
                                }
                            } else {
                                "".normal()
                            };

                            let badge = match f.level {
                                FindingLevel::Critical => "CRITICAL".red().bold(),
                                FindingLevel::High => "HIGH".red(),
                                FindingLevel::Warning => "WARN".yellow(),
                                FindingLevel::Info => "INFO".blue(),
                            };
                            println!(
                                "  {}{}[{}] {} (line {} in `{}`)",
                                diff_tag,
                                if is_pre_existing {
                                    "".dimmed()
                                } else {
                                    "".normal()
                                },
                                badge,
                                f.title.bold(),
                                f.line,
                                f.target
                            );
                            println!("     Rule: {}", f.rule_id.cyan());
                            println!("     Fix:  {}", f.remediation.advice);
                        }
                        println!();
                    }

                    if is_diff_mode {
                        println!(
                            "{}",
                            format!(
                                "Diff Summary: {} total findings ({} new, {} pre-existing)",
                                total_findings,
                                new_findings_count,
                                total_findings.saturating_sub(new_findings_count)
                            )
                            .bold()
                        );
                        if new_findings_count > 0 && deny_warnings {
                            anyhow::bail!(
                                "Diff audit failed: {} newly introduced security finding(s) detected.",
                                new_findings_count
                            );
                        } else {
                            println!("{}", "✔ No new security vulnerabilities introduced relative to baseline.".green().bold());
                        }
                    } else if total_findings == 0 {
                        println!(
                            "{}",
                            "✔ All audited contracts passed security checks without findings!"
                                .green()
                                .bold()
                        );
                    } else {
                        println!(
                            "{}",
                            format!("⚠ Total security findings: {}", total_findings)
                                .red()
                                .bold()
                        );
                        if deny_warnings {
                            anyhow::bail!(
                                "Security audit failed: {} findings discovered.",
                                total_findings
                            );
                        }
                    }
                }
            }
        }
        Commands::SynthTestkit {
            path,
            output,
            proptest,
            cases,
        } => {
            let auditor = SorobanAuditor::default();
            let reports = auditor.audit_path(&path)?;

            let mut tests = String::new();
            tests.push_str("//! Auto-generated by `soroban-guard synth-testkit`\n");
            tests.push_str("//! Regression testkit invariant harness.\n\n");
            tests.push_str("#![cfg(test)]\n\n");

            if proptest {
                tests.push_str("use proptest::prelude::*;\n");
                tests.push_str("use soroban_sdk::{Address, Env};\n");
                tests.push_str(
                    "use soroban_testkit_generators::{arb_address, arb_i128, arb_symbol};\n\n",
                );
                tests.push_str(&format!(
                    "proptest! {{\n    #![proptest_config(ProptestConfig::with_cases({}))]\n\n",
                    cases
                ));
            }

            let mut count = 0;
            for report in &reports {
                for finding in &report.findings {
                    if let Some(invariant) = &finding.remediation.testkit_invariant {
                        count += 1;
                        if proptest {
                            let sanitized_target = finding.target.replace("::", "_");
                            let sanitized_rule = finding.rule_id.replace('-', "_").to_lowercase();
                            tests.push_str(&format!(
                                "    #[test]\n    fn prop_invariant_{}_{}(\n        attacker in arb_address(),\n        amount in arb_i128(1..=1_000_000),\n    ) {{\n        let env = Env::default();\n        // Invariant for [{}]: {}\n        // {}\n    }}\n\n",
                                sanitized_rule, sanitized_target, finding.rule_id, finding.title, invariant
                            ));
                        } else {
                            tests.push_str(&format!(
                                "// [{}] Target: {}\n",
                                finding.rule_id, finding.target
                            ));
                            tests.push_str(invariant);
                            tests.push_str("\n\n");
                        }
                    }
                }
            }

            if proptest {
                tests.push_str("}\n");
            }

            if count == 0 {
                println!(
                    "{}",
                    "No synthesizable invariants found for this path.".yellow()
                );
            } else {
                if let Some(parent) = output.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&output, &tests)?;
                println!(
                    "{}",
                    format!(
                        "✔ Successfully synthesized {} soroban-testkit invariant(s) to `{}`",
                        count,
                        output.display()
                    )
                    .green()
                    .bold()
                );
            }
        }
    }

    Ok(())
}
