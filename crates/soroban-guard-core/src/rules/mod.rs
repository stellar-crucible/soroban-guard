use crate::report::Finding;
use crate::visitor::ContractVisitor;
use std::fmt;

pub mod arithmetic;
pub mod auth;
pub mod auth_prop;
pub mod mint;
pub mod reentrancy;
pub mod storage;
pub mod ttl;
pub mod unbounded_data;
pub mod upgrade;

/// Unique identifier for an audit rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RuleId(pub String);

impl From<&str> for RuleId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Context passed to audit rules during an inspection pass.
pub struct RuleContext<'a> {
    pub visitor: &'a ContractVisitor,
    pub filename: &'a str,
}

/// Common trait implemented by all security linting rules.
pub trait AuditRule: Send + Sync {
    /// Identifier code (e.g. "SG-AUTH-001").
    fn id(&self) -> RuleId;
    /// Friendly human-readable rule name.
    fn name(&self) -> &str;
    /// Description of the security hazard detected by the rule.
    fn description(&self) -> &str;
    /// Execute the audit check across the parsed AST visitor.
    fn check(&self, visitor: &ContractVisitor) -> Vec<Finding>;
}

/// Registry storing all active audit rules.
pub struct RuleRegistry {
    rules: Vec<Box<dyn AuditRule>>,
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::default_rules()
    }
}

impl RuleRegistry {
    /// Initialize an empty rule registry.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Register a new audit rule.
    pub fn register<R: AuditRule + 'static>(&mut self, rule: R) {
        self.rules.push(Box::new(rule));
    }

    /// Return all registered rules.
    pub fn rules(&self) -> &[Box<dyn AuditRule>] {
        &self.rules
    }

    /// Standard suite of security rules for Soroban smart contracts.
    pub fn default_rules() -> Self {
        let mut registry = Self::new();
        registry.register(auth::MissingAuthRule);
        registry.register(storage::TemporaryStorageHazardRule);
        registry.register(reentrancy::StateMutationAfterCallRule);
        registry.register(arithmetic::DivisionPrecisionRule);
        registry.register(upgrade::UnprotectedUpgradeRule);
        registry.register(ttl::MissingTtlExtensionRule);
        registry.register(mint::UnboundedMintRule);
        registry.register(auth_prop::AuthPropagationRule);
        registry.register(unbounded_data::UnboundedDataGrowthRule);
        registry
    }
}
