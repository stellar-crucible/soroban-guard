use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprForLoop, ExprLoop, ExprMethodCall, ExprWhile, ItemImpl, ItemStruct};

/// A function defined within a Soroban contract implementation.
#[derive(Debug, Clone)]
pub struct ContractFunction {
    pub name: String,
    pub line: usize,
    pub has_contractimpl: bool,
    pub storage_writes: Vec<StorageAccess>,
    pub storage_reads: Vec<StorageAccess>,
    pub auth_checks: Vec<AuthCheck>,
    pub external_calls: Vec<ExternalCall>,
    pub division_calls: Vec<ArithmeticOp>,
    pub ttl_extensions: Vec<TtlExtension>,
    pub writes_in_loop: Vec<StorageAccess>,
    pub has_auth_propagation: bool,
    pub has_upgrade_call: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageTier {
    Instance,
    Persistent,
    Temporary,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct StorageAccess {
    pub tier: StorageTier,
    pub method: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct AuthCheck {
    pub target_ident: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct ExternalCall {
    pub callee: String,
    pub method: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct ArithmeticOp {
    pub op: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct TtlExtension {
    pub line: usize,
}

/// Visitor that analyzes the contract syntax tree.
#[derive(Default)]
pub struct ContractVisitor {
    pub functions: Vec<ContractFunction>,
    pub contract_structs: Vec<String>,
}

impl ContractVisitor {
    pub fn analyze(file: &syn::File) -> Self {
        let mut visitor = Self::default();
        visitor.visit_file(file);
        visitor
    }
}

impl<'ast> Visit<'ast> for ContractVisitor {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        let has_contract_attr = node.attrs.iter().any(|a| a.path().is_ident("contract"));
        if has_contract_attr {
            self.contract_structs.push(node.ident.to_string());
        }
        visit::visit_item_struct(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let has_contractimpl = node.attrs.iter().any(|a| a.path().is_ident("contractimpl"));

        for item in &node.items {
            if let syn::ImplItem::Fn(method) = item {
                let mut fn_analyzer = FunctionAnalyzer {
                    name: method.sig.ident.to_string(),
                    line: method.sig.ident.span().start().line,
                    has_contractimpl,
                    storage_writes: Vec::new(),
                    storage_reads: Vec::new(),
                    auth_checks: Vec::new(),
                    external_calls: Vec::new(),
                    division_calls: Vec::new(),
                    ttl_extensions: Vec::new(),
                    writes_in_loop: Vec::new(),
                    in_loop_depth: 0,
                    has_auth_propagation: false,
                    has_upgrade_call: false,
                };
                fn_analyzer.visit_impl_item_fn(method);

                self.functions.push(ContractFunction {
                    name: fn_analyzer.name,
                    line: fn_analyzer.line,
                    has_contractimpl: fn_analyzer.has_contractimpl,
                    storage_writes: fn_analyzer.storage_writes,
                    storage_reads: fn_analyzer.storage_reads,
                    auth_checks: fn_analyzer.auth_checks,
                    external_calls: fn_analyzer.external_calls,
                    division_calls: fn_analyzer.division_calls,
                    ttl_extensions: fn_analyzer.ttl_extensions,
                    writes_in_loop: fn_analyzer.writes_in_loop,
                    has_auth_propagation: fn_analyzer.has_auth_propagation,
                    has_upgrade_call: fn_analyzer.has_upgrade_call,
                });
            }
        }

        visit::visit_item_impl(self, node);
    }
}

struct FunctionAnalyzer {
    name: String,
    line: usize,
    has_contractimpl: bool,
    storage_writes: Vec<StorageAccess>,
    storage_reads: Vec<StorageAccess>,
    auth_checks: Vec<AuthCheck>,
    external_calls: Vec<ExternalCall>,
    division_calls: Vec<ArithmeticOp>,
    ttl_extensions: Vec<TtlExtension>,
    writes_in_loop: Vec<StorageAccess>,
    in_loop_depth: usize,
    has_auth_propagation: bool,
    has_upgrade_call: bool,
}

impl<'ast> Visit<'ast> for FunctionAnalyzer {
    fn visit_expr_for_loop(&mut self, node: &'ast ExprForLoop) {
        self.in_loop_depth += 1;
        visit::visit_expr_for_loop(self, node);
        self.in_loop_depth -= 1;
    }

    fn visit_expr_while(&mut self, node: &'ast ExprWhile) {
        self.in_loop_depth += 1;
        visit::visit_expr_while(self, node);
        self.in_loop_depth -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast ExprLoop) {
        self.in_loop_depth += 1;
        visit::visit_expr_loop(self, node);
        self.in_loop_depth -= 1;
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();
        let line = node.method.span().start().line;

        // Check auth checks
        if method_name == "require_auth" || method_name == "require_auth_for_args" {
            let target_ident = quote::quote!(#node).to_string();
            self.auth_checks.push(AuthCheck { target_ident, line });
        }

        // Check auth propagation
        if method_name == "authorize_as_current_contract" {
            self.has_auth_propagation = true;
        }

        // Check TTL extension
        if method_name == "extend_ttl" || method_name == "extend_ttl_for_code" {
            self.ttl_extensions.push(TtlExtension { line });
        }

        // Check cross-contract client invocations
        let receiver_str = quote::quote!(#node.receiver).to_string();
        if receiver_str.contains("client") || receiver_str.contains("Client") {
            self.external_calls.push(ExternalCall {
                callee: receiver_str,
                method: method_name.clone(),
                line,
            });
        }

        // Check storage operations
        if method_name == "set" || method_name == "remove" {
            let expr_str = quote::quote!(#node).to_string();
            let tier = if expr_str.contains("temporary") {
                StorageTier::Temporary
            } else if expr_str.contains("persistent") {
                StorageTier::Persistent
            } else if expr_str.contains("instance") {
                StorageTier::Instance
            } else {
                StorageTier::Unknown
            };

            let access = StorageAccess {
                tier,
                method: method_name.clone(),
                line,
            };

            self.storage_writes.push(access.clone());

            if self.in_loop_depth > 0 {
                self.writes_in_loop.push(access);
            }
        } else if method_name == "get" || method_name == "has" {
            let expr_str = quote::quote!(#node).to_string();
            let tier = if expr_str.contains("temporary") {
                StorageTier::Temporary
            } else if expr_str.contains("persistent") {
                StorageTier::Persistent
            } else if expr_str.contains("instance") {
                StorageTier::Instance
            } else {
                StorageTier::Unknown
            };
            self.storage_reads.push(StorageAccess {
                tier,
                method: method_name.clone(),
                line,
            });
        }

        // Check contract upgrade
        if method_name == "update_current_contract_wasm" {
            self.has_upgrade_call = true;
        }

        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        let line = node.span().start().line;
        if let syn::BinOp::Div(_) = node.op {
            self.division_calls.push(ArithmeticOp {
                op: "/".to_string(),
                line,
            });
        }
        visit::visit_expr_binary(self, node);
    }
}
