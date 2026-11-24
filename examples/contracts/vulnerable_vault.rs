//! Vulnerable Vault Contract Example
//! Demonstrates common Soroban security hazards detected by `soroban-guard`.

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

const BALANCE_KEY: Symbol = symbol_short!("BAL");

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    /// Hazard: SG-STOR-001 (Temporary storage used for critical balance ledger state)
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // Writing user balances to temporary storage means balances can silently expire without archival recovery
        env.storage().temporary().set(&(&user, BALANCE_KEY), &amount);
    }

    /// Hazard: SG-AUTH-001 (Missing user.require_auth check on state-mutating withdrawal)
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        // Missing user.require_auth() here allows an attacker to drain user funds!
        let current_bal: i128 = env
            .storage()
            .temporary()
            .get(&(&user, BALANCE_KEY))
            .unwrap_or(0);
        assert!(current_bal >= amount, "insufficient balance");
        env.storage()
            .temporary()
            .set(&(&user, BALANCE_KEY), &(current_bal - amount));
    }

    /// Hazard: SG-TTL-001 (Persistent storage write lacking extend_ttl renewal)
    pub fn set_admin(env: Env, new_admin: Address) {
        new_admin.require_auth();
        // Writes to persistent storage without extending TTL, leading to potential archival lockup
        env.storage().persistent().set(&symbol_short!("ADMIN"), &new_admin);
    }

    /// Hazard: SG-ARITH-001 (Division before multiplication precision dust loss)
    pub fn calculate_fee(_env: Env, amount: i128, rate: i128, divisor: i128) -> i128 {
        // Truncates integer precision before multiplying
        (amount / divisor) * rate
    }
}
