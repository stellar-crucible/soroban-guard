//! Secure Vault Contract Example
//! Hardened contract adhering to all Soroban Guard security standards (0 findings).

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

const BALANCE_KEY: Symbol = symbol_short!("BAL");
const ADMIN_KEY: Symbol = symbol_short!("ADMIN");
const DAY_IN_LEDGERS: u32 = 17_280; // ~5 seconds per ledger

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// Deposit funds into persistent storage with proper auth and active TTL extension
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");

        let key = (&user, BALANCE_KEY);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = current.checked_add(amount).expect("overflow");

        env.storage().persistent().set(&key, &updated);
        // Complies with SG-TTL-001
        env.storage()
            .persistent()
            .extend_ttl(&key, DAY_IN_LEDGERS * 30, DAY_IN_LEDGERS * 60);
    }

    /// Secure withdrawal requiring caller authorization
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth(); // Complies with SG-AUTH-001
        assert!(amount > 0, "amount must be positive");

        let key = (&user, BALANCE_KEY);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        assert!(current >= amount, "insufficient balance");

        let remaining = current.checked_sub(amount).expect("underflow");
        env.storage().persistent().set(&key, &remaining);
        env.storage()
            .persistent()
            .extend_ttl(&key, DAY_IN_LEDGERS * 30, DAY_IN_LEDGERS * 60);
    }

    /// Protected admin rotation verifying both current and new admin auth
    pub fn set_admin(env: Env, new_admin: Address) {
        let current_admin: Address = env
            .storage()
            .instance()
            .get(&ADMIN_KEY)
            .expect("admin not configured");
        current_admin.require_auth();
        new_admin.require_auth();

        env.storage().instance().set(&ADMIN_KEY, &new_admin);
        env.storage()
            .instance()
            .extend_ttl(DAY_IN_LEDGERS * 30, DAY_IN_LEDGERS * 60);
    }

    /// Protected fee calculation with safe checked multiplication
    pub fn calculate_fee(_env: Env, amount: i128, rate: i128) -> i128 {
        amount.checked_mul(rate).expect("overflow")
    }
}
