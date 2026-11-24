use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// Secure deposit: enforces authentication and persistent storage with TTL extension
    pub fn deposit(env: Env, caller: Address, amount: i128) {
        caller.require_auth();
        env.storage().persistent().set(&caller, &amount);
        env.storage().persistent().extend_ttl(&caller, 10_000, 50_000);
    }

    /// Safe fee calculation: checks multiplication before division
    pub fn calculate_fee(amount: i128, fee_bps: i128) -> i128 {
        (amount * fee_bps) / 10_000
    }
}
