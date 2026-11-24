use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    /// Insecure deposit: writes to temporary storage without requiring authorization
    pub fn deposit(env: Env, caller: Address, amount: i128) {
        // Missing caller.require_auth()
        // Temporary storage used for user balances (risk of ledger eviction)
        env.storage().temporary().set(&caller, &amount);
    }

    /// Insecure fee calculation: performs integer division before multiplication
    pub fn calculate_fee(amount: i128, bps: i128) -> i128 {
        amount / bps
    }

    /// Insecure upgrade: upgrades contract WASM without admin authorization
    pub fn upgrade_contract(env: Env, new_wasm: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm);
    }
}
