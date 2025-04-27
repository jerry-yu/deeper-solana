use anchor_lang::prelude::*;
use solana_program::pubkey::Pubkey;

/// Defines the structure of the configuration account.
#[account]
#[derive(Default, InitSpace)]
pub struct Config {
    /// The public key of the administrative user.
    pub admin: Pubkey,
    /// The public key of the dev.
    pub dev_key: Pubkey,
    /// The bump seed for the PDA (optional but good practice to store).
    pub bump: u8,
    // You can add other configuration fields here later
    // pub some_other_data: u64,
}

/// Defines the structure of the user's credit account.
#[account]
#[derive(InitSpace)]
pub struct CreditInfo {
    pub user: Pubkey,
    pub number: u16,
    pub timestamp: i64,
}

#[account]
#[derive(InitSpace)]
pub struct CreditSetting {
    // the numerator of the millionth fraction
    pub apy: u32,
    pub balance: u64,
}
