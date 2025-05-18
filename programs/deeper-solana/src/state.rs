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
    pub bump: u8,
    /// The public key of the user.
    pub user: Pubkey,
    pub campaign : u16,
    pub credit: u32,
    pub day: u32,
}
/// Defines the structure of the credit settings.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, InitSpace, Debug)]
pub struct CreditSetting {
    pub daily_reward: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct DayCredit {
    pub day: u32,
    pub credit: u32,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct DayCreditHistory {
    pub history : Vec<DayCredit>,
}