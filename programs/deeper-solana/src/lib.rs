use anchor_lang::prelude::*;

// Replace with your program's actual ID after deployment
declare_id!("H1niZpkjAjop7hqR4jimhtmstiWTLZ9fnooR4vTWFbHs");

#[program]
pub mod deeper_solana {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, initial_admin: Pubkey) -> Result<()> {
        msg!("Initializing contract configuration...");

        // Access the configuration account being initialized
        let config_account = &mut ctx.accounts.dpr_config;

        // Set the admin field in the account's data
        config_account.admin = initial_admin;
        // You can also store the bump seed if needed for later PDA derivation validation
        config_account.bump = ctx.bumps.dpr_config;


        msg!("Admin set to: {}", config_account.admin);
        msg!("Configuration account initialized successfully!");
        Ok(())
    }

    // You might add other instructions here later, e.g., to change the admin
    pub fn update_admin(ctx: Context<UpdateAdmin>, new_admin: Pubkey) -> Result<()> { 
        msg!("Updating admin...");

        // Access the configuration account
        let config_account = &mut ctx.accounts.dpr_config;

        // Update the admin field
        config_account.admin = new_admin;

        msg!("Admin updated to: {}", config_account.admin);
        Ok(())
    }

    pub fn set_credit(ctx: Context<SetCredit>, new_number: u16) -> Result<()> {
        // Check if the signer is the admin
        let config = &ctx.accounts.dpr_config;
        if ctx.accounts.payer.key() != config.admin {
            return err!(ErrorCode::Unauthorized);
        }

        let credit = &mut ctx.accounts.credit_info;
        credit.user = ctx.accounts.user.key();
        credit.number = new_number;
        Ok(())
    }
}

/// Defines the structure of the configuration account.
#[account]
#[derive(Default)]
pub struct Config {
    /// The public key of the administrative user.
    pub admin: Pubkey,
    /// The bump seed for the PDA (optional but good practice to store).
    pub bump: u8,
    // You can add other configuration fields here later
    // pub some_other_data: u64,
}

/// Defines the structure of the user's credit account.
#[account]
pub struct CreditInfo {
    pub user: Pubkey,
    pub number: u16,
}

/// Defines the accounts required for the `initialize` instruction.
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The configuration account (PDA) to be created.
    /// `init` constraint: Creates the account.
    /// `payer = payer`: Specifies the account funding the creation.
    /// `space = 8 + 32 + 1`: Calculates required space:
    ///     - 8 bytes: Anchor account discriminator (standard).
    ///     - 32 bytes: Size of the `admin` Pubkey.
    ///     - 1 byte: Size of the `bump` u8.
    ///     (Adjust space if you add more fields to Config)
    /// `seeds = [b"config"]`: Seeds used to derive the PDA address. "config" is a common seed for singleton config accounts.
    /// `bump`: Anchor will find and provide the canonical bump seed.
    #[account(
        init,
        payer = payer,
        space = 8 + 32 + 1, // 8 discriminator + 32 Pubkey + 1 bump
        seeds = [b"config".as_ref()],
        bump
    )]
    pub dpr_config: Account<'info, Config>,

    /// The user account that pays for the account creation rent.
    /// `mut`: The payer's lamport balance will be modified (decreased).
    /// `Signer`: The payer must sign the transaction.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The Solana System Program, required by `init`.
    pub system_program: Program<'info, System>,
}


#[derive(Accounts)]
pub struct UpdateAdmin<'info> {
    #[account(
        mut,
        has_one = admin,
        seeds = [b"config".as_ref()], // Seeds to find the PDA
        bump = dpr_config.bump // Use the stored bump to verify/find the PDA
    )]
    pub dpr_config: Account<'info, Config>,

    /// The current admin authority signing the transaction.
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetCredit<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: User pubkey, used for PDA derivation and stored in credit
    pub user: AccountInfo<'info>, 

    #[account(
        seeds = [b"config".as_ref()], 
        bump = dpr_config.bump
    )]
    pub dpr_config: Account<'info, Config>,

    #[account(
        init_if_needed,
        space = 8 + 8 + 32, // 8 bytes for discriminator + 8 bytes for u64 + 32 bytes for Pubkey
        payer = payer,
        seeds = [b"credit".as_ref(), user.key().as_ref()], // Seeds to derive the PDA
        bump, // Use the stored bump to verify/find the PDA
    )]
    pub credit_info: Account<'info, CreditInfo>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Only the admin can perform this action")]
    Unauthorized,
}