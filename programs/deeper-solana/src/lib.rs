pub mod state;
// pub mod instructions;
pub mod error;

use state::{Config, CreditInfo};

use anchor_lang::prelude::*;
use error::DeeperErrorCode;
use solana_program::{
    ed25519_program, instruction::Instruction, program::invoke, pubkey::Pubkey,
    sysvar::instructions as tx_instructions, sysvar::instructions::load_instruction_at_checked,
};
pub const CREDIT_SIZE: usize = 10;
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
            return err!(DeeperErrorCode::Unauthorized);
        }

        let credit = &mut ctx.accounts.credit_info;
        credit.user = ctx.accounts.user.key();
        credit.number = new_number;
        Ok(())
    }

    pub fn verify_ed25519_via_sysvar(
        // Renamed function for clarity
        ctx: Context<VerifyEd25519Sysvar>, // Renamed context struct
        public_key: [u8; 32],
        message: Vec<u8>,
        signature: [u8; 64],
    ) -> Result<()> {
        msg!("Verifying Ed25519 signature via Instructions Sysvar...");
        msg!("Expected Public Key: {:?}", public_key);
        // msg!("Expected Message: {:?}", message); // Can be long
        msg!("Expected Signature: {:?}", signature);

        // 1. Get the Instructions sysvar account
        let ix_sysvar = &ctx.accounts.instruction_sysvar;
        //let ix_sysvar_data = ix_sysvar.try_borrow_data()?;

        // 2. Load the current instruction index
        let current_ix_index = tx_instructions::load_current_index_checked(ix_sysvar)
            .map_err(|_| error!(DeeperErrorCode::InstructionLoadFailed))?;
        msg!("Current instruction index: {}", current_ix_index);

        // 3. Ensure there *is* a preceding instruction
        if current_ix_index == 0 {
            msg!("Error: No preceding instruction found.");
            return Err(error!(DeeperErrorCode::NoPrecedingInstruction));
        }
        let preceding_ix_index = current_ix_index - 1;
        msg!("Preceding instruction index: {}", preceding_ix_index);

        // 4. Load the preceding instruction
        let preceding_ix = load_instruction_at_checked(preceding_ix_index as usize, &ix_sysvar)
            .map_err(|_| {
                msg!(
                    "Error: Failed to load preceding instruction at index {}.",
                    preceding_ix_index
                );
                error!(DeeperErrorCode::InstructionLoadFailed)
            })?;
        msg!("Preceding instruction loaded.");

        //5. Check that the preceding instruction was for the Ed25519 program
        require_keys_eq!(
            preceding_ix.program_id,
            ed25519_program::ID,
            DeeperErrorCode::InvalidPrecedingInstructionProgram
        );
        msg!("Preceding instruction program ID matches Ed25519 program.");

        // 6. Deserialize the Ed25519 instruction data to verify its contents
        let data = &preceding_ix.data;
        msg!("Preceding instruction data length: {}", data.len());

        // Minimum size check (header = 16 bytes)
        if data.len() < 16 {
            msg!("Error: Preceding Ed25519 instruction data length ({}) is less than minimum header size (16).", data.len());
            return Err(error!(DeeperErrorCode::InvalidEd25519InstructionData));
        }

        let num_signatures = data[0];
        require!(
            num_signatures == 1,
            DeeperErrorCode::InvalidEd25519InstructionData
        );

        // Offsets are little-endian u16
        let signature_offset = u16::from_le_bytes(data[2..4].try_into().unwrap()) as usize;
        let public_key_offset = u16::from_le_bytes(data[6..8].try_into().unwrap()) as usize;
        let message_data_offset = u16::from_le_bytes(data[10..12].try_into().unwrap()) as usize;
        let message_data_size = u16::from_le_bytes(data[12..14].try_into().unwrap()) as usize;

        msg!("Parsed signature_offset: {}", signature_offset);
        msg!("Parsed public_key_offset: {}", public_key_offset);
        msg!("Parsed message_data_offset: {}", message_data_offset);
        msg!("Parsed message_data_size: {}", message_data_size);

        //msg!("Parsed offsets from preceding ix: sig={}, pk={}, msg={}, msg_size={}", signature_offset, public_key_offset, message_data_offset, message_data_size);

        // Check data boundaries based on offsets and sizes
        let sig_end = signature_offset.checked_add(64).ok_or_else(|| {
            msg!(
                "Error: Overflow calculating sig_end (offset={})",
                signature_offset
            );
            error!(DeeperErrorCode::InvalidEd25519InstructionData)
        })?;
        let pk_end = public_key_offset.checked_add(32).ok_or_else(|| {
            msg!(
                "Error: Overflow calculating pk_end (offset={})",
                public_key_offset
            );
            error!(DeeperErrorCode::InvalidEd25519InstructionData)
        })?;
        let msg_end = message_data_offset
            .checked_add(message_data_size as usize)
            .ok_or_else(|| {
                msg!(
                    "Error: Overflow calculating msg_end (offset={}, size={})",
                    message_data_offset,
                    message_data_size
                );
                error!(DeeperErrorCode::InvalidEd25519InstructionData)
            })?;

        msg!("Calculated sig_end: {}", sig_end);
        msg!("Calculated pk_end: {}", pk_end);
        msg!("Calculated msg_end: {}", msg_end);
        msg!(
            "Comparing calculated ends against data.len(): {}",
            data.len()
        );

        require!(
            sig_end <= data.len(),
            DeeperErrorCode::InvalidEd25519InstructionData
        );
        require!(
            pk_end <= data.len(),
            DeeperErrorCode::InvalidEd25519InstructionData
        );
        require!(
            msg_end <= data.len(),
            DeeperErrorCode::InvalidEd25519InstructionData
        );

        // 7. Extract the data from the preceding instruction
        let ix_signature = &data[signature_offset..sig_end];
        let ix_public_key = &data[public_key_offset..pk_end];
        let ix_message = &data[message_data_offset..msg_end];

        // 8. Compare with the arguments passed to *this* instruction
        require!(
            ix_signature == signature,
            DeeperErrorCode::SignatureMismatch
        );
        require!(
            ix_public_key == public_key,
            DeeperErrorCode::PublicKeyMismatch
        );
        require!(ix_message == message, DeeperErrorCode::MessageMismatch);

        msg!("Verification successful: Preceding Ed25519 instruction data matches arguments.");
        Ok(())
    }

    pub fn set_settings(
        ctx: Context<SetSettings>,
        idx: u16,
        settings: Vec<CreditSetting>,
    ) -> Result<()> {
        if settings.len() > CREDIT_SIZE {
            return err!(DeeperErrorCode::InvalidSettingIndex);
        }

        msg!("Settings len: {}", settings.len());
        for (i, setting) in settings.iter().enumerate() {
            msg!(
                "Setting {}: apy = {}, balance = {}",
                i,
                setting.apy,
                setting.balance
            );
        }

        let account = &mut ctx.accounts.settings_account;

        if account.settings.is_empty() && account.idx == 0 {
            account.idx = idx;
            msg!(
                "Initialized CreditSettingsAccount with idx: {}",
                account.idx
            );
        }

        if account.idx != idx {
            return err!(DeeperErrorCode::InvalidIdx);
        }

        account.settings = settings;

        msg!(
            "Set {:?} settings for account idx {}",
            account.settings,
            account.idx
        );

        Ok(())
    }

    pub fn add_setting(ctx: Context<AddSetting>, idx: u16, apy: u32, balance: u64) -> Result<()> {
        let account = &mut ctx.accounts.settings_account;

        if account.settings.is_empty() && account.idx == 0 {
            account.idx = idx;
            msg!(
                "Initialized CreditSettingsAccount with idx: {}",
                account.idx
            );
        }
        if account.settings.len() >= CREDIT_SIZE {
            return err!(DeeperErrorCode::InvalidSettingIndex);
        }

        if account.idx != idx {
            return err!(DeeperErrorCode::InvalidIdx);
        }

        let new_setting = CreditSetting { apy, balance };
        account.settings.push(new_setting);
        msg!(
            "Added new setting to idx {}: apy = {}, balance = {}",
            account.idx,
            apy,
            balance
        );

        Ok(())
    }

    pub fn update_setting(
        ctx: Context<UpdateSetting>,
        idx: u16,
        setting_index: u32,
        apy: u32,
        balance: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.settings_account;

        // 验证 idx 一致性
        if account.idx != idx {
            return err!(DeeperErrorCode::InvalidIdx);
        }

        if setting_index as usize >= account.settings.len() {
            return err!(DeeperErrorCode::InvalidSettingIndex);
        }
        account.settings[setting_index as usize] = CreditSetting { apy, balance };
        msg!(
            "Updated setting at index {} for account idx {}: apy = {}, balance = {}",
            setting_index,
            account.idx,
            apy,
            balance
        );
        Ok(())
    }

    pub fn get_setting(
        ctx: Context<GetSetting>,
        idx: u16,
        setting_index: u32,
    ) -> Result<CreditSetting> {
        let account = &ctx.accounts.settings_account;
        if account.idx != idx {
            return err!(DeeperErrorCode::InvalidIdx);
        }

        if setting_index as usize >= account.settings.len() {
            return err!(DeeperErrorCode::InvalidSettingIndex);
        }
        Ok(account.settings[setting_index as usize])
    }
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

#[derive(Accounts)]
pub struct VerifyEd25519Sysvar<'info> {
    // Renamed context struct
    #[account(mut)]
    pub signer: Signer<'info>, // Transaction fee payer
    /// CHECK: InstructionsSysvar account - Checked by address constraint
    #[account(address = tx_instructions::ID)]
    pub instruction_sysvar: AccountInfo<'info>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, InitSpace, Debug)]
pub struct CreditSetting {
    pub apy: u32,
    pub balance: u64,
}

#[account]
#[derive(InitSpace, Debug)]
pub struct CreditSettingsAccount {
    #[max_len(10, 12)]
    pub settings: Vec<CreditSetting>,
    pub idx: u16,
}

#[derive(Accounts)]
#[instruction(idx: u16)]
pub struct SetSettings<'info> {
    #[account(
        init_if_needed,
        payer = signer,
        space = 8 + CreditSettingsAccount::INIT_SPACE,
        seeds = [b"settings".as_ref(), &idx.to_le_bytes()],
        bump
    )]
    pub settings_account: Account<'info, CreditSettingsAccount>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(idx: u16)]
pub struct AddSetting<'info> {
    #[account(
        init_if_needed,
        payer = signer,
        space = 8 + CreditSettingsAccount::INIT_SPACE,
        seeds = [b"settings".as_ref(), &idx.to_le_bytes()],
        bump
    )]
    pub settings_account: Account<'info, CreditSettingsAccount>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(idx: u16)]
pub struct UpdateSetting<'info> {
    #[account(
        mut,
        seeds = [b"settings", &idx.to_le_bytes()],
        bump
    )]
    pub settings_account: Account<'info, CreditSettingsAccount>,
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(idx: u16)]
pub struct GetSetting<'info> {
    #[account(
        seeds = [b"settings".as_ref(), &idx.to_le_bytes()],
        bump
    )]
    pub settings_account: Account<'info, CreditSettingsAccount>,
}
