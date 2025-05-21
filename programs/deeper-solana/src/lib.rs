pub mod state;
// pub mod instructions;
pub mod error;

use state::{Config, CreditInfo, CreditSetting, DayCreditHistory};

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    ed25519_program, instruction::Instruction, program::invoke, pubkey::Pubkey,
    sysvar::instructions as tx_instructions, sysvar::instructions::load_instruction_at_checked,
};
use anchor_spl::token::{self, Mint, MintTo, SetAuthority, Token, TokenAccount};
use error::DeeperErrorCode;
// use anchor_spl::{
//     associated_token::AssociatedToken,
//     token_interface::{Mint, TokenAccount, TokenInterface},
// };

pub const CREDIT_SIZE: usize = 10;
pub const LEVEL_ONE: u16 = 100;

pub const START_TIMESTAMP: i64 = 1735689600; // 2025-01-01 00:00:00 UTC with seconds precision
                                             // Replace with your program's actual ID after deployment
declare_id!("H1niZpkjAjop7hqR4jimhtmstiWTLZ9fnooR4vTWFbHs");

fn cur_day() -> u32 {
    let clock: Clock = Clock::get().unwrap();
    msg!("Current clock: {:?}", clock.unix_timestamp);
    let current_second = (clock.unix_timestamp - START_TIMESTAMP) / 1000;
    (current_second / 86400) as u32 // 86400 seconds in a day
}

fn verify_ed25519_signature(
    public_key: [u8; 32],
    message: Vec<u8>,
    signature: [u8; 64],
    data: &[u8],
) -> Result<()> {
    // 6. Deserialize the Ed25519 instruction data to verify its contents
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

    // msg!("Parsed signature_offset: {}", signature_offset);
    // msg!("Parsed public_key_offset: {}", public_key_offset);
    // msg!("Parsed message_data_offset: {}", message_data_offset);
    // msg!("Parsed message_data_size: {}", message_data_size);

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

    // msg!("Calculated sig_end: {}", sig_end);
    // msg!("Calculated pk_end: {}", pk_end);
    // msg!("Calculated msg_end: {}", msg_end);
    // msg!(
    //     "Comparing calculated ends against data.len(): {}",
    //     data.len()
    // );

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

#[program]
pub mod deeper_solana {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        initial_admin: Pubkey,
        dev_key: Pubkey,
    ) -> Result<()> {
        msg!("Initializing contract configuration...");

        // Access the configuration account being initialized
        let config_account = &mut ctx.accounts.dpr_config;

        // Set the admin field in the account's data
        config_account.admin = initial_admin;
        config_account.dev_key = dev_key;
        // You can also store the bump seed if needed for later PDA derivation validation
        config_account.bump = ctx.bumps.dpr_config;

        msg!("Admin set to: {}", config_account.admin);
        msg!("Dev key set to: {}", config_account.dev_key);
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

    pub fn update_timestamp(ctx: Context<UpdateTimeStamp>) -> Result<()> {
        let config = &ctx.accounts.dpr_config;
        if ctx.accounts.payer.key() != config.admin {
            return err!(DeeperErrorCode::Unauthorized);
        }

        let credit = &mut ctx.accounts.credit_info;
        credit.day = cur_day();
        msg!("Updated timestamp for user {}: {}", credit.user, credit.day);
        Ok(())
    }

    pub fn update_dev_key(ctx: Context<UpdateDevKey>, new_dev_key: Pubkey) -> Result<()> {
        msg!("Updating dev key...");

        // Access the configuration account
        let config_account = &mut ctx.accounts.dpr_config;

        // Update the dev key field
        config_account.dev_key = new_dev_key;

        msg!("Dev key updated to: {}", config_account.dev_key);
        Ok(())
    }

    pub fn set_credit(ctx: Context<SetCredit>, campaign: u16, new_credit: u16) -> Result<()> {
        // Check if the signer is the admin
        let config = &ctx.accounts.dpr_config;
        if ctx.accounts.payer.key() != config.admin {
            return err!(DeeperErrorCode::Unauthorized);
        }

        let credit: &mut Account<'_, CreditInfo> = &mut ctx.accounts.credit_info;
        credit.user = ctx.accounts.user.key();
        credit.campaign = campaign;
        credit.credit = new_credit;
        if credit.day == 0 && new_credit > LEVEL_ONE {
            credit.day = cur_day();
        }
        msg!(
            "Updated credit for user {}: day: {}",
            credit.user,
            credit.day
        );
        Ok(())
    }

    pub fn set_mint_authority(ctx: Context<SetMintAuthority>) -> Result<()> {
        let cpi_accounts = SetAuthority {
            account_or_mint: ctx.accounts.mint.to_account_info(),
            current_authority: ctx.accounts.current_authority.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

        token::set_authority(
            cpi_ctx,
            anchor_spl::token::spl_token::instruction::AuthorityType::MintTokens,
            Some(ctx.accounts.mint_authority.key()),
        )?;

        msg!(
            "Mint Authority set to PDA: {} for Mint: {}",
            ctx.accounts.mint_authority.key(),
            ctx.accounts.mint.key()
        );
        Ok(())
    }

    pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
        // 获取 PDA 的 seeds 和 bump
        let seeds = &[b"mint-authority".as_ref(), &[ctx.bumps.mint_authority]];
        let signer_seeds = &[&seeds[..]];

        // 调用 SPL Token 的 mint_to 指令
        let cpi_accounts = MintTo {
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.token_account.to_account_info(),
            authority: ctx.accounts.mint_authority.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts).with_signer(signer_seeds);

        // 执行 mint_to 操作
        token::mint_to(cpi_ctx, amount)?;
        msg!(
            "Minted {} tokens to {}",
            amount,
            ctx.accounts.token_account.key()
        );
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
        msg!("Expected Public Key: {:?}", Pubkey::from(public_key));
        // msg!("Expected Message: {:?}", message); // Can be long
        msg!("Expected Signature: {:?}", signature);
        msg!("dev key: {:?}", ctx.accounts.dpr_config.dev_key);

        if ctx.accounts.dpr_config.dev_key != Pubkey::from(public_key) {
            return err!(DeeperErrorCode::Unauthorized);
        }

        let history: DayCreditHistory = DayCreditHistory::try_from_slice(&message)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        msg!("Parsed history: {:?}", history);

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

        verify_ed25519_signature(public_key, message, signature, &preceding_ix.data)?;

        msg!("Verification successful: Preceding Ed25519 instruction data matches arguments.");

        let info = &mut ctx.accounts.credit_info;
        let settings = &ctx.accounts.settings_account;
        msg!("settings {:?}", settings.settings);

        if info.campaign != settings.idx {
            return err!(DeeperErrorCode::InvalidIdx);
        }
        let cur_day = cur_day();
        // if info.day >= cur_day {
        //     return err!(DeeperErrorCode::InvalidDay);
        // }
        let mut reward = 0;
        let mut last_day = info.day;
        let mut last_level = 0;

        for day_credit in history.history.iter() {
            if day_credit.campaign != info.campaign {
                return err!(DeeperErrorCode::InvalidCampaign);
            }
            // if day_credit.day > cur_day {
            //     return err!(DeeperErrorCode::InvalidDay);
            // }
            msg!("Day credit: {:?} last_day {}", day_credit, last_day);
            let level = day_credit.credit / 100;
            last_level = if level > 8 { 8 } else { level };

            let setting = &settings.settings[level as usize];

            reward += setting.daily_reward * (day_credit.day.saturating_sub(last_day)) as u64;
            last_day = day_credit.day;
        }
        if last_day < cur_day {
            let setting = &settings.settings[last_level as usize];
            reward += setting.daily_reward * (cur_day - last_day) as u64;
        }
        msg!("Reward: {}", reward);

        let seeds = &[b"mint-authority".as_ref(), &[ctx.bumps.mint_authority]];
        let signer_seeds = &[&seeds[..]];

        // 调用 SPL Token 的 mint_to 指令
        let cpi_accounts = MintTo {
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.token_account.to_account_info(),
            authority: ctx.accounts.mint_authority.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts).with_signer(signer_seeds);

        // 执行 mint_to 操作
        token::mint_to(cpi_ctx, reward)?;
        msg!(
            "Minted {} tokens to {}",
            reward,
            ctx.accounts.token_account.key()
        );

        Ok(())
    }

    pub fn set_settings(
        ctx: Context<SetSettings>,
        campaign: u16,
        settings: Vec<CreditSetting>,
    ) -> Result<()> {
        if settings.len() > CREDIT_SIZE {
            return err!(DeeperErrorCode::InvalidSettingIndex);
        }

        msg!("Settings len: {}", settings.len());
        for (i, setting) in settings.iter().enumerate() {
            msg!("Setting {}: daily_reward  = {}", i, setting.daily_reward,);
        }

        let account = &mut ctx.accounts.settings_account;

        if account.settings.is_empty() && account.idx == 0 {
            account.idx = campaign;
            msg!(
                "Initialized CreditSettingsAccount with idx: {}",
                account.idx
            );
        }

        if account.idx != campaign {
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

    pub fn add_setting(ctx: Context<AddSetting>, idx: u16, daily_reward: u64) -> Result<()> {
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

        let new_setting = CreditSetting { daily_reward };
        account.settings.push(new_setting);
        msg!(
            "Added new setting to idx {}: daily_reward  = {}",
            account.idx,
            daily_reward,
        );

        Ok(())
    }

    pub fn update_setting(
        ctx: Context<UpdateSetting>,
        idx: u16,
        setting_index: u32,
        daily_reward: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.settings_account;

        if account.idx != idx {
            return err!(DeeperErrorCode::InvalidIdx);
        }

        if setting_index as usize >= account.settings.len() {
            return err!(DeeperErrorCode::InvalidSettingIndex);
        }
        account.settings[setting_index as usize] = CreditSetting { daily_reward };
        msg!(
            "Updated setting at index {} for account idx {}:  daily_reward  = {}",
            setting_index,
            account.idx,
            daily_reward,
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

    pub fn dummy_instruction(_ctx: Context<GetSetting>, _dummy: DayCreditHistory) -> Result<()> {
        // Empty implementation, used only to allow IDL to include DayCreditHistory
        Ok(())
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
        space = 8+Config::INIT_SPACE, // 8 discriminator + 32 Pubkey + 1 bump
        seeds = [b"config".as_ref()],
        bump
    )]
    pub dpr_config: Account<'info, Config>,

    /// The user account that pays for the account creation rent.
    /// `mut`: The payer's lamport staking_balance  will be modified (decreased).
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
pub struct UpdateTimeStamp<'info> {
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
            space = 8+CreditInfo::INIT_SPACE, // 8 bytes for discriminator + 8 bytes for u64 + 32 bytes for Pubkey
            payer = payer,
            seeds = [b"credit".as_ref(), user.key().as_ref()], // Seeds to derive the PDA
            bump, // Use the stored bump to verify/find the PDA
        )]
    pub credit_info: Account<'info, CreditInfo>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateDevKey<'info> {
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
        space = 8+CreditInfo::INIT_SPACE, // 8 bytes for discriminator + 8 bytes for u64 + 32 bytes for Pubkey
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
    pub credit_info: Account<'info, CreditInfo>,
    pub dpr_config: Account<'info, Config>,
    pub settings_account: Account<'info, CreditSettingsAccount>,

    #[account(mut)]
    pub mint: Account<'info, Mint>, // Mint 账户
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>, // 目标 Token 账户
    #[account(
        seeds = [b"mint-authority"],
        bump
    )]
    pub mint_authority: SystemAccount<'info>, // PDA 作为 Mint Authority
    pub token_program: Program<'info, Token>, // SPL Token 程序
}

#[account]
#[derive(InitSpace, Debug)]
pub struct CreditSettingsAccount {
    #[max_len(10)]
    pub settings: Vec<CreditSetting>,
    pub idx: u16,
}

#[derive(Accounts)]
#[instruction(campaign: u16)]
pub struct SetSettings<'info> {
    #[account(
        init_if_needed,
        payer = signer,
        space = 8+CreditSettingsAccount::INIT_SPACE,
        seeds = [b"settings".as_ref(), &campaign.to_le_bytes()],
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

#[derive(Accounts)]
pub struct SetMintAuthority<'info> {
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub current_authority: Signer<'info>, // 当前 Mint Authority（签名者）
    #[account(
        seeds = [b"mint-authority"],
        bump
    )]
    pub mint_authority: SystemAccount<'info>, // PDA 作为新 Mint Authority
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct MintTokens<'info> {
    #[account(mut)]
    pub mint: Account<'info, Mint>, // Mint 账户
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>, // 目标 Token 账户
    #[account(
        seeds = [b"mint-authority"],
        bump
    )]
    pub mint_authority: SystemAccount<'info>, // PDA 作为 Mint Authority
    pub token_program: Program<'info, Token>, // SPL Token 程序
}
