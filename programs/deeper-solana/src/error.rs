use anchor_lang::prelude::*;

#[error_code]
pub enum DeeperErrorCode {
    #[msg("Only the admin can perform this action")]
    Unauthorized,
    #[msg("Signature verification failed")]
    VerificationFailed,
    #[msg("Failed to load instruction from sysvar")]
    InstructionLoadFailed,
    #[msg("No preceding instruction found")]
    NoPrecedingInstruction,
    #[msg("Preceding instruction was not for the Ed25519 program")]
    InvalidPrecedingInstructionProgram,
    #[msg("Ed25519 instruction data is invalid, corrupt, or has invalid offsets/size")]
    InvalidEd25519InstructionData,
    #[msg("Signature in Ed25519 instruction does not match expected value")]
    SignatureMismatch,
    #[msg("Public key in Ed25519 instruction does not match expected value")]
    PublicKeyMismatch,
    #[msg("Message in Ed25519 instruction does not match expected value")]
    MessageMismatch,
    #[msg("Index out of bounds")]
    InvalidSettingIndex,
    #[msg("Provided idx does not match account idx")]
    InvalidIdx,
}
