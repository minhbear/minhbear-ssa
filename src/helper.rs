use std::str::FromStr;

use solana_sdk::{pubkey::Pubkey, signature::Keypair};

use crate::AppError;

pub fn parse_pubkey(key_str: &str) -> Result<Pubkey, AppError> {
    if key_str.trim().is_empty() {
        return Err(AppError("Public key cannot be empty".to_string()));
    }
    Pubkey::from_str(key_str.trim()).map_err(|_| AppError("Invalid public key format".to_string()))
}

pub fn parse_keypair(secret_str: &str) -> Result<Keypair, AppError> {
    if secret_str.trim().is_empty() {
        return Err(AppError("Secret key cannot be empty".to_string()));
    }
    
    let bytes = bs58::decode(secret_str.trim())
        .into_vec()
        .map_err(|_| AppError("Invalid base58 secret key format".to_string()))?;

    if bytes.len() != 64 {
        return Err(AppError("Invalid secret key length".to_string()));
    }

    Keypair::from_bytes(&bytes).map_err(|_| AppError("Invalid keypair format".to_string()))
}

pub fn validate_token_amount(amount: u64) -> Result<(), AppError> {
    if amount == 0 {
        return Err(AppError("Amount must be greater than 0".to_string()));
    }
    if amount > u64::MAX / 2 {
        return Err(AppError("Amount exceeds maximum allowed value".to_string()));
    }
    Ok(())
}