use actix_web::{App, HttpResponse, HttpServer, Result, middleware::Logger, web};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use solana_sdk::{
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use std::fmt;

mod response;
use response::*;
mod dto;
use dto::*;
mod helper;
use helper::*;

#[derive(Debug)]
struct AppError(String);

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AppError {}

impl actix_web::error::ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::BadRequest().json(ApiResponse::<()>::error(self.0.clone()))
    }
}

async fn generate_keypair() -> Result<HttpResponse> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    let response = ApiResponse::success(KeypairResponse { pubkey, secret });
    Ok(HttpResponse::Ok().json(response))
}

async fn create_token(req: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    if req.mint_authority.trim().is_empty() || req.mint.trim().is_empty() {
        return Err(AppError("Missing required fields".to_string()).into());
    }

    if req.decimals > 9 {
        return Err(AppError("Decimals must be between 0 and 9".to_string()).into());
    }

    let mint_authority = parse_pubkey(&req.mint_authority)?;
    let mint = parse_pubkey(&req.mint)?;

    let instruction = initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        req.decimals,
    )
    .map_err(|e| AppError(format!("Failed to create mint instruction: {}", e)))?;

    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response_data = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: BASE64.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response_data)))
}

async fn mint_token(req: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    validate_token_amount(req.amount)?;

    if req.mint.trim().is_empty()
        || req.destination.trim().is_empty()
        || req.authority.trim().is_empty()
    {
        return Err(AppError("Missing required fields".to_string()).into());
    }

    let mint = parse_pubkey(&req.mint)?;
    let destination = parse_pubkey(&req.destination)?;
    let authority = parse_pubkey(&req.authority)?;

    let destination_ata =
        spl_associated_token_account::get_associated_token_address(&destination, &mint);

    let instruction = mint_to(
        &spl_token::id(),
        &mint,
        &destination_ata,
        &authority,
        &[],
        req.amount,
    )
    .map_err(|e| AppError(format!("Failed to create mint instruction: {}", e)))?;

    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response_data = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: BASE64.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response_data)))
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    if req.message.is_empty() || req.secret.is_empty() {
        let response = ApiResponse::<()>::error("Missing required fields".to_string());
        return Ok(HttpResponse::BadRequest().json(response));
    }

    match parse_keypair(&req.secret) {
        Ok(keypair) => {
            let message_bytes = req.message.as_bytes();
            let signature = keypair.sign_message(message_bytes);

            let response_data = SignMessageResponse {
                signature: BASE64.encode(signature.as_ref()),
                public_key: keypair.pubkey().to_string(),
                message: req.message.clone(),
            };

            let response = ApiResponse::success(response_data);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let response = ApiResponse::<()>::error(e.0);
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    if req.message.trim().is_empty()
        || req.signature.trim().is_empty()
        || req.pubkey.trim().is_empty()
    {
        return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "Missing required fields".to_string(),
        )));
    }

    let pubkey = match parse_pubkey(&req.pubkey) {
        Ok(key) => key,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(e.0))),
    };

    let signature_bytes = match BASE64.decode(req.signature.trim()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                "Invalid base64 signature format".to_string(),
            )));
        }
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                "Invalid signature format".to_string(),
            )));
        }
    };

    let message_bytes = req.message.as_bytes();
    let valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    let response_data = VerifyMessageResponse {
        valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response_data)))
}

async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    if req.lamports == 0 {
        let response =
            ApiResponse::<()>::error("Invalid amount: must be greater than 0".to_string());
        return Ok(HttpResponse::BadRequest().json(response));
    }

    match (parse_pubkey(&req.from), parse_pubkey(&req.to)) {
        (Ok(from), Ok(to)) => {
            let instruction = system_instruction::transfer(&from, &to, req.lamports);

            let accounts: Vec<String> = instruction
                .accounts
                .iter()
                .map(|acc| acc.pubkey.to_string())
                .collect();

            let response_data = SolTransferResponse {
                program_id: instruction.program_id.to_string(),
                accounts,
                instruction_data: BASE64.encode(&instruction.data),
            };

            let response = ApiResponse::success(response_data);
            Ok(HttpResponse::Ok().json(response))
        }
        _ => {
            let response = ApiResponse::<()>::error("Invalid public key format".to_string());
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    validate_token_amount(req.amount)?;

    if req.destination.trim().is_empty()
        || req.mint.trim().is_empty()
        || req.owner.trim().is_empty()
    {
        return Err(AppError("Missing required fields".to_string()).into());
    }

    let destination = parse_pubkey(&req.destination)?;
    let mint = parse_pubkey(&req.mint)?;
    let owner = parse_pubkey(&req.owner)?;

    let source_ata = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    let destination_ata =
        spl_associated_token_account::get_associated_token_address(&destination, &mint);

    let instruction = transfer(
        &spl_token::id(),
        &source_ata,
        &destination_ata,
        &owner,
        &[],
        req.amount,
    )
    .map_err(|e| AppError(format!("Failed to create transfer instruction: {}", e)))?;

    let accounts: Vec<TokenAccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| TokenAccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    let response_data = TokenInstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: BASE64.encode(&instruction.data),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response_data)))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let host = "0.0.0.0";
    let addr = format!("{}:{}", host, port);

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .app_data(web::JsonConfig::default().error_handler(|err, _req| {
                actix_web::error::InternalError::from_response(
                    err,
                    HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                        "Invalid JSON format or missing required fields".to_string(),
                    )),
                )
                .into()
            }))
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind(&addr)?
    .run()
    .await
}
