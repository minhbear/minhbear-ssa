# Solana Fellowship HTTP Server

A Rust-based HTTP server providing Solana-related functionality including keypair generation, SPL token operations, message signing/verification, and transaction instruction creation.

## Features

- **Keypair Generation**: Generate new Solana keypairs
- **SPL Token Operations**: Create and mint SPL tokens
- **Message Signing/Verification**: Sign and verify messages using Ed25519
- **Transaction Instructions**: Create SOL and SPL token transfer instructions
- **Comprehensive Error Handling**: All errors return status 400 with detailed messages

## Requirements

- Rust 1.70 or higher
- Cargo

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ssa-http-server
```

2. Build the project:
```bash
cargo build --release
```

## Running the Server

### Development
```bash
cargo run
```

### Production
```bash
cargo run --release
```

The server runs on port 8080 by default. You can change this by setting the `PORT` environment variable:
```bash
PORT=3000 cargo run
```

## API Endpoints

All endpoints return JSON responses with the following format:

**Success (Status 200):**
```json
{
  "success": true,
  "data": { /* endpoint-specific data */ }
}
```

**Error (Status 400):**
```json
{
  "success": false,
  "error": "Error description"
}
```

### 1. Generate Keypair
`POST /keypair`

Generates a new Solana keypair.

### 2. Create Token
`POST /token/create`

Creates an SPL token initialize mint instruction.

### 3. Mint Token
`POST /token/mint`

Creates a mint-to instruction for SPL tokens.

### 4. Sign Message
`POST /message/sign`

Signs a message using a private key with Ed25519.

### 5. Verify Message
`POST /message/verify`

Verifies a signed message.

### 6. Send SOL
`POST /send/sol`

Creates a SOL transfer instruction with validation.

### 7. Send Token
`POST /send/token`

Creates an SPL token transfer instruction.

## Running Tests

```bash
cargo test
```

For integration tests (requires server to be running):
```bash
# In one terminal
cargo run

# In another terminal
cargo test --test integration_tests
```

## Security Considerations

- Private keys are never stored on the server
- All cryptographic operations use standard Solana SDK libraries
- Input validation on all endpoints
- Proper error handling to prevent information leakage

## Development

The project uses:
- `actix-web` for the HTTP server
- `solana-sdk` for Solana operations
- `spl-token` for SPL token operations
- `ed25519-dalek` for signature verification
- `base58` and `base64` for encoding/decoding

## License

This project is part of the Solana Fellowship assignment. 