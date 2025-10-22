use std::io::{self, BufRead, Write};
use serde::{Deserialize, Serialize};
use serde_json;

// Lisk-specific crypto
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use base58::ToBase58;
use hex;

#[derive(Debug, Serialize, Deserialize)]
struct WalletRequest {
    action: String,
    network: String,
    message: Option<String>,
    public_key: Option<String>,
    signature: Option<String>,
    address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletResponse {
    success: bool,
    address: Option<String>,
    public_key: Option<String>,
    signature: Option<String>,
    verified: Option<bool>,
    error: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyPair {
    private_key: String,
    public_key: String,
    address: String,
}

fn generate_lisk_keypair() -> KeyPair {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    
    // Lisk address generation: SHA256(public_key).first_20_bytes -> base58
    let mut hasher = Sha256::new();
    hasher.update(keypair.public.as_bytes());
    let hash_result = hasher.finalize();
    let address_bytes = &hash_result[..20];
    let address = address_bytes.to_base58();
    
    KeyPair {
        private_key: hex::encode(keypair.secret.as_bytes()),
        public_key: hex::encode(keypair.public.as_bytes()),
        address,
    }
}

fn get_lisk_address_from_public_key(public_key_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    let public_key_bytes = hex::decode(public_key_hex)?;
    let public_key = PublicKey::from_bytes(&public_key_bytes)?;
    
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    let hash_result = hasher.finalize();
    let address_bytes = &hash_result[..20];
    Ok(address_bytes.to_base58())
}

fn sign_message(private_key_hex: &str, message: &str) -> Result<String, Box<dyn std::error::Error>> {
    let private_key_bytes = hex::decode(private_key_hex)?;
    let secret_key = SecretKey::from_bytes(&private_key_bytes)?;
    let public_key = PublicKey::from(&secret_key);
    let keypair = Keypair {
        secret: secret_key,
        public: public_key,
    };
    
    let signature = keypair.sign(message.as_bytes());
    Ok(hex::encode(signature.to_bytes()))
}

fn verify_signature(public_key_hex: &str, message: &str, signature_hex: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let public_key_bytes = hex::decode(public_key_hex)?;
    let public_key = PublicKey::from_bytes(&public_key_bytes)?;
    
    let signature_bytes = hex::decode(signature_hex)?;
    
    // Convert Vec<u8> to [u8; 64] for signature
    let mut signature_array = [0u8; 64];
    if signature_bytes.len() != 64 {
        return Ok(false);
    }
    signature_array.copy_from_slice(&signature_bytes);
    
    // Signature::from_bytes returns a Result, so we need to handle it
    let signature = match Signature::from_bytes(&signature_array) {
        Ok(sig) => sig,
        Err(_) => return Ok(false), // Invalid signature format
    };
    
    match public_key.verify(message.as_bytes(), &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn handle_generate_keypair() -> WalletResponse {
    let keypair = generate_lisk_keypair();
    WalletResponse {
        success: true,
        address: Some(keypair.address),
        public_key: Some(keypair.public_key),
        signature: None,
        verified: None,
        error: None,
        message: None,
    }
}

fn handle_get_address(public_key: &str) -> WalletResponse {
    match get_lisk_address_from_public_key(public_key) {
        Ok(address) => WalletResponse {
            success: true,
            address: Some(address),
            public_key: Some(public_key.to_string()),
            signature: None,
            verified: None,
            error: None,
            message: None,
        },
        Err(e) => WalletResponse {
            success: false,
            address: None,
            public_key: None,
            signature: None,
            verified: None,
            error: Some(format!("Failed to get address: {}", e)),
            message: None,
        },
    }
}

fn handle_sign_message(private_key: &str, message: &str) -> WalletResponse {
    match sign_message(private_key, message) {
        Ok(signature) => WalletResponse {
            success: true,
            address: None,
            public_key: None,
            signature: Some(signature),
            verified: None,
            error: None,
            message: Some(message.to_string()),
        },
        Err(e) => WalletResponse {
            success: false,
            address: None,
            public_key: None,
            signature: None,
            verified: None,
            error: Some(format!("Failed to sign message: {}", e)),
            message: None,
        },
    }
}

fn handle_verify_signature(public_key: &str, message: &str, signature: &str) -> WalletResponse {
    match verify_signature(public_key, message, signature) {
        Ok(verified) => WalletResponse {
            success: true,
            address: None,
            public_key: None,
            signature: None,
            verified: Some(verified),
            error: None,
            message: None,
        },
        Err(e) => WalletResponse {
            success: false,
            address: None,
            public_key: None,
            signature: None,
            verified: None,
            error: Some(format!("Failed to verify signature: {}", e)),
            message: None,
        },
    }
}

fn handle_verify_address(address: &str, public_key: &str) -> WalletResponse {
    match get_lisk_address_from_public_key(public_key) {
        Ok(derived_address) => WalletResponse {
            success: true,
            address: Some(derived_address.clone()),
            public_key: Some(public_key.to_string()),
            signature: None,
            verified: Some(derived_address == address),
            error: None,
            message: None,
        },
        Err(e) => WalletResponse {
            success: false,
            address: None,
            public_key: None,
            signature: None,
            verified: None,
            error: Some(format!("Failed to verify address: {}", e)),
            message: None,
        },
    }
}

fn main() {
    let stdin = io::stdin();
    
    // Read JSON requests from stdin
    for line in stdin.lock().lines() {
        let input = match line {
            Ok(line) => line,
            Err(_) => continue,
        };
        
        let request: WalletRequest = match serde_json::from_str(&input) {
            Ok(req) => req,
            Err(e) => {
                let error_response = WalletResponse {
                    success: false,
                    address: None,
                    public_key: None,
                    signature: None,
                    verified: None,
                    error: Some(format!("Invalid JSON: {}", e)),
                    message: None,
                };
                println!("{}", serde_json::to_string(&error_response).unwrap());
                continue;
            }
        };
        
        let response = match request.action.as_str() {
            "generate_keypair" => handle_generate_keypair(),
            "get_address" => {
                if let Some(public_key) = request.public_key {
                    handle_get_address(&public_key)
                } else {
                    WalletResponse {
                        success: false,
                        address: None,
                        public_key: None,
                        signature: None,
                        verified: None,
                        error: Some("public_key required for get_address".to_string()),
                        message: None,
                    }
                }
            },
            "sign_message" => {
                if let (Some(private_key), Some(message)) = (request.public_key, request.message) {
                    handle_sign_message(&private_key, &message)
                } else {
                    WalletResponse {
                        success: false,
                        address: None,
                        public_key: None,
                        signature: None,
                        verified: None,
                        error: Some("private_key and message required for sign_message".to_string()),
                        message: None,
                    }
                }
            },
            "verify_signature" => {
                if let (Some(public_key), Some(message), Some(signature)) = 
                    (request.public_key, request.message, request.signature) {
                    handle_verify_signature(&public_key, &message, &signature)
                } else {
                    WalletResponse {
                        success: false,
                        address: None,
                        public_key: None,
                        signature: None,
                        verified: None,
                        error: Some("public_key, message, and signature required for verify_signature".to_string()),
                        message: None,
                    }
                }
            },
            "verify_address" => {
                if let (Some(address), Some(public_key)) = (request.address, request.public_key) {
                    handle_verify_address(&address, &public_key)
                } else {
                    WalletResponse {
                        success: false,
                        address: None,
                        public_key: None,
                        signature: None,
                        verified: None,
                        error: Some("address and public_key required for verify_address".to_string()),
                        message: None,
                    }
                }
            },
            _ => WalletResponse {
                success: false,
                address: None,
                public_key: None,
                signature: None,
                verified: None,
                error: Some(format!("Unknown action: {}", request.action)),
                message: None,
            },
        };
        
        // Send response back to Python
        println!("{}", serde_json::to_string(&response).unwrap());
        io::stdout().flush().unwrap();
    }
}