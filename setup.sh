#!/bin/bash
echo "Setting up Forensic Auth System..."

# Create directories
mkdir -p wallet-connector/src templates

# Create Cargo.toml
cat > wallet-connector/Cargo.toml << 'EOF'
[package]
name = "wallet_connector"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
ed25519-dalek = "2.0.0"
rand = "0.8.5"
sha2 = "0.10.6"
base58 = "0.1.0"
EOF

# Create requirements.txt
cat > requirements.txt << 'EOF'
quart>=0.18.0
quart-cors>=0.6.0
aiosqlite>=0.19.0
bcrypt>=4.0.0
pyjwt>=2.0.0
EOF

echo "Building Rust wallet connector..."
cd wallet-connector
cargo build --release
cd ..

echo "Setup complete! Run: python app.py"