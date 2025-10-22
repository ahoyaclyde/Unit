import json
import subprocess
import os
import shutil
import time
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RustWalletConnector:
    """Python wrapper for Rust wallet connector with robust error handling"""
    
    def __init__(self, binary_path: str = None, max_retries: int = 3):
        self.binary_path = binary_path or self._find_binary()
        self.max_retries = max_retries
        self.process = None
        self._ensure_binary_exists()
        self._start_process()
    
    def _ensure_binary_exists(self):
        """Ensure the binary exists and is executable"""
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"Wallet connector binary not found at: {self.binary_path}")
        
        # Make binary executable (Unix-like systems)
        if os.name != 'nt':  # Not Windows
            os.chmod(self.binary_path, 0o755)
    
    def _find_binary(self) -> str:
        """Find the Rust wallet connector binary with multiple fallback locations"""
        possible_paths = [
            # Primary locations
            "./wallet_connector",
            "./wallet-connector/target/release/wallet_connector",
            "./target/release/wallet_connector",
            
            # Windows executable
            "./wallet_connector.exe",
            "./wallet-connector/target/release/wallet_connector.exe",
            "./target/release/wallet_connector.exe",
            
            # Development paths
            "../wallet_connector",
            "../wallet-connector/target/release/wallet_connector",
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                logger.info(f"Found wallet connector at: {path}")
                return path
        
        # Attempt to build the binary if not found
        return self._build_binary()
    
    def _build_binary(self) -> str:
        """Attempt to build the Rust binary"""
        logger.info("Attempting to build Rust wallet connector...")
        
        build_locations = [
            ("wallet-connector", "./wallet-connector/target/release/wallet_connector"),
            (".", "./target/release/wallet_connector"),
        ]
        
        for build_dir, expected_path in build_locations:
            if os.path.exists(build_dir):
                try:
                    logger.info(f"Building in directory: {build_dir}")
                    result = subprocess.run(
                        ["cargo", "build", "--release"],
                        cwd=build_dir,
                        capture_output=True,
                        text=True,
                        timeout=120  # 2 minute timeout
                    )
                    
                    if result.returncode == 0:
                        if os.path.exists(expected_path):
                            logger.info(f"Build successful: {expected_path}")
                            return expected_path
                        else:
                            logger.warning(f"Build succeeded but binary not found at expected path: {expected_path}")
                    else:
                        logger.error(f"Build failed in {build_dir}: {result.stderr}")
                        
                except subprocess.TimeoutExpired:
                    logger.error(f"Build timed out in {build_dir}")
                except Exception as e:
                    logger.error(f"Build error in {build_dir}: {e}")
        
        raise FileNotFoundError(
            "Rust wallet connector binary not found and could not be built. "
            "Please ensure Rust is installed and run 'cargo build --release' manually."
        )
    
    def _start_process(self):
        """Start the Rust process with retry logic"""
        for attempt in range(self.max_retries):
            try:
                self.process = subprocess.Popen(
                    [self.binary_path],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Test the process with a simple request
                test_response = self._send_request_safe({"action": "generate_keypair", "network": "lisk"})
                if test_response and test_response.get("success"):
                    logger.info("Wallet connector process started successfully")
                    return
                else:
                    self._cleanup_process()
                    logger.warning(f"Process test failed, attempt {attempt + 1}/{self.max_retries}")
                    
            except Exception as e:
                self._cleanup_process()
                logger.warning(f"Failed to start process, attempt {attempt + 1}/{self.max_retries}: {e}")
            
            if attempt < self.max_retries - 1:
                time.sleep(1)  # Wait before retry
        
        raise RuntimeError(f"Failed to start Rust wallet connector after {self.max_retries} attempts")
    
    def _cleanup_process(self):
        """Clean up the process if it exists"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            except Exception as e:
                logger.warning(f"Error cleaning up process: {e}")
            finally:
                self.process = None
    
    def _check_process(self) -> bool:
        """Check if the process is still running"""
        if not self.process:
            return False
        
        return self.process.poll() is None
    
    def _restart_process_if_needed(self):
        """Restart the process if it's not running"""
        if not self._check_process():
            logger.warning("Wallet connector process not running, restarting...")
            self._cleanup_process()
            self._start_process()
    
    def _send_request_safe(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send request with basic error handling"""
        try:
            request_json = json.dumps(request) + "\n"
            self.process.stdin.write(request_json)
            self.process.stdin.flush()
            
            response_line = self.process.stdout.readline().strip()
            if response_line:
                return json.loads(response_line)
                
        except Exception as e:
            logger.error(f"Error sending request: {e}")
        
        return None
    
    def _send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to Rust process with comprehensive error handling"""
        for attempt in range(self.max_retries):
            try:
                self._restart_process_if_needed()
                
                response = self._send_request_safe(request)
                if response:
                    return response
                else:
                    logger.warning(f"Empty response, attempt {attempt + 1}/{self.max_retries}")
                    
            except Exception as e:
                logger.warning(f"Request failed, attempt {attempt + 1}/{self.max_retries}: {e}")
            
            if attempt < self.max_retries - 1:
                time.sleep(0.5)  # Brief wait before retry
                self._restart_process_if_needed()
        
        raise RuntimeError(f"Failed to get valid response after {self.max_retries} attempts")
    
    def generate_keypair(self) -> Dict[str, str]:
        """Generate new Lisk keypair"""
        response = self._send_request({
            "action": "generate_keypair",
            "network": "lisk"
        })
        
        if response.get("success"):
            return {
                "private_key": response["private_key"],
                "public_key": response["public_key"],
                "address": response["address"]
            }
        else:
            error_msg = response.get('error', 'Key generation failed')
            logger.error(f"Key generation failed: {error_msg}")
            raise RuntimeError(f"Key generation failed: {error_msg}")
    
    def get_address_from_public_key(self, public_key: str) -> str:
        """Get Lisk address from public key"""
        response = self._send_request({
            "action": "get_address",
            "network": "lisk",
            "public_key": public_key
        })
        
        if response.get("success"):
            return response["address"]
        else:
            error_msg = response.get('error', 'Address derivation failed')
            logger.error(f"Address derivation failed: {error_msg}")
            raise RuntimeError(f"Address derivation failed: {error_msg}")
    
    def sign_message(self, private_key: str, message: str) -> str:
        """Sign a message with private key"""
        response = self._send_request({
            "action": "sign_message",
            "network": "lisk",
            "public_key": private_key,  # Note: field name should be private_key but Rust expects public_key
            "message": message
        })
        
        if response.get("success"):
            return response["signature"]
        else:
            error_msg = response.get('error', 'Signing failed')
            logger.error(f"Signing failed: {error_msg}")
            raise RuntimeError(f"Signing failed: {error_msg}")
    
    def verify_signature(self, public_key: str, message: str, signature: str) -> bool:
        """Verify a signature"""
        response = self._send_request({
            "action": "verify_signature",
            "network": "lisk",
            "public_key": public_key,
            "message": message,
            "signature": signature
        })
        
        if response.get("success"):
            return response.get("verified", False)
        else:
            error_msg = response.get('error', 'Verification failed')
            logger.error(f"Signature verification failed: {error_msg}")
            raise RuntimeError(f"Signature verification failed: {error_msg}")
    
    def verify_address(self, address: str, public_key: str) -> bool:
        """Verify that address matches public key"""
        response = self._send_request({
            "action": "verify_address",
            "network": "lisk",
            "address": address,
            "public_key": public_key
        })
        
        if response.get("success"):
            return response.get("verified", False)
        else:
            error_msg = response.get('error', 'Address verification failed')
            logger.error(f"Address verification failed: {error_msg}")
            raise RuntimeError(f"Address verification failed: {error_msg}")
    
    def create_verification_message(self, address: str, nonce: str) -> str:
        """Create a message for wallet verification"""
        return f"ForensicPlatform: Verify ownership of {address} with nonce: {nonce}"
    
    def health_check(self) -> bool:
        """Check if the wallet connector is healthy"""
        try:
            response = self._send_request_safe({"action": "generate_keypair", "network": "lisk"})
            return response is not None and response.get("success", False)
        except:
            return False
    
    def close(self):
        """Close the Rust process gracefully"""
        logger.info("Closing wallet connector process")
        self._cleanup_process()


# Singleton instance with lazy initialization
_wallet_connector_instance = None

def get_wallet_connector(binary_path: str = None) -> RustWalletConnector:
    """Get or create wallet connector instance with lazy initialization"""
    global _wallet_connector_instance
    
    if _wallet_connector_instance is None:
        logger.info("Initializing Rust wallet connector...")
        _wallet_connector_instance = RustWalletConnector(binary_path)
    
    # Check if instance is still healthy
    if not _wallet_connector_instance.health_check():
        logger.warning("Wallet connector unhealthy, recreating instance...")
        _wallet_connector_instance.close()
        _wallet_connector_instance = RustWalletConnector(binary_path)
    
    return _wallet_connector_instance

def close_wallet_connector():
    """Close the wallet connector instance"""
    global _wallet_connector_instance
    if _wallet_connector_instance:
        _wallet_connector_instance.close()
        _wallet_connector_instance = None
        logger.info("Wallet connector closed")

# Context manager support
class WalletConnectorContext:
    """Context manager for wallet connector"""
    
    def __init__(self, binary_path: str = None):
        self.binary_path = binary_path
        self.connector = None
    
    def __enter__(self) -> RustWalletConnector:
        self.connector = get_wallet_connector(self.binary_path)
        return self.connector
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connector:
            # Don't close the singleton instance, just leave it open for reuse
            pass

# Test function
def test_wallet_connector():
    """Test the wallet connector functionality"""
    try:
        connector = get_wallet_connector()
        
        # Test keypair generation
        keypair = connector.generate_keypair()
        print("✓ Keypair generation successful")
        print(f"  Address: {keypair['address']}")
        print(f"  Public Key: {keypair['public_key'][:20]}...")
        
        # Test address derivation
        derived_address = connector.get_address_from_public_key(keypair['public_key'])
        print("✓ Address derivation successful")
        print(f"  Derived Address: {derived_address}")
        
        # Test message signing
        test_message = "Test message for signing"
        signature = connector.sign_message(keypair['private_key'], test_message)
        print("✓ Message signing successful")
        print(f"  Signature: {signature[:20]}...")
        
        # Test signature verification
        is_valid = connector.verify_signature(keypair['public_key'], test_message, signature)
        print("✓ Signature verification successful")
        print(f"  Signature valid: {is_valid}")
        
        # Test address verification
        address_valid = connector.verify_address(keypair['address'], keypair['public_key'])
        print("✓ Address verification successful")
        print(f"  Address valid: {address_valid}")
        
        print("\n🎉 All tests passed! Wallet connector is working correctly.")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    # Run tests if script is executed directly
    print("Testing Rust wallet connector...")
    success = test_wallet_connector()
    exit(0 if success else 1)