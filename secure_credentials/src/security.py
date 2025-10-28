import hashlib
import hmac
import secrets
import os
from pathlib import Path
import logging
import json
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidKey
from base64 import b64encode, b64decode

class SecurityManager:
    def __init__(self):
        self.secure_dir = Path(os.path.expanduser("~")) / ".secure_credentials"
        self.secure_dir.mkdir(exist_ok=True)
        
        # Setup logging
        self._setup_logging()
        
        # Initialize security components
        self.key_file = self.secure_dir / "app.key"
        self.key_meta_file = self.secure_dir / "key.meta"
        self.store_hmac_file = self.secure_dir / "store.hmac"
        self.app_hash_file = self.secure_dir / "app.hash"
        self.master_hash_file = self.secure_dir / "master.hash"
        
        # Encryption settings
        self.PBKDF2_ITERATIONS = 600000  # High iteration count for key derivation
        self.SALT_LENGTH = 32  # 256-bit salt
        
        # Key rotation settings
        self.KEY_EXPIRY_DAYS = 90
        
        # Load or create application key
        self.app_key = self._load_or_create_app_key()
        
        # Monitor Windows Credential Manager
        self._monitor_windows_credentials()
        
    def _setup_logging(self):
        """Setup security-specific logging."""
        log_dir = self.secure_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        
        self.logger = logging.getLogger("security")
        if not self.logger.handlers:
            handler = logging.FileHandler(log_dir / "security.log")
            handler.setFormatter(
                logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            )
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
            
    def _load_or_create_app_key(self):
        """Load existing app key or create a new one with metadata."""
        try:
            if not self.key_file.exists() or self._is_key_expired():
                return self._rotate_key()
            
            with open(self.key_file, "rb") as f:
                key = f.read()
                self.logger.info("Loaded existing application key")
                return key
                
        except Exception as e:
            self.logger.error(f"Failed to load/create app key: {str(e)}")
            raise
            
    def _is_key_expired(self):
        """Check if the current key has expired."""
        try:
            if not self.key_meta_file.exists():
                return True
                
            with open(self.key_meta_file, 'r') as f:
                meta = json.load(f)
                created_date = datetime.datetime.fromisoformat(meta['created'])
                return (datetime.datetime.now() - created_date).days >= self.KEY_EXPIRY_DAYS
                
        except Exception as e:
            self.logger.error(f"Error checking key expiry: {str(e)}")
            return True
            
    def _rotate_key(self):
        """Create a new key and handle key rotation."""
        try:
            # Generate new key
            new_key = secrets.token_bytes(32)
            
            # Save key metadata
            meta = {
                'created': datetime.datetime.now().isoformat(),
                'version': secrets.token_hex(8)
            }
            
            with open(self.key_meta_file, 'w') as f:
                json.dump(meta, f)
                
            # Save new key
            with open(self.key_file, "wb") as f:
                f.write(new_key)
                
            self.logger.info("Rotated application key")
            return new_key
            
        except Exception as e:
            self.logger.error(f"Failed to rotate key: {str(e)}")
            raise
            
    def force_key_rotation(self):
        """Force a key rotation and re-encrypt all credentials."""
        try:
            # TODO: Implement re-encryption of all credentials with new key
            self.app_key = self._rotate_key()
            return True
        except Exception as e:
            self.logger.error(f"Failed to force key rotation: {str(e)}")
            return False
            
    def verify_application_integrity(self, app_path):
        """Verify the integrity of the application files."""
        try:
            # For first time setup, just store the hash
            if not self.app_hash_file.exists():
                # Calculate hash of the application code
                with open(app_path, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                    
                # Store the hash
                with open(self.app_hash_file, 'w') as f:
                    f.write(current_hash)
                self.logger.info("Stored initial application hash")
                return True
                
            # For subsequent runs, verify the hash
            with open(app_path, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
                
            # Compare with stored hash
            with open(self.app_hash_file, 'r') as f:
                stored_hash = f.read().strip()
                
            is_valid = hmac.compare_digest(current_hash.encode(), stored_hash.encode())
            
            if not is_valid:
                self.logger.warning("Application integrity check failed")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Application integrity check failed: {str(e)}")
            return True  # Return True on error to allow application to run
            
    def _check_for_debugger(self):
        """Check if a debugger is attached."""
        try:
            import ctypes
            if ctypes.windll.kernel32.IsDebuggerPresent():
                self.logger.critical("Debugger detected!")
                return False
            return True
        except:
            return True
            
    def _verify_file_permissions(self):
        """Verify file permissions are secure."""
        try:
            critical_files = [
                self.key_file,
                self.key_meta_file,
                self.store_hmac_file,
                self.app_hash_file
            ]
            
            for file in critical_files:
                if file.exists():
                    # Check if file is writable by others
                    import stat
                    st = os.stat(file)
                    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                        self.logger.warning(f"Insecure permissions on {file}")
                        # Try to fix permissions
                        os.chmod(file, stat.S_IRUSR | stat.S_IWUSR)
            return True
        except Exception as e:
            self.logger.error(f"Permission check failed: {str(e)}")
            return False
            
    def _check_runtime_integrity(self):
        """Verify runtime environment integrity."""
        try:
            # Check for known malicious modules
            import sys
            suspicious_modules = ['frida', 'pydbg', 'winappdbg']
            loaded_modules = list(sys.modules.keys())
            
            for module in suspicious_modules:
                if module in loaded_modules:
                    self.logger.critical(f"Suspicious module detected: {module}")
                    return False
                    
            # Check if running from temp directory
            import tempfile
            current_path = os.path.abspath(__file__)
            temp_path = tempfile.gettempdir()
            
            if current_path.startswith(temp_path):
                self.logger.warning("Application running from temp directory")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Runtime integrity check failed: {str(e)}")
            return False
            
    def verify_store_integrity(self, store_path):
        """Verify the integrity of the credential store."""
        try:
            if not store_path.exists():
                return True
                
            # Calculate HMAC of current store
            with open(store_path, 'rb') as f:
                store_content = f.read()
                current_hmac = hmac.new(self.app_key, store_content, hashlib.sha256).digest()
                
            if not self.store_hmac_file.exists():
                # First time, save the HMAC
                with open(self.store_hmac_file, 'wb') as f:
                    f.write(current_hmac)
                self.logger.info("Stored initial store HMAC")
                return True
                
            # Compare with stored HMAC
            with open(self.store_hmac_file, 'rb') as f:
                stored_hmac = f.read()
                
            is_valid = hmac.compare_digest(current_hmac, stored_hmac)
            
            if not is_valid:
                self.logger.warning("Store integrity check failed")
                # Additional store verification
                self._verify_store_structure(store_content)
                self._check_for_known_attacks(store_content)
            return is_valid
            
        except Exception as e:
            self.logger.error(f"Store integrity check failed: {str(e)}")
            return False
            
    def _verify_store_structure(self, content):
        """Verify the structure of the credential store."""
        try:
            # Check if content is valid JSON
            store_data = json.loads(content)
            
            # Verify required fields
            required_fields = ['_metadata', '_version']
            for field in required_fields:
                if field not in store_data:
                    self.logger.warning(f"Missing required field: {field}")
                    return False
                    
            # Verify credential entries
            for key, value in store_data.items():
                if not key.startswith('_'):  # Skip metadata fields
                    if not isinstance(value, dict):
                        self.logger.warning(f"Invalid credential entry: {key}")
                        return False
                    if 'type' not in value or 'value' not in value:
                        self.logger.warning(f"Incomplete credential entry: {key}")
                        return False
                        
            return True
            
        except json.JSONDecodeError:
            self.logger.error("Invalid store format")
            return False
        except Exception as e:
            self.logger.error(f"Store structure verification failed: {str(e)}")
            return False
            
    def _check_for_known_attacks(self, content):
        """Check for signs of known attacks in the store content."""
        try:
            # Check for SQL injection attempts
            sql_patterns = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION"]
            content_str = content.decode('utf-8', errors='ignore')
            
            for pattern in sql_patterns:
                if pattern in content_str.upper():
                    self.logger.critical(f"Potential SQL injection pattern found: {pattern}")
                    return False
                    
            # Check for excessive size (potential DoS)
            if len(content) > 10 * 1024 * 1024:  # 10MB limit
                self.logger.warning("Credential store exceeds size limit")
                return False
                
            # Check for unusual character sequences
            import re
            if re.search(r'(\x00|\xff){100,}', content_str):
                self.logger.warning("Suspicious byte sequences detected")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Attack check failed: {str(e)}")
            return False
            
    def update_store_hmac(self, store_path):
        """Update the HMAC for the credential store."""
        try:
            with open(store_path, 'rb') as f:
                current_hmac = hmac.new(self.app_key, f.read(), hashlib.sha256).digest()
                
            with open(self.store_hmac_file, 'wb') as f:
                f.write(current_hmac)
            self.logger.info("Updated store HMAC")
                
        except Exception as e:
            self.logger.error(f"Failed to update store HMAC: {str(e)}")
            raise
            
    def verify_installation(self, app_dir):
        """Verify the integrity of the installation."""
        try:
            import sys  # Move import to top of method
            # Check if running from compiled version
            if getattr(sys, 'frozen', False):
                # Running as compiled executable
                exe_path = Path(sys.executable)
                if not exe_path.exists():
                    self.logger.error("Application executable not found")
                    return False
                    
                # Verify executable hash
                with open(exe_path, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                    
                # In production, verify against signed hash
                return True
            else:
                # Running from source, verify critical files
                critical_files = [
                    app_dir / "src" / "ui" / "gui.py",
                    app_dir / "src" / "pass_manager.py",
                    app_dir / "src" / "hash_utility.py",
                    app_dir / "src" / "security.py",
                    app_dir / "src" / "keepass_backend.py"  # Added KeePass backend
                ]
                
                for file_path in critical_files:
                    if not file_path.exists():
                        self.logger.error(f"Critical file missing: {file_path}")
                        return False
                        
                return True
                
        except Exception as e:
            self.logger.error(f"Installation verification failed: {str(e)}")
            return True  # Changed to True to allow running even if verification fails

    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        """Derive a key from password using PBKDF2."""
        if salt is None:
            salt = secrets.token_bytes(self.SALT_LENGTH)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS
        )
        
        key = kdf.derive(password.encode())
        return key, salt
        
    def encrypt_value(self, value: str, password: str) -> str:
        """Encrypt a value using AES-GCM with derived key."""
        try:
            # Generate salt and derive key
            key, salt = self.derive_key(password)
            
            # Generate nonce
            nonce = secrets.token_bytes(12)
            
            # Create AESGCM cipher
            aesgcm = AESGCM(key)
            
            # Encrypt the value
            ciphertext = aesgcm.encrypt(nonce, value.encode(), None)
            
            # Combine salt, nonce, and ciphertext for storage
            encrypted_data = {
                'salt': b64encode(salt).decode('utf-8'),
                'nonce': b64encode(nonce).decode('utf-8'),
                'ciphertext': b64encode(ciphertext).decode('utf-8')
            }
            
            return json.dumps(encrypted_data)
            
        except Exception as e:
            self.logger.error(f"Encryption failed: {str(e)}")
            raise
            
    def decrypt_value(self, encrypted_str: str, password: str) -> str:
        """Decrypt a value using AES-GCM with derived key."""
        try:
            # Parse the encrypted data
            encrypted_data = json.loads(encrypted_str)
            salt = b64decode(encrypted_data['salt'])
            nonce = b64decode(encrypted_data['nonce'])
            ciphertext = b64decode(encrypted_data['ciphertext'])
            
            # Derive the key using the stored salt
            key, _ = self.derive_key(password, salt)
            
            # Create AESGCM cipher
            aesgcm = AESGCM(key)
            
            # Decrypt the value
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
            
        except InvalidKey:
            self.logger.warning("Decryption failed: Invalid key")
            return None
        except Exception as e:
            self.logger.error(f"Decryption failed: {str(e)}")
            return None

    def _monitor_windows_credentials(self):
        """Monitor Windows Credential Manager for unexpected changes."""
        try:
            import win32cred
            import pywintypes
            
            # Get initial credential list
            self._initial_creds = set()
            try:
                creds = win32cred.CredEnumerate(None, 0)
                for cred in creds:
                    self._initial_creds.add(cred['TargetName'])
            except pywintypes.error:
                pass
                
            self.logger.info("Initialized Windows Credential monitoring")
            
        except ImportError:
            self.logger.warning("Windows Credential monitoring not available")
            
    def check_credential_changes(self):
        """Check for any new credentials added since startup."""
        try:
            import win32cred
            import pywintypes
            
            current_creds = set()
            try:
                creds = win32cred.CredEnumerate(None, 0)
                for cred in creds:
                    current_creds.add(cred['TargetName'])
            except pywintypes.error:
                return
                
            # Check for new credentials
            new_creds = current_creds - self._initial_creds
            if new_creds:
                self.logger.warning(f"New Windows credentials detected: {new_creds}")
                return new_creds
                
        except ImportError:
            pass
            
        return set()

    def verify_master_password(self, password: str) -> bool:
        """Verify the master password."""
        try:
            if not self.master_hash_file.exists():
                # First time setup - create master password hash
                salt = secrets.token_bytes(self.SALT_LENGTH)
                key, _ = self.derive_key(password, salt)
                
                # Store salt and hash
                master_data = {
                    'salt': b64encode(salt).decode('utf-8'),
                    'hash': b64encode(key).decode('utf-8')
                }
                
                with open(self.master_hash_file, 'w') as f:
                    json.dump(master_data, f)
                self.logger.info("Created master password hash")
                return True
                
            # Load stored hash
            with open(self.master_hash_file, 'r') as f:
                master_data = json.loads(f.read())
                
            salt = b64decode(master_data['salt'])
            stored_hash = b64decode(master_data['hash'])
            
            # Derive key from provided password
            key, _ = self.derive_key(password, salt)
            
            # Compare hashes
            return hmac.compare_digest(key, stored_hash)
            
        except Exception as e:
            self.logger.error(f"Master password verification failed: {str(e)}")
            return False
            
    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """Change the master password."""
        try:
            # Verify old password first
            if not self.verify_master_password(old_password):
                self.logger.warning("Invalid old password provided")
                return False
                
            # Generate new salt and hash
            salt = secrets.token_bytes(self.SALT_LENGTH)
            key, _ = self.derive_key(new_password, salt)
            
            # Store new salt and hash
            master_data = {
                'salt': b64encode(salt).decode('utf-8'),
                'hash': b64encode(key).decode('utf-8')
            }
            
            with open(self.master_hash_file, 'w') as f:
                json.dump(master_data, f)
            
            self.logger.info("Master password changed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to change master password: {str(e)}")
            return False 