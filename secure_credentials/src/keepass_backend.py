import os
from pathlib import Path
import logging
import datetime
from typing import Optional, Dict, Any
import shutil
import sys
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
from pykeepass import create_database
import hashlib
import hmac
import secrets
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAX_NAME_LENGTH: int = 256


def invalid_name_reason(name: str) -> Optional[str]:
    """Return why a credential name is unusable, or None if it is fine.

    pykeepass builds an XPath predicate from the title, which raises for names containing
    a double quote, so such names could be stored but never found again.
    """
    if not name or not name.strip():
        return "Name cannot be empty"
    if len(name) > MAX_NAME_LENGTH:
        return f"Name is longer than {MAX_NAME_LENGTH} characters"
    if '"' in name:
        return 'Name cannot contain a double quote (")'
    return None


class KeePassHandler:
    def __init__(self, vault_path: Optional[str] = None):
        # Allow custom vault path via parameter or environment variable
        if vault_path:
            self.db_path = Path(vault_path)
            print(f"[KEEPASS] Using vault from parameter: {self.db_path}")
        elif os.getenv("VAULT_PATH"):
            self.db_path = Path(os.getenv("VAULT_PATH"))
            print(f"[KEEPASS] Using vault from VAULT_PATH env: {self.db_path}")
        else:
            self.db_path = Path(os.path.expanduser("~")) / ".secure_credentials" / "vault.kdbx"
            print(f"[KEEPASS] Using default vault: {self.db_path}")
        self.kp = None
        self.setup_logging()
        self.logger.info(f"KeePassHandler initialized with vault: {self.db_path}")

    def setup_logging(self):
        """Setup logging for KeePass operations."""
        log_dir = Path(os.path.expanduser("~")) / ".secure_credentials" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger("keepass")
        if not self.logger.handlers:
            handler = logging.FileHandler(log_dir / "keepass.log")
            handler.setFormatter(
                logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            )
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def create_database(self, password: str) -> bool:
        """Create a new KeePass database."""
        try:
            self.logger.info(f"Starting database creation at path: {self.db_path}")
            
            # Create parent directory with explicit error checking
            parent_dir = self.db_path.parent
            self.logger.info(f"Checking/creating parent directory: {parent_dir}")
            try:
                if not parent_dir.exists():
                    parent_dir.mkdir(parents=True)
                    self.logger.info("Parent directory created successfully")
                else:
                    self.logger.info("Parent directory already exists")
            except Exception as e:
                self.logger.error(f"Failed to create parent directory: {str(e)}")
                raise
            
            # Ensure the directory is writable
            if not os.access(parent_dir, os.W_OK):
                self.logger.error(f"Directory {parent_dir} is not writable")
                raise PermissionError(f"Directory {parent_dir} is not writable")
            
            self.logger.info("Creating new KeePass database...")
            try:
                # Create a new database using the helper function
                self.kp = create_database(str(self.db_path), password=password, keyfile=None)
                self.logger.info("KeePass database object created")
            except Exception as e:
                self.logger.error(f"Failed to create KeePass database object: {str(e)}")
                raise
            
            try:
                self.logger.info("Creating default groups...")
                # Create default groups
                self.kp.add_group(self.kp.root_group, "Passwords")
                self.kp.add_group(self.kp.root_group, "API Keys")
                self.kp.add_group(self.kp.root_group, "Other")
                self.logger.info("Default groups created successfully")
            except Exception as e:
                self.logger.error(f"Failed to create default groups: {str(e)}")
                raise
            
            try:
                self.logger.info("Saving database...")
                # Save the database
                self.kp.save()
                self.logger.info("Database saved successfully")
            except Exception as e:
                self.logger.error(f"Failed to save database: {str(e)}")
                raise
            
            return True
            
        except Exception as e:
            self.logger.error(f"Database creation failed with error: {str(e)}", exc_info=True)
            # If database file was created but incomplete, try to clean it up
            try:
                if self.db_path.exists():
                    self.db_path.unlink()
                    self.logger.info("Cleaned up incomplete database file")
            except:
                self.logger.warning("Failed to clean up incomplete database file")
            return False

    def open_database(self, password: str) -> bool:
        """Open existing KeePass database."""
        try:
            self.kp = PyKeePass(str(self.db_path), password=password)
            self.logger.info("Opened KeePass database")
            return True
        except CredentialsError:
            self.logger.warning("Invalid password provided")
            return False
        except Exception as e:
            self.logger.error(f"Failed to open database: {str(e)}")
            return False

    def verify_password(self, password: str) -> bool:
        """Verify the master password."""
        try:
            # Try to open database with password
            PyKeePass(str(self.db_path), password=password)
            return True
        except:
            return False

    def _hash_credential_password(self, password: str) -> str:
        """Hash a credential password using PBKDF2."""
        salt = secrets.token_bytes(16)
        # Use PBKDF2 with SHA256, 100000 iterations
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        # Store as base64: salt:hash
        return b64encode(salt + key).decode('utf-8')

    def _verify_credential_password(self, password: str, stored_hash: str) -> bool:
        """Verify a credential password against its stored hash."""
        try:
            # Decode the stored hash
            data = b64decode(stored_hash.encode('utf-8'))
            salt = data[:16]
            stored_key = data[16:]
            
            # Hash the provided password with the same salt
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

            # Constant-time comparison to prevent timing attacks
            return hmac.compare_digest(key, stored_key)
        except Exception:
            return False

    def _derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        """Derive a symmetric key from the credential password."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            200000,
            dklen=32
        )

    def _encrypt_value(self, value: str, credential_password: str) -> str:
        """
        Encrypt a credential value with AES-GCM using a key derived from the
        credential-specific password. Stored format: ENC1:<b64(salt|nonce|ciphertext)>
        """
        salt = secrets.token_bytes(16)
        key = self._derive_encryption_key(credential_password, salt)
        nonce = secrets.token_bytes(12)  # AES-GCM standard nonce size
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, value.encode('utf-8'), None)
        payload = b64encode(salt + nonce + ciphertext).decode('utf-8')
        return f"ENC1:{payload}"

    def _decrypt_value(self, stored_value: str, credential_password: str) -> Optional[str]:
        """
        Decrypt a stored credential value that was encrypted with _encrypt_value.
        Returns None on failure; if value is not prefixed with ENC1:, returns it as-is.
        """
        if not stored_value.startswith("ENC1:"):
            self.logger.warning(f"Stored value does not have ENC1: prefix, returning as-is")
            return stored_value

        try:
            payload = b64decode(stored_value.split(":", 1)[1])
            salt = payload[:16]
            nonce = payload[16:28]
            ciphertext = payload[28:]
            key = self._derive_encryption_key(credential_password, salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            self.logger.info("Successfully decrypted credential value")
            return plaintext.decode('utf-8')
        except Exception as e:
            self.logger.error(f"Failed to decrypt value: {type(e).__name__}: {str(e)}")
            return None

    def add_credential(self, name: str, value: str, cred_type: str, credential_password: str) -> bool:
        """Add a new credential to the database with its own password."""
        try:
            if not self.kp:
                return False  # Database must be opened first with master password

            reason = invalid_name_reason(name)
            if reason:
                self.logger.warning(f"Rejected credential name: {reason}")
                return False

            # Get appropriate group
            group = self.kp.find_groups(name=cred_type.title(), first=True)
            if not group:
                group = self.kp.root_group

            # Hash the credential password before storing
            password_hash = self._hash_credential_password(credential_password)
            encrypted_value = self._encrypt_value(value, credential_password)
            
            # Create entry with credential-specific password (stored as hash)
            self.kp.add_entry(
                destination_group=group,
                title=name,
                username="",  # We don't use username in our simple model
                password=encrypted_value,
                url="",
                notes=f"Type: {cred_type}\nCreated: {datetime.datetime.now().isoformat()}\nCredential Password Hash: {password_hash}"
            )
            
            self.kp.save()
            self.logger.info("Added credential")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add credential: {str(e)}")
            return False

    def get_credential(
        self, name: str, credential_password: str, persist: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a credential using only its specific password.

        With persist=False the vault file is never written (no last-accessed update, no
        migration of legacy entries); the network server uses this so reads stay read-only.
        """
        try:
            if not self.kp:
                return None  # Database must be opened first with master password

            entry = self.kp.find_entries(title=name, first=True)
            if not entry:
                return None

            # Verify credential password
            notes = entry.notes or ""
            stored_hash = None
            for line in notes.splitlines():
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                key = parts[0].strip().lower()
                value = parts[1].strip()
                if key == "credential password hash":
                    stored_hash = value
                    break
            if not stored_hash:
                self.logger.warning("No credential password hash found for entry")
                return None
            if not self._verify_credential_password(credential_password, stored_hash):
                self.logger.warning("Invalid credential password provided")
                return None

            # Decrypt the stored value using the credential password
            decrypted_value = self._decrypt_value(entry.password, credential_password)
            if decrypted_value is None:
                self.logger.warning("Failed to decrypt credential value")
                return None

            notes_lines = notes.split('\n')
            if persist:
                # Migrate older plaintext entries to encrypted form
                if not entry.password.startswith("ENC1:"):
                    entry.password = self._encrypt_value(decrypted_value, credential_password)
                    self.logger.info("Migrated credential to encrypted storage")

                # Update last accessed time in notes
                new_notes = []
                access_time_added = False

                for line in notes_lines:
                    if line.startswith("Last Accessed:"):
                        new_notes.append(f"Last Accessed: {datetime.datetime.now().isoformat()}")
                        access_time_added = True
                    else:
                        new_notes.append(line)

                if not access_time_added:
                    new_notes.append(f"Last Accessed: {datetime.datetime.now().isoformat()}")

                entry.notes = '\n'.join(new_notes)
                self.kp.save()

            # Parse type from notes
            cred_type = "other"
            for line in notes_lines:
                if line.startswith("Type:"):
                    cred_type = line.split(":")[1].strip().lower()
                    break

            return {
                "name": entry.title,
                "value": decrypted_value,
                "type": cred_type
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get credential: {str(e)}")
            return None

    def edit_credential(self, old_name: str, new_name: str, new_value: str, 
                       new_type: str, credential_password: str) -> bool:
        """Edit an existing credential using its specific password."""
        try:
            if not self.kp:
                return False  # Database must be opened first with master password

            reason = invalid_name_reason(new_name)
            if reason:
                self.logger.warning(f"Rejected credential name: {reason}")
                return False

            entry = self.kp.find_entries(title=old_name, first=True)
            if not entry:
                return False

            # Verify credential password
            notes = entry.notes or ""
            stored_hash = None
            for line in notes.splitlines():
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                key = parts[0].strip().lower()
                value = parts[1].strip()
                if key == "credential password hash":
                    stored_hash = value
                    break

            if not stored_hash:
                self.logger.warning("No credential password hash found for entry")
                return False
            if not self._verify_credential_password(credential_password, stored_hash):
                self.logger.warning("Invalid credential password provided")
                return False

            # Update entry
            entry.title = new_name
            entry.password = self._encrypt_value(new_value, credential_password)
            
            # Update notes - ensure hash format is used
            notes_lines = notes.split('\n')
            new_notes = []
            type_updated = False
            hash_updated = False
            
            for line in notes_lines:
                if line.startswith("Type:"):
                    new_notes.append(f"Type: {new_type}")
                    type_updated = True
                elif line.startswith("Credential Password Hash:"):
                    new_notes.append(line)
                    hash_updated = True
                else:
                    new_notes.append(line)
                    
            if not type_updated:
                new_notes.append(f"Type: {new_type}")
            
            if not hash_updated and stored_hash:
                new_notes.append(f"Credential Password Hash: {stored_hash}")
            
            entry.notes = '\n'.join(new_notes)

            # Move to appropriate group
            new_group = self.kp.find_groups(name=new_type.title(), first=True)
            if new_group:
                entry.move(new_group)

            self.kp.save()
            self.logger.info("Updated credential")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to edit credential: {str(e)}")
            return False

    def delete_credential(self, name: str, credential_password: str) -> bool:
        """Delete a credential using its specific password."""
        try:
            if not self.kp:
                return False

            entry = self.kp.find_entries(title=name, first=True)
            if not entry:
                return False

            # Verify credential password
            notes = entry.notes or ""
            stored_hash = None
            for line in notes.splitlines():
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                key = parts[0].strip().lower()
                value = parts[1].strip()
                if key == "credential password hash":
                    stored_hash = value
                    break

            if not stored_hash:
                self.logger.warning("No credential password hash found for entry")
                return False
            if not self._verify_credential_password(credential_password, stored_hash):
                self.logger.warning("Invalid credential password provided")
                return False

            self.kp.delete_entry(entry)
            self.kp.save()
            self.logger.info("Deleted credential")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete credential: {str(e)}")
            return False


    def get_all_credentials(self) -> Dict[str, Dict[str, Any]]:
        """Get all credentials from the database (names and metadata only, no values)."""
        try:
            if not self.kp:
                return {}  # Database must be opened first with master password

            result = {}
            for entry in self.kp.entries:
                # Parse type and dates from notes
                notes = entry.notes or ""
                cred_type = "other"
                created_at = None
                last_accessed = None
                
                for line in notes.split('\n'):
                    if line.startswith("Type:"):
                        cred_type = line.split(":")[1].strip().lower()
                    elif line.startswith("Created:"):
                        created_at = line.split(":", 1)[1].strip()
                    elif line.startswith("Last Accessed:"):
                        last_accessed = line.split(":", 1)[1].strip()

                result[entry.title] = {
                    "type": cred_type,
                    "created_at": created_at or entry.ctime.isoformat(),
                    "last_accessed": last_accessed
                }

            return result
            
        except Exception as e:
            self.logger.error(f"Failed to get all credentials: {str(e)}")
            return {} 
