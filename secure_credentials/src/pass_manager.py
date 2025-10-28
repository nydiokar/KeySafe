import datetime
import json
import os
import re
from pathlib import Path
from typing import Any

try:
    from . import hash_utility as pwl
except ImportError:
    import hash_utility as pwl  # type: ignore[no-redef]

# Windows-specific imports
WINDOWS_SECURITY_AVAILABLE = False
try:
    import win32con  # type: ignore
    import win32security  # type: ignore

    WINDOWS_SECURITY_AVAILABLE = True
except ImportError:
    # Create dummy objects to satisfy type checking
    class Win32SecurityDummy:
        ACL_REVISION: int = 1
        DACL_SECURITY_INFORMATION: int = 4

        def ACL(self) -> Any:
            raise NotImplementedError("Windows security not available on this platform")

        def LookupAccountName(self, domain: str, username: str) -> tuple[Any, Any, Any]:
            raise NotImplementedError("Windows security not available on this platform")

        def GetFileSecurity(self, path: str, info_type: int) -> Any:
            raise NotImplementedError("Windows security not available on this platform")

        def SetFileSecurity(self, path: str, info_type: int, security: Any) -> None:
            raise NotImplementedError("Windows security not available on this platform")

    class Win32ConDummy:
        GENERIC_READ: int = 0x80000000
        GENERIC_WRITE: int = 0x40000000
        GENERIC_EXECUTE: int = 0x20000000
        GENERIC_ALL: int = 0x10000000

    win32security = Win32SecurityDummy()  # type: ignore
    win32con = Win32ConDummy()  # type: ignore


class CredentialType:
    PASSWORD = "password"
    API_KEY = "api_key"
    OTHER = "other"


class Credential:
    def __init__(
        self,
        name: str,
        value: str,
        cred_type: CredentialType,
        created_at: datetime.datetime,
    ):
        self.name = name
        self.value = value
        self.type = cred_type
        self.created_at = created_at
        self.is_visible = False
        self.last_accessed = None


class CredentialManager:
    def __init__(self, message_callback=None):
        self.credential_file_path = self.get_credential_file_path()
        self.wizardy_file_path = Path.home() / "Desktop" / "wizardy.log"
        self.backup_file_path = self.credential_file_path.with_suffix(".backup.json")
        self.message_callback = message_callback or (
            lambda x: None
        )  # Default no-op callback

        # Ensure files exist and are properly secured
        self._ensure_secure_files()

    def _ensure_secure_files(self):
        """Ensure files exist and have proper permissions."""
        # Create files if they don't exist
        self.credential_file_path.touch(exist_ok=True)
        self.wizardy_file_path.touch(exist_ok=True)
        self.backup_file_path.touch(exist_ok=True)

        # Set secure permissions on Windows
        if WINDOWS_SECURITY_AVAILABLE:
            # Get the current user's SID
            username = os.getenv("USERNAME")
            domain = os.getenv("USERDOMAIN")
            sid = win32security.LookupAccountName(domain, username)[0]

            # Create a new DACL (Discretionary Access Control List)
            dacl = win32security.ACL()

            # Add ACE (Access Control Entry) for the current user only
            # Combine read, write, and execute permissions
            all_access = (
                win32con.GENERIC_READ
                | win32con.GENERIC_WRITE
                | win32con.GENERIC_EXECUTE
            )

            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, all_access, sid)

            # Get security descriptor
            security_descriptor = win32security.GetFileSecurity(
                str(self.credential_file_path), win32security.DACL_SECURITY_INFORMATION
            )

            # Set the new DACL
            security_descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                str(self.credential_file_path),
                win32security.DACL_SECURITY_INFORMATION,
                security_descriptor,
            )

            # Also secure the backup file
            win32security.SetFileSecurity(
                str(self.backup_file_path),
                win32security.DACL_SECURITY_INFORMATION,
                security_descriptor,
            )

        else:
            self.message_callback(
                "Warning: pywin32 not installed. File permissions not secured."
            )
            # Set basic file permissions
            try:
                # Make files readable/writable only by owner
                os.chmod(self.credential_file_path, 0o600)
                os.chmod(self.backup_file_path, 0o600)
            except Exception as e:
                self.message_callback(
                    f"Warning: Could not set file permissions: {str(e)}"
                )

    def get_test_credential_file_path(self):
        """Returns the path to the test credential file."""
        # Create a test directory for development
        test_dir = Path.home() / "creds_test"
        test_dir.mkdir(exist_ok=True)
        return test_dir / "test_wizardy.json"

    @staticmethod
    def datetime_current_UTC():
        """Returns the current datetime in UTC."""
        now = datetime.datetime.now()
        utc_time = now.astimezone(datetime.timezone.utc)
        return utc_time

    @staticmethod
    def get_home_directory():
        """Returns the home directory of the current user."""
        return Path.home()

    def get_credentials_directory(self):
        """Returns the path to the directory, creating it if it does not exist."""
        home_dir = self.get_home_directory()
        creds_dir = home_dir / "creds"
        creds_dir.mkdir(exist_ok=True)
        return creds_dir

    def get_credential_file_path(self):
        """Returns the path to the credential file, creating it if it does not exist."""
        creds_dir = self.get_credentials_directory()
        cred_file_path = creds_dir / "wizardy.json"

        if not cred_file_path.exists():
            cred_file_path.touch()
            print(f"CREATED MANY AS ONE CREDENTIALS FILE AT {cred_file_path}")

        return cred_file_path

    def get_datadump_directory_path(self):
        """Returns the path to the datadump directory, creating it if it does not exist."""
        home_dir = self.get_home_directory()
        datadump_dir = home_dir / "datadump"
        data_dir = datadump_dir / "data"

        datadump_dir.mkdir(exist_ok=True)
        data_dir.mkdir(exist_ok=True)

        print(f"CREATED DATADUMP DIRECTORY AT {datadump_dir}")
        print(f"CREATED DATA DIRECTORY AT {data_dir}")

        return datadump_dir

    @staticmethod
    def convert_credential_string_to_map(stringx):
        """Converts a credential string to a map."""

        def convert_string_to_bytes(string):
            if string.startswith("b'"):
                return bytes(string[2:-1], "utf-8")
            else:
                return string

        variables = re.findall(r"variable___\w+", stringx)
        map_constructor = {}

        for variable_to_work in variables:
            raw_text = (
                stringx.split(variable_to_work)[1].split("variable___")[0].strip()
            )
            variable_name = variable_to_work.split("variable___")[1]
            map_constructor[variable_name] = convert_string_to_bytes(string=raw_text)

        return map_constructor

    def read_creds(self):
        """Read credentials from the JSON file."""
        try:
            with open(self.credential_file_path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
        except FileNotFoundError:
            return {}

    def write_creds(self, creds_data):
        """Write credentials to the JSON file."""
        # Create a temporary file first
        temp_path = self.credential_file_path.with_suffix(".tmp")
        try:
            with open(temp_path, "w") as f:
                json.dump(creds_data, f, indent=4)

            # Secure the temporary file
            try:
                os.chmod(temp_path, 0o600)
            except Exception:
                pass

            # Safely replace the original file
            os.replace(temp_path, self.credential_file_path)

        except Exception as e:
            # Clean up temp file if it exists
            if temp_path.exists():
                temp_path.unlink()
            raise e

    def output_cred_map(self):
        """Get all credentials with their metadata."""
        return self.read_creds()

    def write_cred_map_to_file(self, cred_map):
        """Write the updated credential map back to the file."""
        try:
            self.write_creds(cred_map)
            print("Credential file updated successfully!")
        except Exception as e:
            print(f"Error writing credentials to file: {e}")

    def backup_credential_file(self):
        """Create a backup of the credential file."""
        backup_path = str(self.credential_file_path) + ".backup"
        try:
            with open(self.credential_file_path, "r") as original, open(
                backup_path, "w"
            ) as backup:
                backup.write(original.read())
            print(f"Backup created at {backup_path}")
        except Exception as e:
            print(f"Failed to create a backup: {e}")

    def initialize_store(self, master_password):
        """Initialize or load the credential store with master password."""
        try:
            # Check if store exists and has content
            if (
                not os.path.exists(self.credential_file_path)
                or os.path.getsize(self.credential_file_path) == 0
            ):
                self.message_callback(
                    "First time setup - creating new credential store..."
                )
                # Create a test credential to verify the master password works
                test_data = {
                    "_master_verify": {
                        "value": pwl.password_encrypt(
                            b"verification", master_password
                        ).decode("utf-8"),
                        "type": "system",
                        "created_at": self.datetime_current_UTC().isoformat(),
                        "last_accessed": None,
                    }
                }
                self.write_creds(test_data)
                self.message_callback("Credential store initialized successfully.")
                return True
            else:
                # Verify master password against existing store
                existing_creds = self.read_creds()
                if not existing_creds:
                    # If file exists but is empty or invalid, reinitialize
                    self.message_callback(
                        "Credential store is empty, reinitializing..."
                    )
                    test_data = {
                        "_master_verify": {
                            "value": pwl.password_encrypt(
                                b"verification", master_password
                            ).decode("utf-8"),
                            "type": "system",
                            "created_at": self.datetime_current_UTC().isoformat(),
                            "last_accessed": None,
                        }
                    }
                    self.write_creds(test_data)
                    self.message_callback(
                        "Credential store reinitialized successfully."
                    )
                    return True

                if "_master_verify" not in existing_creds:
                    # If verification token is missing, reinitialize
                    self.message_callback(
                        "Verification token missing, reinitializing..."
                    )
                    test_data = {
                        "_master_verify": {
                            "value": pwl.password_encrypt(
                                b"verification", master_password
                            ).decode("utf-8"),
                            "type": "system",
                            "created_at": self.datetime_current_UTC().isoformat(),
                            "last_accessed": None,
                        }
                    }
                    # Preserve existing credentials
                    existing_creds["_master_verify"] = test_data["_master_verify"]
                    self.write_creds(existing_creds)
                    self.message_callback(
                        "Credential store reinitialized while preserving existing credentials."
                    )
                    return True

                try:
                    # Try to decrypt the verification token
                    encrypted_verify = existing_creds["_master_verify"]["value"]
                    decrypted = pwl.password_decrypt(encrypted_verify, master_password)
                    if decrypted.decode("utf-8") != "verification":
                        raise ValueError("Invalid master password")
                    return True
                except Exception as e:
                    self.message_callback(f"Password verification failed: {str(e)}")
                    raise ValueError("Invalid master password")

        except Exception as e:
            self.message_callback(f"Store initialization failed: {str(e)}")
            return False

    def enter_and_encrypt_credential(self, name, value, cred_type, password):
        """Add a new credential with type."""
        self.backup_credential_file()  # Create a backup before modifying

        # Validate the credential reference format
        if not re.match(r"^[a-zA-Z0-9_]+$", name):
            raise ValueError(
                "Invalid format. Use only letters, numbers, and underscores."
            )

        existing_creds = self.read_creds()

        if name in existing_creds:
            raise ValueError("Credential already exists")

        encrypted_value = pwl.password_encrypt(
            message=bytes(value, "utf-8"), password=password
        )

        # Create credential entry with metadata
        credential_data = {
            "value": encrypted_value.decode("utf-8"),
            "type": cred_type,
            "created_at": self.datetime_current_UTC().isoformat(),
            "last_accessed": None,
        }

        existing_creds[name] = credential_data
        self.write_creds(existing_creds)

        # Log the addition
        timestamp = self.datetime_current_UTC().strftime("%Y-%m-%d %H:%M:%S UTC")
        with open(self.wizardy_file_path, "a") as f:
            f.write(f"\n=== {timestamp} ===\n")
            f.write(f"Credential: {name}\n")
            f.write(f"Type: {cred_type}\n")
            f.write(f"Encrypted: {encrypted_value.decode('utf-8')}\n")
            f.write("=" * 50 + "\n")

        print(
            f"Added credential {name} to credential file and {self.wizardy_file_path}"
        )

    def decrypt_credential(self, credential_ref, pw_decryptor):
        """Decrypts a credential and updates last accessed time."""
        existing_creds = self.read_creds()

        if credential_ref in existing_creds:
            encrypted_cred = existing_creds[credential_ref]["value"]
            try:
                decrypted_cred = pwl.password_decrypt(
                    token=encrypted_cred, password=pw_decryptor
                )

                # Update last accessed time
                existing_creds[credential_ref][
                    "last_accessed"
                ] = self.datetime_current_UTC().isoformat()
                self.write_creds(existing_creds)

                return decrypted_cred.decode("utf-8")
            except Exception:
                print("Incorrect password. Please try again.")
                return None
        else:
            print("Credential not found")
            return None

    def edit_credential(
        self, old_name: str, new_name: str, new_value: str, new_type: str, password: str
    ):
        """Edit an existing credential.

        Args:
            old_name (str): The current name of the credential
            new_name (str): The new name for the credential
            new_value (str): The new value to encrypt
            new_type (str): The new type of the credential
            password (str): The existing password used for encryption
        """
        self.backup_credential_file()  # Create a backup before modifying

        # Validate the new credential reference format
        if not re.match(r"^[a-zA-Z0-9_]+$", new_name):
            raise ValueError(
                "Invalid format. Use only letters, numbers, and underscores."
            )

        existing_creds = self.read_creds()

        # Check if the credential exists
        if old_name not in existing_creds:
            raise ValueError("Credential does not exist")

        # If renaming, check if new name already exists
        if old_name != new_name and new_name in existing_creds:
            raise ValueError("New credential name already exists")

        # Encrypt the new value with the provided password
        encrypted_value = pwl.password_encrypt(
            message=bytes(new_value, "utf-8"), password=password
        )

        # Update or create the credential entry
        credential_data = {
            "value": encrypted_value.decode("utf-8"),
            "type": new_type,
            "created_at": existing_creds[old_name][
                "created_at"
            ],  # Preserve creation date
            "last_accessed": self.datetime_current_UTC().isoformat(),
        }

        # Remove old entry if name changed
        if old_name != new_name:
            del existing_creds[old_name]

        existing_creds[new_name] = credential_data
        self.write_creds(existing_creds)

        # Log the modification
        timestamp = self.datetime_current_UTC().strftime("%Y-%m-%d %H:%M:%S UTC")
        with open(self.wizardy_file_path, "a") as f:
            f.write(f"\n=== {timestamp} ===\n")
            f.write(f"Modified credential: {old_name} -> {new_name}\n")
            f.write(f"Type: {new_type}\n")
            f.write(f"Encrypted: {encrypted_value.decode('utf-8')}\n")
            f.write("=" * 50 + "\n")

    def delete_credential(self, name):
        """Delete a credential."""
        try:
            self.backup_credential_file()
            existing_creds = self.read_creds()

            if name not in existing_creds:
                raise ValueError("Credential not found")

            del existing_creds[name]
            self.write_creds(existing_creds)

            # Log the deletion
            timestamp = self.datetime_current_UTC().strftime("%Y-%m-%d %H:%M:%S UTC")
            with open(self.wizardy_file_path, "a") as f:
                f.write(f"\n=== {timestamp} - DELETED ===\n")
                f.write(f"Credential: {name}\n")
                f.write("=" * 50 + "\n")

            print("Credential deleted successfully!")

        except Exception as e:
            print(f"Error deleting credential: {e}")
            raise

    def backup_credentials(self):
        """Create a backup of all credentials."""
        self.backup_credential_file()


def main():
    from .ui import CredentialManagerGUI

    gui = CredentialManagerGUI()
    gui.run()


if __name__ == "__main__":
    main()
