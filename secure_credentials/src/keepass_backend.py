from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
import os
from pathlib import Path
import logging
import datetime
from typing import Optional, Dict, Any
from pykeepass.kdbx_parsing import KDBX
from pykeepass import create_database

class KeePassHandler:
    def __init__(self):
        self.db_path = Path(os.path.expanduser("~")) / ".secure_credentials" / "vault.kdbx"
        self.kp = None
        self.setup_logging()

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
                # Create a new empty database file
                self.kp = create_database(str(self.db_path), password=password)
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

    def add_credential(self, name: str, value: str, cred_type: str, credential_password: str) -> bool:
        """Add a new credential to the database with its own password."""
        try:
            if not self.kp:
                return False  # Database must be opened first with master password

            # Get appropriate group
            group = self.kp.find_groups(name=cred_type.title(), first=True)
            if not group:
                group = self.kp.root_group

            # Create entry with credential-specific password
            self.kp.add_entry(
                destination_group=group,
                title=name,
                username="",  # We don't use username in our simple model
                password=value,
                url="",
                notes=f"Type: {cred_type}\nCreated: {datetime.datetime.now().isoformat()}\nCredential Password: {credential_password}"
            )
            
            self.kp.save()
            self.logger.info(f"Added credential: {name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add credential: {str(e)}")
            return False

    def get_credential(self, name: str, credential_password: str) -> Optional[Dict[str, Any]]:
        """Retrieve a credential using only its specific password."""
        try:
            if not self.kp:
                return None  # Database must be opened first with master password

            entry = self.kp.find_entries(title=name, first=True)
            if not entry:
                return None

            # Verify credential password
            notes = entry.notes or ""
            stored_password = None
            for line in notes.split('\n'):
                if line.startswith("Credential Password:"):
                    stored_password = line.split(":", 1)[1].strip()
                    break

            if not stored_password or stored_password != credential_password:
                self.logger.warning("Invalid credential password provided")
                return None

            # Update last accessed time in notes
            notes_lines = notes.split('\n')
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
                "value": entry.password,
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

            entry = self.kp.find_entries(title=old_name, first=True)
            if not entry:
                return False

            # Verify credential password
            notes = entry.notes or ""
            stored_password = None
            for line in notes.split('\n'):
                if line.startswith("Credential Password:"):
                    stored_password = line.split(":", 1)[1].strip()
                    break

            if not stored_password or stored_password != credential_password:
                self.logger.warning("Invalid credential password provided")
                return False

            # Update entry
            entry.title = new_name
            entry.password = new_value
            
            # Update notes
            notes_lines = notes.split('\n')
            new_notes = []
            type_updated = False
            
            for line in notes_lines:
                if line.startswith("Type:"):
                    new_notes.append(f"Type: {new_type}")
                    type_updated = True
                else:
                    new_notes.append(line)
                    
            if not type_updated:
                new_notes.append(f"Type: {new_type}")
            
            entry.notes = '\n'.join(new_notes)

            # Move to appropriate group
            new_group = self.kp.find_groups(name=new_type.title(), first=True)
            if new_group:
                entry.move(new_group)

            self.kp.save()
            self.logger.info(f"Updated credential: {new_name}")
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
            stored_password = None
            for line in notes.split('\n'):
                if line.startswith("Credential Password:"):
                    stored_password = line.split(":", 1)[1].strip()
                    break

            if not stored_password or stored_password != credential_password:
                self.logger.warning("Invalid credential password provided")
                return False

            self.kp.delete_entry(entry)
            self.kp.save()
            self.logger.info(f"Deleted credential: {name}")
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