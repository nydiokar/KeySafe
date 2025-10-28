import datetime
import json
import logging
import os
from tkinter import messagebox

import pkg_resources
import pyperclip
import ttkbootstrap as ttk
from packaging import version
from ttkbootstrap.constants import *

try:
    from ..keepass_backend import KeePassHandler
    from ..pass_manager import CredentialType
except ImportError:
    from secure_credentials.src.keepass_backend import KeePassHandler
    from secure_credentials.src.pass_manager import CredentialType


class CredentialManagerGUI:
    def __init__(self, security_manager=None):
        # Initialize icon to None first
        self.icon = None

        # Store security manager
        self.security_manager = security_manager
        if not self.security_manager:
            raise ValueError("SecurityManager is required")

        # Setup logging first for better diagnostics
        self.setup_logging()
        self.logger.info("Initializing CredentialManagerGUI")

        # Initialize KeePass handler
        self.keepass = KeePassHandler()

        # Initialize root window
        self.root = ttk.Window(themename="darkly")
        self.root.title("Secure Credential Manager")
        self.root.geometry("1000x700")

        # Position in the center of the screen
        self.center_window(self.root)

        # Create status bar early for user feedback
        self.status_bar = ttk.Label(
            self.root,
            text="Initializing secure credential manager...",
            relief=SUNKEN,
            style="info.TLabel",
        )
        self.status_bar.pack(fill=X, side=BOTTOM)

        # Update root to process the status bar
        self.root.update()

        # Load window state before showing window
        self.load_window_state()

        # Configure style
        self.style = ttk.Style()
        self.style.configure("Treeview", rowheight=30)

        # Auto-lock variables
        self.last_activity = datetime.datetime.now()
        self.auto_lock_timeout = 300  # 5 minutes
        self.is_locked = False

        # Setup UI components with status updates
        self.update_status("Setting up user interface...")
        self.setup_ui()
        self.setup_shortcuts()
        self.setup_auto_lock()

        # Update status for master password prompt
        self.update_status("Waiting for master password...")
        self.master_password = self.get_master_password()

        if not self.master_password:
            self.logger.info("No master password provided - shutting down")
            self.update_status("Shutting down - no master password provided")
            if self.icon:
                try:
                    self.icon.stop()
                except:
                    pass
            self.root.quit()
            return

        # Update status for database operations
        self.update_status("Verifying master password...")
        if not self.security_manager.verify_master_password(self.master_password):
            self.logger.error("Invalid master password")
            self.update_status("Error: Invalid master password")
            messagebox.showerror("Error", "Invalid master password")
            self.root.quit()
            return

        # Load credentials after password is verified
        self.update_status("Loading credentials...")
        self.load_credentials()

        # Setup system tray
        self.update_status("Setting up system tray...")
        try:
            self.setup_system_tray()
        except Exception as e:
            self.logger.error(f"Failed to setup system tray: {str(e)}")
            # Continue without system tray functionality

        # Show the window and ensure it's visible
        self.update_status("Ready")
        self.show_main_window()

        # Check for updates if enabled
        if hasattr(self, "auto_update_var") and self.auto_update_var.get():
            self.check_for_updates()

    def center_window(self, window):
        """Center a window on the screen"""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f"+{x}+{y}")

    def check_visibility(self):
        """Check if the window needs to be made visible again"""
        if (
            self.visibility_needed
            and hasattr(self, "root")
            and self.root.winfo_exists()
        ):
            self.logger.debug("Forcing window visibility")
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()

            # Set topmost attribute temporarily to try to force focus
            self.root.attributes("-topmost", True)
            self.root.update()
            self.root.attributes("-topmost", False)

            # Only force visibility for the first 5 seconds
            self.root.after(5000, self.stop_forcing_visibility)

        # Re-schedule this check if needed
        if (
            self.visibility_needed
            and hasattr(self, "root")
            and self.root.winfo_exists()
        ):
            self.root.after(500, self.check_visibility)

    def stop_forcing_visibility(self):
        """Stop forcing the visibility after initial launch period"""
        self.logger.debug("Stopping forced visibility")
        self.visibility_needed = False

    def show_main_window(self):
        """Explicitly show the main window - used for direct access from launcher or system tray"""
        self.logger.info("Explicitly showing main window")
        if hasattr(self, "root") and self.root.winfo_exists():
            # Use multiple techniques to ensure visibility
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
            self.root.update()

            # Log window state
            self.logger.debug(
                f"Window state after show_main_window: exists={self.root.winfo_exists()}, "
                f"visible={self.root.winfo_ismapped()}, "
                f"geometry={self.root.geometry()}"
            )

    def setup_logging(self):
        """Setup logging for the application."""
        log_dir = os.path.join(os.path.expanduser("~"), ".secure_credentials", "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "credential_manager.log")

        logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG,  # Change to DEBUG for more verbose logging
            format="%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Application started")

    def setup_system_tray(self):
        """Setup system tray icon and menu."""
        try:
            import PIL.Image
            import PIL.ImageDraw
            from pystray import Icon, Menu, MenuItem

            # Create a simple icon
            image = PIL.Image.new("RGB", (64, 64), color="blue")
            draw = PIL.ImageDraw.Draw(image)
            draw.ellipse([4, 4, 60, 60], fill="white")

            # Create menu
            menu = Menu(
                MenuItem("Show", self.show_main_window),
                MenuItem("Lock", self.lock),
                MenuItem("Exit", self.quit_app),
            )

            self.icon = Icon(
                "SecureCredManager", image, "Secure Credential Manager", menu
            )
            # Start the system tray in a different thread without waiting
            self.icon.run_detached()
        except ImportError:
            print(
                "System tray support not available. Install pystray package for system tray functionality."
            )

    def lock(self):
        """Lock the application."""
        self.is_locked = True
        self.root.withdraw()  # Hide main window

        # Create lock window
        self.lock_window = ttk.Toplevel(self.root)
        self.lock_window.title("Secure Credential Manager - Locked")
        self.lock_window.geometry("300x150")
        self.lock_window.transient(self.root)
        self.lock_window.grab_set()

        # Center the lock window
        self.lock_window.update_idletasks()
        width = self.lock_window.winfo_width()
        height = self.lock_window.winfo_height()
        x = (self.lock_window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.lock_window.winfo_screenheight() // 2) - (height // 2)
        self.lock_window.geometry(f"+{x}+{y}")

        # Add lock message
        ttk.Label(
            self.lock_window, text="Application Locked", font=("Helvetica", 12, "bold")
        ).pack(pady=10)
        ttk.Label(self.lock_window, text="Enter master password to unlock").pack(pady=5)

        # Password entry
        self.lock_password_var = ttk.StringVar()
        password_entry = ttk.Entry(
            self.lock_window, textvariable=self.lock_password_var, show="*"
        )
        password_entry.pack(fill=X, padx=20, pady=5)

        # Unlock button
        ttk.Button(
            self.lock_window,
            text="Unlock",
            command=self.unlock_with_password,
            style="primary.TButton",
        ).pack(pady=10)

        # Bind unlock event
        self.lock_window.bind("<Return>", lambda e: self.unlock_with_password())
        self.lock_window.bind("<Escape>", lambda e: self.lock_window.destroy())

        password_entry.focus_set()

    def unlock_with_password(self):
        """Unlock the application with password verification."""
        entered_password = self.lock_password_var.get()
        if entered_password == self.master_password:
            self.unlock()
        else:
            messagebox.showerror("Error", "Incorrect master password")

    def unlock(self, event=None):
        """Unlock the application."""
        if self.is_locked:
            self.is_locked = False
            self.lock_window.destroy()
            self.root.deiconify()  # Show main window
            self.update_activity()

    def load_window_state(self):
        """Load window position and size from config file."""
        config_path = os.path.join(
            os.path.expanduser("~"), ".secure_credentials", "gui_config.json"
        )
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
                self.root.geometry(
                    f"{config.get('width', 1000)}x{config.get('height', 700)}"
                )
                self.root.geometry(f"+{config.get('x', 100)}+{config.get('y', 100)}")
        except (FileNotFoundError, json.JSONDecodeError):
            self.root.geometry("1000x700")

    def save_window_state(self):
        """Save window position and size to config file."""
        try:
            config_path = os.path.join(
                os.path.expanduser("~"), ".secure_credentials", "gui_config.json"
            )
            os.makedirs(os.path.dirname(config_path), exist_ok=True)

            # Get window geometry
            geometry = self.root.geometry()
            # Parse geometry string (format: "WxH+X+Y")
            parts = geometry.split("+")
            size = parts[0].split("x")
            width = int(size[0])
            height = int(size[1])
            x = int(parts[1])
            y = int(parts[2])

            config = {"width": width, "height": height, "x": x, "y": y}

            with open(config_path, "w") as f:
                json.dump(config, f)
        except Exception as e:
            print(f"Failed to save window state: {str(e)}")
            # Don't prevent application from closing if saving state fails

    def setup_auto_lock(self):
        """Setup auto-lock functionality."""
        self.root.bind("<Key>", self.update_activity)
        self.root.bind("<Button-1>", self.update_activity)
        self.root.bind("<Button-2>", self.update_activity)
        self.root.bind("<Button-3>", self.update_activity)
        self.root.bind("<Motion>", self.update_activity)

        # Check for auto-lock every minute
        self.root.after(60000, self.check_auto_lock)

    def update_activity(self, event=None):
        """Update last activity timestamp."""
        self.last_activity = datetime.datetime.now()
        if self.is_locked:
            self.unlock()

    def check_auto_lock(self):
        """Check if we should auto-lock the application."""
        if not self.is_locked:
            idle_time = (datetime.datetime.now() - self.last_activity).total_seconds()
            if idle_time > self.auto_lock_timeout:
                self.lock()
        self.root.after(60000, self.check_auto_lock)

    def on_closing(self):
        """Handle application closing."""
        try:
            self.save_window_state()
            self.logger.info("Application closing normally")
            if self.icon:
                self.icon.stop()
            self.root.quit()
        except Exception as e:
            self.logger.error(f"Error during application shutdown: {str(e)}")

    def setup_shortcuts(self):
        self.root.bind("<Control-n>", lambda e: self.add_credential())
        self.root.bind("<Control-e>", lambda e: self.edit_credential())
        self.root.bind("<Delete>", lambda e: self.delete_credential())
        self.root.bind("<Control-c>", lambda e: self.copy_to_clipboard())
        self.root.bind("<Control-f>", lambda e: self.search_entry.focus())

    def setup_ui(self):
        # Create main container
        self.main_container = ttk.Frame(self.root, padding="10")
        self.main_container.pack(fill=BOTH, expand=YES)

        # Create menu bar
        self.create_menu_bar()

        # Create toolbar
        self.create_toolbar()

        # Create main content area
        self.create_content_area()

        # Create status bar
        self.create_status_bar()

    def create_menu_bar(self):
        """Create the main menu bar with essential functionality."""
        menubar = ttk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu - essential operations only
        file_menu = ttk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(
            label="New Credential", command=self.add_credential, accelerator="Ctrl+N"
        )
        file_menu.add_separator()
        file_menu.add_command(label="Backup Database...", command=self.create_backup)
        file_menu.add_command(label="Restore Database...", command=self.restore_backup)
        file_menu.add_separator()
        file_menu.add_command(label="Lock", command=self.lock, accelerator="Ctrl+L")
        file_menu.add_command(label="Exit", command=self.quit_app)

        # Settings menu - all configuration options
        settings_menu = ttk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        # Security settings
        security_menu = ttk.Menu(settings_menu, tearoff=0)
        settings_menu.add_cascade(label="Security", menu=security_menu)

        # Auto-lock timeout
        self.auto_lock_var = ttk.StringVar(
            value=str(self.load_setting("auto_lock_timeout", 300) // 60)
        )
        security_menu.add_command(
            label="Set Auto-Lock Timeout...", command=self.set_auto_lock_timeout
        )

        # Clear clipboard
        self.clear_clipboard_var = ttk.BooleanVar(
            value=self.load_setting("clear_clipboard", True)
        )
        security_menu.add_checkbutton(
            label="Auto-Clear Clipboard",
            variable=self.clear_clipboard_var,
            command=lambda: self.save_setting(
                "clear_clipboard", self.clear_clipboard_var.get()
            ),
        )

        # Theme selection
        settings_menu.add_separator()
        appearance_menu = ttk.Menu(settings_menu, tearoff=0)
        settings_menu.add_cascade(label="Theme", menu=appearance_menu)

        self.theme_var = ttk.StringVar(value=self.load_setting("theme", "darkly"))
        for theme in self.root.style.theme_names():
            appearance_menu.add_radiobutton(
                label=theme.capitalize(),
                value=theme,
                variable=self.theme_var,
                command=self.apply_theme,
            )

        # Updates settings
        self.auto_update_var = ttk.BooleanVar(
            value=self.load_setting("auto_update", True)
        )
        settings_menu.add_checkbutton(
            label="Check for Updates Automatically",
            variable=self.auto_update_var,
            command=lambda: self.save_setting(
                "auto_update", self.auto_update_var.get()
            ),
        )
        settings_menu.add_command(
            label="Check for Updates Now", command=self.manual_check_for_updates
        )

        # Backup operations
        settings_menu.add_separator()
        settings_menu.add_command(label="Create Backup...", command=self.create_backup)
        settings_menu.add_command(
            label="Restore from Backup...", command=self.restore_backup
        )

        # Reset settings
        settings_menu.add_separator()
        settings_menu.add_command(
            label="Reset All Settings", command=self.reset_settings
        )

        # Help menu - documentation and about
        help_menu = ttk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(
            label="Quick Start Guide",
            command=lambda: self.show_documentation("quick_start"),
        )
        help_menu.add_command(
            label="Security Guide", command=lambda: self.show_documentation("security")
        )
        help_menu.add_command(
            label="Keyboard Shortcuts",
            command=lambda: self.show_documentation("shortcuts"),
        )
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)

    def load_setting(self, key, default_value):
        """Load a setting from config file."""
        config_path = os.path.join(
            os.path.expanduser("~"), ".secure_credentials", "gui_config.json"
        )
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
                return config.get(key, default_value)
        except (FileNotFoundError, json.JSONDecodeError):
            return default_value

    def save_setting(self, key, value):
        """Save a setting to config file."""
        config_path = os.path.join(
            os.path.expanduser("~"), ".secure_credentials", "gui_config.json"
        )
        try:
            # Load existing config
            config = {}
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config = json.load(f)

            # Update the setting
            config[key] = value

            # Save back to file
            with open(config_path, "w") as f:
                json.dump(config, f)

            # Apply setting immediately if needed
            self.apply_setting(key, value)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save setting: {str(e)}")

    def apply_setting(self, key, value):
        """Apply a setting immediately after it's changed."""
        if key == "auto_lock_timeout":
            self.auto_lock_timeout = value
        elif key == "theme":
            self.root.style.theme_use(value)

    def set_auto_lock_timeout(self):
        """Show dialog to set auto-lock timeout."""
        dialog = ttk.Toplevel(self.root)
        dialog.title("Set Auto-Lock Timeout")
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()

        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=BOTH, expand=YES)

        ttk.Label(main_frame, text="Minutes before auto-lock:").pack(pady=(0, 10))

        timeout_var = ttk.StringVar(value=self.auto_lock_var.get())
        timeout_entry = ttk.Entry(main_frame, textvariable=timeout_var)
        timeout_entry.pack(fill=X, pady=(0, 10))

        def save_timeout():
            try:
                timeout = int(timeout_var.get())
                if timeout < 1:
                    raise ValueError("Timeout must be at least 1 minute")
                self.auto_lock_var.set(str(timeout))
                self.save_setting("auto_lock_timeout", timeout * 60)  # Save in seconds
                dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(
            main_frame, text="Save", command=save_timeout, style="primary.TButton"
        ).pack(side=RIGHT, padx=5)
        ttk.Button(
            main_frame, text="Cancel", command=dialog.destroy, style="secondary.TButton"
        ).pack(side=RIGHT, padx=5)

        dialog.bind("<Return>", lambda e: save_timeout())
        dialog.bind("<Escape>", lambda e: dialog.destroy())

    def apply_theme(self):
        """Apply selected theme."""
        theme = self.theme_var.get()
        self.save_setting("theme", theme)
        self.root.style.theme_use(theme)

    def create_backup(self):
        """Create a backup of the database."""
        from tkinter import filedialog

        backup_path = filedialog.asksaveasfilename(
            defaultextension=".kdbx",
            filetypes=[("KeePass Database", "*.kdbx")],
            title="Save Backup As",
        )
        if backup_path:
            try:
                import shutil

                shutil.copy2(self.keepass.db_path, backup_path)
                messagebox.showinfo("Success", "Backup created successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create backup: {str(e)}")

    def restore_backup(self):
        """Restore database from backup."""
        from tkinter import filedialog

        backup_path = filedialog.askopenfilename(
            filetypes=[("KeePass Database", "*.kdbx")], title="Select Backup File"
        )
        if backup_path:
            if messagebox.askyesno(
                "Warning",
                "This will replace your current database with the backup.\n"
                "Make sure you have the correct master password for the backup.\n"
                "Do you want to continue?",
            ):
                try:
                    import shutil

                    # First create a backup of current database
                    current_backup = str(self.keepass.db_path) + ".bak"
                    shutil.copy2(self.keepass.db_path, current_backup)

                    # Now restore the selected backup
                    shutil.copy2(backup_path, self.keepass.db_path)
                    messagebox.showinfo(
                        "Success",
                        "Backup restored successfully!\n"
                        "The application will now close. Please restart it.",
                    )
                    self.quit_app()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to restore backup: {str(e)}")

    def reset_settings(self):
        """Reset all settings to defaults."""
        if messagebox.askyesno(
            "Confirm Reset",
            "This will reset all settings to their default values.\n"
            "Do you want to continue?",
        ):
            try:
                config_path = os.path.join(
                    os.path.expanduser("~"), ".secure_credentials", "gui_config.json"
                )
                defaults = {
                    "auto_update": True,
                    "auto_lock_timeout": 300,  # 5 minutes
                    "clear_clipboard": True,
                    "theme": "darkly",
                    "width": 1000,
                    "height": 700,
                    "x": 100,
                    "y": 100,
                }
                with open(config_path, "w") as f:
                    json.dump(defaults, f)

                # Apply defaults
                self.auto_update_var.set(True)
                self.auto_lock_timeout = 300
                self.clear_clipboard_var.set(True)
                self.theme_var.set("darkly")
                self.root.style.theme_use("darkly")

                messagebox.showinfo("Success", "Settings have been reset to defaults.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to reset settings: {str(e)}")

    def create_toolbar(self):
        toolbar = ttk.Frame(self.main_container)
        toolbar.pack(fill=X, pady=(0, 10))

        # Search frame
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=LEFT, fill=X, expand=YES)

        ttk.Label(search_frame, text="Search:").pack(side=LEFT, padx=5)
        self.search_var = ttk.StringVar()
        self.search_var.trace("w", self.filter_credentials)
        self.search_entry = ttk.Entry(
            search_frame, textvariable=self.search_var, width=30
        )
        self.search_entry.pack(side=LEFT, padx=5)

        # Buttons
        ttk.Button(
            toolbar, text="New", command=self.add_credential, style="primary.TButton"
        ).pack(side=RIGHT, padx=5)
        ttk.Button(
            toolbar, text="View", command=self.view_credential, style="info.TButton"
        ).pack(side=RIGHT, padx=5)
        ttk.Button(
            toolbar, text="Edit", command=self.edit_credential, style="info.TButton"
        ).pack(side=RIGHT, padx=5)
        ttk.Button(
            toolbar,
            text="Delete",
            command=self.delete_credential,
            style="danger.TButton",
        ).pack(side=RIGHT, padx=5)
        ttk.Button(
            toolbar,
            text="Copy",
            command=self.copy_to_clipboard,
            style="success.TButton",
        ).pack(side=RIGHT, padx=5)

    def create_content_area(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=BOTH, expand=YES)

        # Create frames for each tab
        self.all_creds_frame = ttk.Frame(self.notebook)
        self.password_frame = ttk.Frame(self.notebook)
        self.apikey_frame = ttk.Frame(self.notebook)
        self.other_frame = ttk.Frame(self.notebook)

        # Add frames to notebook
        self.notebook.add(self.all_creds_frame, text="All Credentials")
        self.notebook.add(self.password_frame, text="Passwords")
        self.notebook.add(self.apikey_frame, text="API Keys")
        self.notebook.add(self.other_frame, text="Other")

        # Create treeviews for each tab
        self.create_treeview(self.all_creds_frame, "all")
        self.create_treeview(self.password_frame, "password")
        self.create_treeview(self.apikey_frame, "api_key")
        self.create_treeview(self.other_frame, "other")

    def create_treeview(self, parent, cred_type):
        """Create a treeview for credentials."""
        # Create frame to hold treeview
        frame = ttk.Frame(parent)
        frame.pack(fill=BOTH, expand=True)

        # Create and configure treeview
        tree = ttk.Treeview(frame, style="Custom.Treeview")
        tree.pack(side=LEFT, fill=BOTH, expand=True)

        # Configure treeview style
        style = ttk.Style()
        style.configure("Custom.Treeview", rowheight=25, borderwidth=1, relief="solid")
        style.configure(
            "Custom.Treeview.Heading",
            font=("TkDefaultFont", 10, "bold"),
            relief="raised",
            borderwidth=1,
        )

        # Enable column dragging
        tree.bind("<Button-1>", self.on_click)
        tree.bind("<B1-Motion>", self.on_drag)
        tree.bind("<ButtonRelease-1>", self.on_release)

        # Define columns with specific widths and stretch behavior
        tree["columns"] = ("type", "created", "last_accessed")

        # Name column (the #0 column)
        tree.column("#0", width=300, minwidth=200)
        tree.heading("#0", text="Name", anchor=W)

        # Type column - fixed width, no stretch
        tree.column("type", width=100, minwidth=80, stretch=False)
        tree.heading("type", text="Type", anchor=W)

        # Created and Last Accessed - fixed width initially, but can be resized
        tree.column("created", width=150, minwidth=120, stretch=False)
        tree.heading("created", text="Created", anchor=W)

        tree.column("last_accessed", width=150, minwidth=120, stretch=False)
        tree.heading("last_accessed", text="Last Accessed", anchor=W)

        # Add vertical scrollbar
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        vsb.pack(side=RIGHT, fill=Y)
        tree.configure(yscrollcommand=vsb.set)

        # Add horizontal scrollbar
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        hsb.pack(side=BOTTOM, fill=X)
        tree.configure(xscrollcommand=hsb.set)

        # Configure tags for different credential types with better visibility
        tree.tag_configure("password", foreground="#00FF00")  # Bright green
        tree.tag_configure("api_key", foreground="#00FFFF")  # Cyan
        tree.tag_configure("other", foreground="#FFFF00")  # Yellow

        # Store reference to the treeview
        if cred_type == "all":
            self.tree = tree  # Main treeview
        elif cred_type == "password":
            self.password_tree = tree
        elif cred_type == "api_key":
            self.apikey_tree = tree
        else:
            self.other_tree = tree

        # Bind events
        tree.bind("<<TreeviewSelect>>", self.on_select)
        tree.bind("<Double-1>", self.on_double_click)

        # Enable sorting
        for col in ("#0",) + tree["columns"]:
            tree.heading(col, command=lambda c=col: self.sort_treeview(tree, c, False))

        return tree

    def on_click(self, event):
        """Handle column click for drag operations."""
        tree = event.widget
        region = tree.identify_region(event.x, event.y)
        if region == "separator":
            self.drag_start_x = event.x
            self.drag_column = tree.identify_column(event.x)
            self.drag_width = tree.column(self.drag_column, "width")
            return "break"

    def on_drag(self, event):
        """Handle column drag operation."""
        if hasattr(self, "drag_start_x"):
            diff = event.x - self.drag_start_x
            new_width = max(self.drag_width + diff, 50)  # Minimum width of 50
            tree = event.widget
            tree.column(self.drag_column, width=new_width)
            return "break"

    def on_release(self, event):
        """Handle end of drag operation."""
        if hasattr(self, "drag_start_x"):
            del self.drag_start_x
            del self.drag_column
            del self.drag_width

    def sort_treeview(self, tree, col, reverse):
        """Sort treeview content when clicking on headers."""
        items = [
            (tree.set(k, col), k) if col != "#0" else (tree.item(k)["text"], k)
            for k in tree.get_children("")
        ]
        items.sort(reverse=reverse)

        # Rearrange items in sorted positions
        for index, (val, k) in enumerate(items):
            tree.move(k, "", index)

        # Reverse sort next time
        tree.heading(col, command=lambda: self.sort_treeview(tree, col, not reverse))

    def create_status_bar(self):
        self.status_bar = ttk.Label(self.main_container, text="Ready", relief=SUNKEN)
        self.status_bar.pack(fill=X, side=BOTTOM)

    def update_status(self, message):
        self.status_bar.config(text=message)

    def load_credentials(self):
        """Load credentials into the treeviews."""
        # First ensure database is open with master password
        if not self.keepass.kp:
            if not self.keepass.open_database(self.master_password):
                self.update_status("Failed to open database")
                return

        # Clear existing items
        self.tree.delete(*self.tree.get_children())
        self.password_tree.delete(*self.password_tree.get_children())
        self.apikey_tree.delete(*self.apikey_tree.get_children())
        self.other_tree.delete(*self.other_tree.get_children())

        # Get credentials
        creds = self.keepass.get_all_credentials()

        # Count for each type
        counts = {"password": 0, "api_key": 0, "other": 0}

        for name, data in creds.items():
            cred_type = data.get("type", "other")
            created = data.get("created_at", "Unknown")
            last_accessed = data.get("last_accessed", "Never")

            # Format dates
            created = self.format_date(created)
            last_accessed = (
                self.format_date(last_accessed) if last_accessed else "Never"
            )

            # Add to main treeview
            self.tree.insert(
                "",
                "end",
                text=name,
                values=(cred_type, created, last_accessed),
                tags=(cred_type,),
            )

            # Add to type-specific tree
            if cred_type == "password":
                self.password_tree.insert(
                    "",
                    "end",
                    text=name,
                    values=(cred_type, created, last_accessed),
                    tags=(cred_type,),
                )
                counts["password"] += 1
            elif cred_type == "api_key":
                self.apikey_tree.insert(
                    "",
                    "end",
                    text=name,
                    values=(cred_type, created, last_accessed),
                    tags=(cred_type,),
                )
                counts["api_key"] += 1
            else:
                self.other_tree.insert(
                    "",
                    "end",
                    text=name,
                    values=(cred_type, created, last_accessed),
                    tags=(cred_type,),
                )
                counts["other"] += 1

        # Update tab text with counts
        self.notebook.tab(0, text=f"All Credentials ({len(creds)})")
        self.notebook.tab(1, text=f'Passwords ({counts["password"]})')
        self.notebook.tab(2, text=f'API Keys ({counts["api_key"]})')
        self.notebook.tab(3, text=f'Other ({counts["other"]})')

        self.update_status(f"Loaded {len(creds)} credentials")

    def format_date(self, date_str):
        """Format date string for display."""
        if not date_str or date_str == "Never":
            return "Never"
        try:
            dt = datetime.datetime.fromisoformat(date_str)
            return dt.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            return date_str

    def filter_credentials(self, *args):
        """Filter credentials in all treeviews based on search text."""
        search_term = self.search_var.get().lower()

        # Get all credentials
        creds = self.keepass.get_all_credentials()

        # Clear all trees
        for tree in [self.tree, self.password_tree, self.apikey_tree, self.other_tree]:
            tree.delete(*tree.get_children())

        # Counts for filtered items
        counts = {"all": 0, "password": 0, "api_key": 0, "other": 0}

        # Repopulate with filtered items
        for name, data in creds.items():
            if search_term in name.lower():
                cred_type = data.get("type", "other")
                created = data.get("created_at", "Unknown")
                last_accessed = data.get("last_accessed", "Never")

                # Format dates
                created = self.format_date(created)
                last_accessed = (
                    self.format_date(last_accessed) if last_accessed else "Never"
                )

                # Add to main tree
                self.tree.insert(
                    "",
                    "end",
                    text=name,
                    values=(cred_type, created, last_accessed),
                    tags=(cred_type,),
                )
                counts["all"] += 1

                # Add to type-specific tree
                if cred_type == "password":
                    self.password_tree.insert(
                        "",
                        "end",
                        text=name,
                        values=(cred_type, created, last_accessed),
                        tags=(cred_type,),
                    )
                    counts["password"] += 1
                elif cred_type == "api_key":
                    self.apikey_tree.insert(
                        "",
                        "end",
                        text=name,
                        values=(cred_type, created, last_accessed),
                        tags=(cred_type,),
                    )
                    counts["api_key"] += 1
                else:
                    self.other_tree.insert(
                        "",
                        "end",
                        text=name,
                        values=(cred_type, created, last_accessed),
                        tags=(cred_type,),
                    )
                    counts["other"] += 1

        # Update tab text with filtered counts
        self.notebook.tab(0, text=f'All Credentials ({counts["all"]})')
        self.notebook.tab(1, text=f'Passwords ({counts["password"]})')
        self.notebook.tab(2, text=f'API Keys ({counts["api_key"]})')
        self.notebook.tab(3, text=f'Other ({counts["other"]})')

        if search_term:
            self.update_status(f"Found {counts['all']} matching credentials")
        else:
            self.update_status(f"Showing all {counts['all']} credentials")

    def calculate_password_strength(self, password):
        """Calculate password strength score (0-100)."""
        score = 0

        # Length
        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10

        # Character types
        if any(c.isupper() for c in password):
            score += 20
        if any(c.islower() for c in password):
            score += 20
        if any(c.isdigit() for c in password):
            score += 20
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 10

        return min(score, 100)

    def get_master_password(self):
        """Prompt for master password using GUI dialog."""
        dialog = ttk.Toplevel(self.root)
        dialog.title("Password Required")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f"+{x}+{y}")

        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=BOTH, expand=YES)

        # Check if this is first time setup
        is_new_store = not self.keepass.db_path.exists()
        self.logger.info(f"Is new store: {is_new_store}")

        if is_new_store:
            ttk.Label(
                main_frame,
                text="First Time Setup - Create Master Password",
                font=("Helvetica", 10, "bold"),
            ).pack(pady=(0, 10))
            ttk.Label(
                main_frame,
                text="This password will be used to encrypt your credential storage.\n"
                "Make sure to remember it as it cannot be recovered!",
                wraplength=350,
            ).pack(pady=(0, 10))
        else:
            ttk.Label(main_frame, text="Enter Master Password:").pack(pady=(0, 10))

        # Password entry
        password_var = ttk.StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=password_var, show="*")
        password_entry.pack(fill=X, pady=(0, 5))

        # Password strength indicator
        strength_frame = ttk.Frame(main_frame)
        strength_frame.pack(fill=X, pady=(0, 5))
        ttk.Label(strength_frame, text="Strength:").pack(side=LEFT)
        self.strength_var = ttk.StringVar(value="")
        self.strength_label = ttk.Label(strength_frame, textvariable=self.strength_var)
        self.strength_label.pack(side=LEFT, padx=(5, 0))

        # Progress bar for strength
        self.strength_bar = ttk.Progressbar(main_frame, length=200, mode="determinate")
        self.strength_bar.pack(fill=X, pady=(0, 10))

        # For new store, add password confirmation
        confirm_var = None
        if is_new_store:
            ttk.Label(main_frame, text="Confirm Password:").pack(pady=(0, 5))
            confirm_var = ttk.StringVar()
            confirm_entry = ttk.Entry(main_frame, textvariable=confirm_var, show="*")
            confirm_entry.pack(fill=X, pady=(0, 20))

        # Initialize result dictionary
        result = {"password": None}

        def update_strength(*args):
            """Update password strength indicator."""
            password = password_var.get()
            if not password:
                self.strength_var.set("")
                self.strength_bar["value"] = 0
                return

            score = self.calculate_password_strength(password)
            self.strength_bar["value"] = score

            if score < 40:
                self.strength_var.set("Weak")
                self.strength_bar["style"] = "danger.Horizontal.TProgressbar"
            elif score < 70:
                self.strength_var.set("Medium")
                self.strength_bar["style"] = "warning.Horizontal.TProgressbar"
            else:
                self.strength_var.set("Strong")
                self.strength_bar["style"] = "success.Horizontal.TProgressbar"

        def on_ok():
            self.logger.info("OK button clicked")
            password = password_var.get()
            if is_new_store:
                self.logger.info("Processing new store creation")
                if password != confirm_var.get():
                    self.logger.warning("Passwords do not match")
                    messagebox.showerror("Error", "Passwords do not match!")
                    return
                if len(password) < 8:
                    self.logger.warning("Password too short")
                    messagebox.showerror(
                        "Error", "Password must be at least 8 characters long!"
                    )
                    return
                if self.calculate_password_strength(password) < 40:
                    self.logger.warning("Weak password detected")
                    if not messagebox.askyesno(
                        "Warning",
                        "Your password is weak. Are you sure you want to use it?\n"
                        "A strong password should be at least 8 characters long and include:\n"
                        "- Uppercase and lowercase letters\n"
                        "- Numbers\n"
                        "- Special characters",
                    ):
                        return
                # Create new database
                self.logger.info("Creating new database...")
                if self.keepass.create_database(password):
                    self.logger.info("Database created successfully")
                    result["password"] = password
                    dialog.destroy()
                else:
                    self.logger.error("Failed to create database")
                    messagebox.showerror("Error", "Failed to create database!")
            else:
                # Verify existing password
                self.logger.info("Verifying existing password")
                if self.keepass.verify_password(password):
                    self.logger.info("Password verified successfully")
                    result["password"] = password
                    dialog.destroy()
                else:
                    self.logger.warning("Invalid password provided")
                    messagebox.showerror("Error", "Invalid master password!")
                    password_entry.delete(0, "end")
                    password_entry.focus()

        def on_cancel():
            self.logger.info("Cancel button clicked")
            dialog.destroy()

        ttk.Button(main_frame, text="OK", command=on_ok, style="primary.TButton").pack(
            side=RIGHT, padx=5
        )
        ttk.Button(
            main_frame, text="Cancel", command=on_cancel, style="secondary.TButton"
        ).pack(side=RIGHT, padx=5)

        # Bind events
        password_var.trace("w", update_strength)
        password_entry.focus_set()
        dialog.bind("<Return>", lambda e: on_ok())
        dialog.bind("<Escape>", lambda e: on_cancel())

        # Wait for dialog to close
        dialog.wait_window()

        # Return the password or None if cancelled
        return result.get("password")

    def add_credential(self):
        # First ensure database is open with master password
        if not self.keepass.kp:
            if not self.keepass.open_database(self.master_password):
                self.update_status("Failed to open database")
                return

        dialog = CredentialDialog(self.root)
        if dialog.result:
            name, value, cred_type, credential_password = dialog.result
            try:
                if self.keepass.add_credential(
                    name, value, cred_type, credential_password
                ):
                    self.load_credentials()
                    self.update_status(f"Added credential: {name}")
                else:
                    self.update_status("Failed to add credential")
            except Exception as e:
                self.update_status(f"Error: {str(e)}")

    def edit_credential(self):
        # First ensure database is open with master password
        if not self.keepass.kp:
            if not self.keepass.open_database(self.master_password):
                self.update_status("Failed to open database")
                return

        selected = self.tree.selection()
        if not selected:
            self.update_status("Please select a credential to edit")
            return

        item = selected[0]
        name = self.tree.item(item)["text"]

        # Ask for credential password
        password = self.prompt_for_password("Enter current credential password")
        if not password:
            self.update_status("Operation cancelled")
            return

        # Get current credential
        current = self.keepass.get_credential(name, password)
        if not current:
            self.update_status("Failed to retrieve credential - incorrect password")
            return

        dialog = CredentialDialog(self.root, name=name, current_value=current["value"])
        if dialog.result:
            new_name, new_value, new_type, new_password = dialog.result
            try:
                if self.keepass.edit_credential(
                    name, new_name, new_value, new_type, new_password
                ):
                    self.load_credentials()
                    self.update_status(f"Updated credential: {new_name}")
                else:
                    self.update_status("Failed to update credential")
            except Exception as e:
                self.update_status(f"Error: {str(e)}")

    def delete_credential(self):
        # First ensure database is open with master password
        if not self.keepass.kp:
            if not self.keepass.open_database(self.master_password):
                self.update_status("Failed to open database")
                return

        selected = self.tree.selection()
        if not selected:
            self.update_status("Please select a credential to delete")
            return

        item = selected[0]
        name = self.tree.item(item)["text"]

        # Ask for credential password
        password = self.prompt_for_password("Enter credential password to delete")
        if not password:
            self.update_status("Operation cancelled")
            return

        if messagebox.askyesno(
            "Confirm", "Are you sure you want to delete this credential?"
        ):
            try:
                if self.keepass.delete_credential(
                    name, password
                ):  # Use credential password instead of master password
                    self.load_credentials()
                    self.update_status(f"Deleted credential: {name}")
                else:
                    self.update_status(
                        "Failed to delete credential - incorrect password"
                    )
            except Exception as e:
                self.update_status(f"Error: {str(e)}")

    def copy_to_clipboard(self):
        # First ensure database is open with master password
        if not self.keepass.kp:
            if not self.keepass.open_database(self.master_password):
                self.update_status("Failed to open database")
                return

        selected = self.tree.selection()
        if not selected:
            self.update_status("Please select a credential to copy")
            return

        item = selected[0]
        name = self.tree.item(item)["text"]

        # Ask for credential password
        password = self.prompt_for_password("Enter credential password")
        if not password:
            self.update_status("Operation cancelled")
            return

        credential = self.keepass.get_credential(
            name, password
        )  # Use credential password
        if credential:
            pyperclip.copy(credential["value"])
            self.update_status(f"Copied credential: {name}")

            # Schedule clipboard clearing if enabled
            if self.clear_clipboard_var.get():
                self.root.after(30000, self.clear_clipboard)  # 30 seconds
        else:
            self.update_status("Failed to retrieve credential - incorrect password")

    def view_credential(self):
        # First ensure database is open with master password
        if not self.keepass.kp:
            if not self.keepass.open_database(self.master_password):
                self.update_status("Failed to open database")
                return

        selected = self.tree.selection()
        if not selected:
            self.update_status("Please select a credential to view")
            return

        item = selected[0]
        name = self.tree.item(item)["text"]

        # Ask for credential password
        password = self.prompt_for_password("Enter credential password")
        if not password:
            self.update_status("Operation cancelled")
            return

        credential = self.keepass.get_credential(
            name, password
        )  # Use credential password
        if credential:
            self.show_credential_details(credential)
        else:
            self.update_status("Failed to retrieve credential - incorrect password")

    def run(self):
        """Run the application."""
        try:
            self.root.mainloop()
        finally:
            # Ensure we clean up the icon when the app closes
            if self.icon:
                self.icon.stop()

    def quit_app(self):
        """Quit the application safely."""
        if self.icon:
            try:
                self.icon.stop()
            except:
                pass
        self.root.quit()

    def show_message(self, message, level="info"):
        """Show a message in the GUI.

        Args:
            message (str): The message to show
            level (str): The message level ('info', 'warning', or 'error')
        """
        # Update status bar
        self.update_status(message)

        # Show message box for important messages
        if "error" in message.lower() or "failed" in message.lower():
            messagebox.showerror("Error", message)
        elif "warning" in message.lower():
            messagebox.showwarning("Warning", message)
        elif "success" in message.lower():
            messagebox.showinfo("Success", message)

    def on_select(self, event):
        """Handle treeview selection event."""
        # Get the selected item
        selected = event.widget.selection()
        if selected:
            self.update_status(
                "Selected credential: " + event.widget.item(selected[0])["text"]
            )

    def on_double_click(self, event):
        """Handle double-click event."""
        # View credential on double click
        self.view_credential()

    def prompt_for_password(self, message):
        """Prompt for a password using a dialog."""
        dialog = ttk.Toplevel(self.root)
        dialog.title("Password Required")
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f"+{x}+{y}")

        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=BOTH, expand=YES)

        ttk.Label(main_frame, text=message).pack(pady=(0, 10))

        # Password entry
        password_var = ttk.StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=password_var, show="*")
        password_entry.pack(fill=X, pady=(0, 10))

        result = {"password": None}

        def on_ok():
            result["password"] = password_var.get()
            dialog.destroy()

        def on_cancel():
            dialog.destroy()

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=X, pady=(10, 0))
        ttk.Button(
            button_frame, text="OK", command=on_ok, style="primary.TButton"
        ).pack(side=RIGHT, padx=5)
        ttk.Button(
            button_frame, text="Cancel", command=on_cancel, style="secondary.TButton"
        ).pack(side=RIGHT, padx=5)

        # Bind events
        password_entry.focus_set()
        dialog.bind("<Return>", lambda e: on_ok())
        dialog.bind("<Escape>", lambda e: on_cancel())

        dialog.wait_window()
        return result["password"]

    def show_credential_details(self, credential):
        """Show credential details in a dialog window."""
        dialog = ttk.Toplevel(self.root)
        dialog.title("Credential Details")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f"+{x}+{y}")

        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=BOTH, expand=YES)

        # Name display
        name_frame = ttk.LabelFrame(main_frame, text="Name", padding="5")
        name_frame.pack(fill=X, pady=(0, 10))
        ttk.Label(name_frame, text=credential["name"]).pack(fill=X)

        # Value display
        value_frame = ttk.LabelFrame(main_frame, text="Value", padding="5")
        value_frame.pack(fill=X, pady=(0, 10))
        value_var = ttk.StringVar(value=credential["value"])
        value_entry = ttk.Entry(
            value_frame, textvariable=value_var, show="*", state="readonly"
        )
        value_entry.pack(side=LEFT, fill=X, expand=YES)

        # Show/Hide value button
        show_var = ttk.BooleanVar(value=False)
        ttk.Checkbutton(
            value_frame,
            text="Show",
            variable=show_var,
            command=lambda: value_entry.configure(show="" if show_var.get() else "*"),
            style="primary.TCheckbutton",
        ).pack(side=LEFT, padx=(5, 0))

        # Type display
        type_frame = ttk.LabelFrame(main_frame, text="Type", padding="5")
        type_frame.pack(fill=X, pady=(0, 10))
        ttk.Label(type_frame, text=credential["type"].title()).pack(fill=X)

        # Copy button
        ttk.Button(
            main_frame,
            text="Copy to Clipboard",
            command=lambda: [
                pyperclip.copy(credential["value"]),
                self.update_status(f"Copied credential: {credential['name']}"),
            ],
            style="primary.TButton",
        ).pack(fill=X, pady=(10, 0))

        # Close button
        ttk.Button(
            main_frame, text="Close", command=dialog.destroy, style="secondary.TButton"
        ).pack(fill=X, pady=(10, 0))

        # Bind escape to close
        dialog.bind("<Escape>", lambda e: dialog.destroy())

        dialog.wait_window()

    def clear_clipboard(self):
        """Clear the clipboard contents."""
        current = pyperclip.paste()
        # Only clear if it still contains our last copied value
        if any(
            cred.get("value", "") == current
            for cred in self.keepass.get_all_credentials().values()
        ):
            pyperclip.copy("")

    def manual_check_for_updates(self):
        """Manually trigger an update check."""
        self.update_status("Checking for updates...")
        try:
            if self.check_for_updates():
                messagebox.showinfo("Updates", "Application is up to date!")
            else:
                messagebox.showinfo(
                    "Updates",
                    "Updates are available. Please download the latest version.",
                )
        except Exception as e:
            self.logger.error(f"Manual update check failed: {str(e)}")
            messagebox.showerror(
                "Error", "Failed to check for updates. Please try again later."
            )
        finally:
            self.update_status("Ready")

    def show_settings(self):
        """Show the settings dialog."""
        messagebox.showinfo(
            "Settings", "Settings dialog will be implemented in a future version."
        )

    def show_password_generator(self):
        """Show the password generator dialog."""
        messagebox.showinfo(
            "Password Generator",
            "Password generator will be implemented in a future version.",
        )

    def run_security_check(self):
        """Run a security check on stored credentials."""
        messagebox.showinfo(
            "Security Check", "Security check will be implemented in a future version."
        )

    def show_documentation(self, section="quick_start"):
        """Show the documentation viewer with the specified section."""
        dialog = ttk.Toplevel(self.root)
        dialog.title("Secure Credential Manager - Documentation")
        dialog.geometry("600x500")
        dialog.transient(self.root)

        # Create main frame
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=BOTH, expand=YES)

        # Documentation content
        docs = {
            "quick_start": {
                "title": "Quick Start Guide",
                "content": """
# Quick Start Guide

## Managing Credentials

1. **Adding Credentials**
   - Click 'New Credential' or press Ctrl+N
   - Enter the name, value, and credential password
   - Select the credential type
   - Click OK to save

2. **Viewing Credentials**
   - Double-click any credential to view details
   - Use the search bar to filter credentials
   - Click column headers to sort

3. **Editing Credentials**
   - Select a credential and click 'Edit'
   - Enter the credential password
   - Modify the details and click OK

4. **Deleting Credentials**
   - Select a credential and click 'Delete'
   - Enter the credential password
   - Confirm deletion

## Organization

- Use meaningful names for easy searching
- Group similar credentials using consistent naming
- Use appropriate credential types
""",
            },
            "security": {
                "title": "Security Guide",
                "content": """
# Security Guide

## Master Password

- Use a strong, unique master password
- Never share your master password
- Change it periodically
- No password recovery - keep it safe!

## Credential Passwords

- Each credential has its own password
- Use different passwords for each credential
- Enable auto-clear clipboard for safety

## Auto-Lock

- Set appropriate auto-lock timeout
- Lock manually when stepping away
- Application locks automatically on inactivity

## Backups

- Create regular database backups
- Store backups securely
- Test backup restoration periodically
""",
            },
            "shortcuts": {
                "title": "Keyboard Shortcuts",
                "content": """
# Keyboard Shortcuts

## General
- Ctrl+N: New Credential
- Ctrl+L: Lock Application
- Ctrl+F: Focus Search
- Esc: Close current window

## Selected Credential
- Enter: View Details
- Delete: Delete Credential
- Ctrl+C: Copy Value

## Navigation
- Tab: Move between fields
- Arrow keys: Navigate list
""",
            },
        }

        # Create notebook for sections
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=BOTH, expand=YES, pady=(0, 10))

        # Create text widgets for each section
        for key, content in docs.items():
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=content["title"])

            text = ttk.Text(frame, wrap="word", font=("TkDefaultFont", 10))
            text.pack(fill=BOTH, expand=YES)

            # Add scrollbar
            scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
            scrollbar.pack(side=RIGHT, fill=Y)
            text.configure(yscrollcommand=scrollbar.set)

            # Insert content
            text.insert("1.0", content["content"])
            text.configure(state="disabled")  # Make read-only

        # Select the requested section
        section_index = list(docs.keys()).index(section)
        notebook.select(section_index)

        # Close button
        ttk.Button(
            main_frame, text="Close", command=dialog.destroy, style="primary.TButton"
        ).pack(fill=X)

        # Bind escape to close
        dialog.bind("<Escape>", lambda e: dialog.destroy())

    def show_about(self):
        """Show the about dialog."""
        messagebox.showinfo(
            "About",
            "Secure Credential Manager\nVersion 1.0.0\n\nA secure password manager.",
        )

    def import_credentials(self):
        """Import credentials from a file."""
        messagebox.showinfo(
            "Import", "Import functionality will be implemented in a future version."
        )

    def export_credentials(self):
        """Export credentials to a file."""
        messagebox.showinfo(
            "Export", "Export functionality will be implemented in a future version."
        )

    def copy_field(self, field_type: str):
        """Copy a field to the clipboard."""
        messagebox.showinfo(
            "Copy",
            f"Copy {field_type} functionality will be implemented in a future version.",
        )

    def check_for_updates(self) -> bool:
        """Check for updates and return True if up to date, False if updates available."""
        try:
            # Get current version from package
            current_version = pkg_resources.get_distribution(
                "secure_credentials"
            ).version

            # Get latest version from GitHub or your package repository
            # This is a placeholder - implement actual version check logic
            latest_version = current_version  # Replace with actual version check

            # Compare versions
            if version.parse(current_version) < version.parse(latest_version):
                self.logger.info(f"Update available: {latest_version}")
                return False
            else:
                self.logger.info("Application is up to date")
                return True

        except Exception as e:
            self.logger.error(f"Failed to check for updates: {str(e)}")
            return True  # Return True to avoid update notifications on error


class CredentialDialog:
    def __init__(self, parent, name=None, current_value=None):
        self.result = None
        self.dialog = ttk.Toplevel(parent)
        self.dialog.title("Add Credential" if not name else "Edit Credential")
        self.dialog.geometry("400x300")  # Made taller for new field
        self.dialog.resizable(False, False)

        # Make dialog modal
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Create main frame
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=BOTH, expand=YES)

        # Name entry
        name_frame = ttk.Frame(main_frame)
        name_frame.pack(fill=X, pady=(0, 10))
        ttk.Label(name_frame, text="Name:").pack(side=LEFT)
        self.name_var = ttk.StringVar(value=name if name else "")
        self.name_entry = ttk.Entry(name_frame, textvariable=self.name_var)
        self.name_entry.pack(side=LEFT, fill=X, expand=YES, padx=(5, 0))

        # Value entry
        value_frame = ttk.Frame(main_frame)
        value_frame.pack(fill=X, pady=(0, 10))
        ttk.Label(value_frame, text="Value:").pack(side=LEFT)
        self.value_var = ttk.StringVar(value=current_value if current_value else "")
        self.value_entry = ttk.Entry(value_frame, textvariable=self.value_var, show="*")
        self.value_entry.pack(side=LEFT, fill=X, expand=YES, padx=(5, 5))

        # Show/Hide value button
        self.show_value_var = ttk.BooleanVar(value=False)
        ttk.Checkbutton(
            value_frame,
            text="Show",
            variable=self.show_value_var,
            command=lambda: self.toggle_show(self.value_entry, self.show_value_var),
            style="primary.TCheckbutton",
        ).pack(side=LEFT, padx=(5, 0))

        # Credential Password entry
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(fill=X, pady=(0, 10))
        ttk.Label(password_frame, text="Password:").pack(side=LEFT)
        self.password_var = ttk.StringVar()
        self.password_entry = ttk.Entry(
            password_frame, textvariable=self.password_var, show="*"
        )
        self.password_entry.pack(side=LEFT, fill=X, expand=YES, padx=(5, 5))

        # Show/Hide password button
        self.show_password_var = ttk.BooleanVar(value=False)
        ttk.Checkbutton(
            password_frame,
            text="Show",
            variable=self.show_password_var,
            command=lambda: self.toggle_show(
                self.password_entry, self.show_password_var
            ),
            style="primary.TCheckbutton",
        ).pack(side=LEFT, padx=(5, 0))

        # Type selection
        type_frame = ttk.Frame(main_frame)
        type_frame.pack(fill=X, pady=(0, 20))
        ttk.Label(type_frame, text="Type:").pack(side=LEFT)
        self.type_var = ttk.StringVar(value=CredentialType.PASSWORD)
        type_combo = ttk.Combobox(
            type_frame,
            textvariable=self.type_var,
            values=[
                CredentialType.PASSWORD,
                CredentialType.API_KEY,
                CredentialType.OTHER,
            ],
            state="readonly",
        )
        type_combo.pack(side=LEFT, fill=X, expand=YES, padx=(5, 0))

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=X, pady=(0, 0))

        ttk.Button(
            button_frame,
            text="Cancel",
            command=self.dialog.destroy,
            style="secondary.TButton",
        ).pack(side=RIGHT, padx=5)
        ttk.Button(
            button_frame, text="OK", command=self.ok, style="primary.TButton"
        ).pack(side=RIGHT, padx=5)

        # Bind events
        self.dialog.bind("<Return>", lambda e: self.ok())

        # Focus on name entry if new credential, value entry if editing
        if name:
            self.value_entry.focus_set()
        else:
            self.name_entry.focus_set()

        parent.wait_window(self.dialog)

    def toggle_show(self, entry, var):
        """Toggle password visibility for an entry."""
        entry.configure(show="" if var.get() else "*")

    def ok(self):
        if (
            not self.name_var.get()
            or not self.value_var.get()
            or not self.password_var.get()
        ):
            messagebox.showwarning("Warning", "Please fill in all fields")
            return

        self.result = (
            self.name_var.get(),
            self.value_var.get(),
            self.type_var.get(),
            self.password_var.get(),
        )
        self.dialog.destroy()
