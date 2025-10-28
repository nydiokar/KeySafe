#!/usr/bin/env python3
"""
Run script for Secure Credential Manager with different modes for debugging.

Usage:
  python run_app.py                # Normal mode
  python run_app.py debug          # Debug mode with verbose logging
  python run_app.py test_window    # Test just the window functionality
  python run_app.py direct_gui     # Run GUI directly without launcher
"""

import sys
import os
import time
import threading
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("run_app_debug.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("run_app")

def run_normal():
    """Run the app in normal mode through the launcher."""
    logger.info("Running app in normal mode")
    
    from secure_credentials.src.security import SecurityManager
    from secure_credentials.src.ui.gui import CredentialManagerGUI
    
    # Initialize security manager
    security_manager = SecurityManager()
    
    # Verify installation integrity
    app_dir = Path(__file__).parent.resolve()
    if not security_manager.verify_installation(app_dir):
        logger.error("Security Error: Installation verification failed")
        sys.exit(1)
        
    try:
        # Create the application with security manager
        logger.info("Creating GUI application...")
        app = CredentialManagerGUI(security_manager=security_manager)
        
        # Run the application
        logger.info("Running main application loop...")
        app.run()
    except Exception as e:
        logger.exception(f"Error in run_normal: {str(e)}")
        sys.exit(1)

def run_debug():
    """Run with extra debug output and window forcing."""
    logger.info("Running app in DEBUG mode with enhanced visibility checks")
    
    from secure_credentials.src.security import SecurityManager
    from secure_credentials.src.ui.gui import CredentialManagerGUI
    
    # Initialize security manager
    security_manager = SecurityManager()
    
    # Verify installation integrity
    app_dir = Path(__file__).parent.resolve()
    if not security_manager.verify_installation(app_dir):
        logger.error("Security Error: Installation verification failed")
        sys.exit(1)
        
    try:
        # Create the application with security manager
        logger.info("Creating GUI application in debug mode...")
        app = CredentialManagerGUI(security_manager=security_manager)
        
        # Explicit window showing with aggressive approach
        def aggressive_show():
            for i in range(10):  # Try multiple times
                logger.debug(f"Aggressive show attempt {i+1}")
                time.sleep(0.5)
                try:
                    if hasattr(app, 'root') and app.root.winfo_exists():
                        app.root.deiconify()
                        app.root.lift()
                        app.root.focus_force()
                        app.root.attributes('-topmost', True)
                        app.root.update()
                        app.root.attributes('-topmost', False)
                        logger.debug(f"Window state: visible={app.root.winfo_ismapped()}")
                except Exception as e:
                    logger.exception(f"Error in aggressive show: {str(e)}")
        
        # Start the aggressive show thread
        logger.info("Starting aggressive show thread...")
        threading.Thread(target=aggressive_show, daemon=True).start()
        
        # Run the application
        logger.info("Running main application loop...")
        app.run()
    except Exception as e:
        logger.exception(f"Error in run_debug: {str(e)}")
        sys.exit(1)

def test_window():
    """Test just the basic window functionality."""
    logger.info("Testing basic window functionality")
    
    import ttkbootstrap as ttk
    
    try:
        # Initialize root window
        root = ttk.Window(themename="darkly")
        root.title("Test Window")
        
        # Set window size and position
        root.geometry("600x400+100+100")
        
        # Add a label
        label = ttk.Label(root, text="Test Window", font=('TkDefaultFont', 16))
        label.pack(pady=20)
        
        # Add a message
        message = ttk.Label(root, text="If you can see this window, the issue is likely\nspecific to the credential manager GUI.", 
                          wraplength=500)
        message.pack(pady=10)
        
        # Add a button to force visibility
        def force_visibility():
            logger.debug("Force visibility button clicked")
            root.deiconify()
            root.lift()
            root.focus_force()
            root.attributes('-topmost', True)
            root.update()
            root.attributes('-topmost', False)
            
        ttk.Button(root, text="Force Visibility", command=force_visibility,
                 style='primary.TButton').pack(pady=10)
        
        # Add a close button
        ttk.Button(root, text="Close", command=root.destroy,
                 style='danger.TButton').pack(pady=10)
        
        # Show the window with multiple methods
        root.deiconify()
        root.lift()
        root.focus_force()
        root.attributes('-topmost', True)
        root.update()
        root.attributes('-topmost', False)
        
        logger.info("Test window created and displayed")
        
        # Start the main loop
        root.mainloop()
        
    except Exception as e:
        logger.exception(f"Error in test_window: {str(e)}")
        sys.exit(1)

def run_direct_gui():
    """Run the GUI directly without going through the launcher."""
    logger.info("Running GUI directly (bypassing launcher)")
    
    from secure_credentials.src.ui.gui import CredentialManagerGUI
    
    try:
        app = CredentialManagerGUI()
        app.run()
    except Exception as e:
        logger.exception(f"Error in run_direct_gui: {str(e)}")
        sys.exit(1)

def main():
    """Main entry point for the application."""
    # Get mode from command line argument
    mode = sys.argv[1] if len(sys.argv) > 1 else "normal"

    logger.info(f"Starting app in {mode} mode")

    if mode == "debug":
        run_debug()
    elif mode == "test_window":
        test_window()
    elif mode == "direct_gui":
        run_direct_gui()
    else:
        run_normal()

if __name__ == "__main__":
    main() 