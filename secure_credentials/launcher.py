#!/usr/bin/env python3
import logging
import sys
import threading
import time
from pathlib import Path

from secure_credentials.src.security import SecurityManager
from secure_credentials.src.ui.gui import CredentialManagerGUI

# Configure root logger
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("secure_credentials_debug.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("secure_credentials.launcher")


def main():
    logger.info("Application starting...")

    # Initialize security manager
    security_manager = SecurityManager()

    # Verify installation integrity
    app_dir = Path(__file__).parent.resolve()
    if not security_manager.verify_installation(app_dir):
        logger.error("Security Error: Installation verification failed")
        sys.exit(1)

    try:
        # Create the application
        logger.info("Creating GUI application...")
        app = CredentialManagerGUI()

        # Explicitly trigger the show_main_window after a slight delay
        # This helps overcome Windows focus management issues
        def delayed_show():
            # Wait a bit to ensure everything is fully initialized
            logger.debug("Delayed show thread started, waiting...")
            time.sleep(1.0)
            # Try to call show_main_window from within the main thread
            logger.debug("Attempting to show main window...")
            if hasattr(app, "root") and app.root.winfo_exists():
                logger.debug("Scheduling show_main_window call in Tkinter event loop")
                app.root.after(
                    10, app.show_main_window
                )  # Queue call to show_main_window in the Tkinter event loop
            else:
                logger.error(
                    "Cannot show main window - root does not exist or is not valid"
                )

        # Start the delayed show thread
        logger.info("Starting delayed show thread...")
        threading.Thread(target=delayed_show, daemon=True).start()

        # Run the application
        logger.info("Running main application loop...")
        app.run()
    except Exception as e:
        logger.exception(f"Error in main function: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
