#!/usr/bin/env python3
"""
Web server for Secure Credential Manager.
Provides browser-based access to the password manager.

Usage:
  python -m secure_credentials.src.web_app
  # Or after installation:
  secure-credentials-web

Environment variables:
  FLASK_ENV=development  # Enable debug mode
  FLASK_PORT=5000        # Server port (default: 5000)
  HOST=0.0.0.0          # Bind address (default: 127.0.0.1)
"""

import os
import sys
import logging
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import HTTPException

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from secure_credentials.src.keepass_backend import KeePassHandler
from secure_credentials.src.security import SecurityManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

# Flask application
template_dir = Path(__file__).parent.parent / 'templates'
app = Flask(__name__, template_folder=str(template_dir))
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_TYPE'] = 'filesystem'

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Global instances
keepass_handler = None
security_manager = None

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def get_keepass_handler():
    """Get or create KeePass handler instance."""
    global keepass_handler
    if keepass_handler is None:
        keepass_handler = KeePassHandler()
    return keepass_handler

def get_security_manager():
    """Get or create security manager instance."""
    global security_manager
    if security_manager is None:
        security_manager = SecurityManager()
    return security_manager

@app.route('/')
@login_required
def index():
    """Main dashboard showing all credentials."""
    try:
        kp = get_keepass_handler()
        if not kp.kp:
            # Database not opened, clear session and redirect to login
            logout_user()
            session.clear()
            flash('Session expired. Please log in again.', 'error')
            return redirect(url_for('login'))

        credentials = kp.get_all_credentials()

        # Group credentials by type
        grouped_creds = {
            'passwords': [],
            'api_keys': [],
            'other': []
        }

        for name, data in credentials.items():
            cred_type = data.get('type', 'other')
            if cred_type == 'password':
                grouped_creds['passwords'].append({'name': name, **data})
            elif cred_type == 'api_key':
                grouped_creds['api_keys'].append({'name': name, **data})
            else:
                grouped_creds['other'].append({'name': name, **data})

        return render_template('index.html',
                             passwords=grouped_creds['passwords'],
                             api_keys=grouped_creds['api_keys'],
                             other_creds=grouped_creds['other'])

    except Exception as e:
        logger.exception(f"Error in index: {str(e)}")
        flash('An error occurred while loading credentials.', 'error')
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page for master password."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        master_password = request.form.get('master_password')

        if not master_password:
            flash('Master password is required.', 'error')
            return render_template('login.html')

        try:
            kp = get_keepass_handler()

            # Check if database exists
            if kp.db_path.exists():
                # Try to open existing database
                if kp.open_database(master_password):
                    # Store password hash in session for verification
                    session['password_hash'] = generate_password_hash(master_password)
                    login_user(User('admin'))
                    flash('Successfully logged in!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Invalid master password.', 'error')
            else:
                # Create new database for first-time setup
                logger.info("No database found, creating new one")
                if kp.create_database(master_password):
                    # Store password hash in session for verification
                    session['password_hash'] = generate_password_hash(master_password)
                    login_user(User('admin'))
                    flash('Database created and login successful!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Failed to create database.', 'error')

        except Exception as e:
            logger.exception(f"Login error: {str(e)}")
            flash('An error occurred during login.', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout and close database."""
    try:
        kp = get_keepass_handler()
        # Close database connection
        kp.kp = None
        session.clear()
        logout_user()
        flash('Successfully logged out.', 'success')
    except Exception as e:
        logger.exception(f"Logout error: {str(e)}")

    return redirect(url_for('login'))

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_credential():
    """Add new credential."""
    if request.method == 'POST':
        name = request.form.get('name')
        value = request.form.get('value')
        cred_type = request.form.get('type', 'password')
        credential_password = request.form.get('credential_password')

        if not all([name, value, credential_password]):
            flash('All fields are required.', 'error')
            return render_template('add.html')

        try:
            kp = get_keepass_handler()
            if kp.add_credential(name, value, cred_type, credential_password):
                flash('Credential added successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Failed to add credential.', 'error')

        except Exception as e:
            logger.exception(f"Add credential error: {str(e)}")
            flash('An error occurred while adding the credential.', 'error')

    return render_template('add.html')

@app.route('/view/<name>', methods=['GET', 'POST'])
@login_required
def view_credential(name):
    """View credential details."""
    if request.method == 'POST':
        credential_password = request.form.get('credential_password')

        if not credential_password:
            flash('Credential password is required.', 'error')
            return render_template('view.html', name=name)

        try:
            kp = get_keepass_handler()
            credential = kp.get_credential(name, credential_password)

            if credential:
                return render_template('view.html', name=name, credential=credential)
            else:
                flash('Invalid credential password.', 'error')

        except Exception as e:
            logger.exception(f"View credential error: {str(e)}")
            flash('An error occurred while retrieving the credential.', 'error')

    return render_template('view.html', name=name)

@app.route('/edit/<name>', methods=['GET', 'POST'])
@login_required
def edit_credential(name):
    """Edit existing credential."""
    kp = get_keepass_handler()

    if request.method == 'GET':
        # Get current credential info (without password)
        credentials = kp.get_all_credentials()
        if name in credentials:
            cred_data = credentials[name]
            return render_template('edit.html', name=name, credential=cred_data)
        else:
            flash('Credential not found.', 'error')
            return redirect(url_for('index'))

    elif request.method == 'POST':
        new_name = request.form.get('name')
        new_value = request.form.get('value')
        new_type = request.form.get('type', 'password')
        current_password = request.form.get('current_password')

        if not all([new_name, new_value, current_password]):
            flash('All fields are required.', 'error')
            return render_template('edit.html', name=name)

        try:
            if kp.edit_credential(name, new_name, new_value, new_type, current_password):
                flash('Credential updated successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Failed to update credential. Check your current password.', 'error')

        except Exception as e:
            logger.exception(f"Edit credential error: {str(e)}")
            flash('An error occurred while updating the credential.', 'error')

    return render_template('edit.html', name=name)

@app.route('/delete/<name>', methods=['POST'])
@login_required
def delete_credential(name):
    """Delete credential."""
    credential_password = request.form.get('credential_password')

    if not credential_password:
        flash('Credential password is required.', 'error')
        return redirect(url_for('index'))

    try:
        kp = get_keepass_handler()
        if kp.delete_credential(name, credential_password):
            flash('Credential deleted successfully!', 'success')
        else:
            flash('Failed to delete credential. Check your password.', 'error')

    except Exception as e:
        logger.exception(f"Delete credential error: {str(e)}")
        flash('An error occurred while deleting the credential.', 'error')

    return redirect(url_for('index'))

@app.route('/api/search')
@login_required
def search_credentials():
    """API endpoint for searching credentials."""
    query = request.args.get('q', '').lower()

    try:
        kp = get_keepass_handler()
        credentials = kp.get_all_credentials()

        results = []
        for name, data in credentials.items():
            if query in name.lower() or query in data.get('type', '').lower():
                results.append({'name': name, **data})

        return jsonify(results)

    except Exception as e:
        logger.exception(f"Search error: {str(e)}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/api/view/<name>', methods=['POST'])
@login_required
def api_view_credential(name):
    """API endpoint for viewing credentials via AJAX."""
    try:
        data = request.get_json()
        credential_password = data.get('password')

        if not credential_password:
            return jsonify({'success': False, 'message': 'Password is required'}), 400

        kp = get_keepass_handler()
        credential = kp.get_credential(name, credential_password)

        if credential:
            return jsonify({
                'success': True,
                'credential': credential
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid credential password'}), 403

    except Exception as e:
        logger.exception(f"API view credential error: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.errorhandler(HTTPException)
def handle_http_error(error):
    """Handle HTTP errors."""
    return render_template('error.html', error=error), error.code

@app.errorhandler(Exception)
def handle_general_error(error):
    """Handle general errors."""
    logger.exception(f"Unhandled error: {str(error)}")
    return render_template('error.html', error="Internal server error"), 500

def main():
    """Main entry point for the web server."""
    # Get configuration from environment
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'

    print(f"Starting Secure Credential Manager Web Server...")
    print(f"Access at: http://{host}:{port}")
    print(f"Debug mode: {debug}")
    print("Press Ctrl+C to stop")

    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    main()
