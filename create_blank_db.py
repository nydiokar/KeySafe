from pykeepass import create_database
import os

def create_blank_template():
    """Create a blank KeePass database template."""
    template_path = os.path.join('secure_credentials', 'assets', 'blank_database.kdbx')
    
    # Create assets directory if it doesn't exist
    os.makedirs(os.path.dirname(template_path), exist_ok=True)
    
    # Create blank database with temporary password
    kp = create_database(template_path, password='temp')
    kp.save()
    print(f"Created blank database template at {template_path}")

if __name__ == '__main__':
    create_blank_template() 