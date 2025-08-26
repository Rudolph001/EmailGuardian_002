
#!/usr/bin/env python3
"""
Email Guardian Setup Script
Installs dependencies and sets up the application for local development
"""

import os
import sys
import subprocess
import platform

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"\n{description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✓ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✓ Python {version.major}.{version.minor}.{version.micro} detected")

def install_dependencies():
    """Install required Python packages"""
    packages = [
        "Flask>=3.1.2",
        "pandas>=2.3.2",
        "numpy>=2.3.2",
        "scikit-learn>=1.7.1",
        "python-dateutil>=2.9.0.post0",
        "email-validator>=2.2.0",
        "tqdm>=4.67.1",
        "Werkzeug>=3.1.3",
        "gunicorn>=23.0.0"
    ]
    
    for package in packages:
        if not run_command(f"pip install {package}", f"Installing {package}"):
            return False
    return True

def create_local_config():
    """Create local configuration file"""
    config_content = '''# Local Configuration for Email Guardian
import os

# Database configuration
DATABASE_PATH = "email_guardian.sqlite"

# Security
SECRET_KEY = "your-secret-key-change-this-in-production"

# Application settings
BATCH_SIZE = 1000
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB

# Internal domains (customize for your organization)
INTERNAL_DOMAINS = [
    "example.com",
    "yourcompany.com"
]

# Field delimiters for CSV parsing
RECIPIENTS_DELIMITER = ";"
ATTACHMENTS_DELIMITER = ";"
POLICIES_DELIMITER = ";"
'''
    
    if not os.path.exists("config_local.py"):
        with open("config_local.py", "w") as f:
            f.write(config_content)
        print("✓ Created local configuration file (config_local.py)")
    else:
        print("✓ Local configuration file already exists")

def setup_database():
    """Initialize the database"""
    try:
        from models import init_db
        init_db()
        print("✓ Database initialized successfully")
        return True
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")
        return False

def main():
    """Main setup function"""
    print("Email Guardian Local Setup")
    print("=" * 40)
    
    # Check Python version
    check_python_version()
    
    # Check if pip is available
    if not run_command("pip --version", "Checking pip availability"):
        print("Please install pip and try again")
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("Failed to install dependencies")
        sys.exit(1)
    
    # Create local config
    create_local_config()
    
    # Setup database
    if not setup_database():
        print("Failed to initialize database")
        sys.exit(1)
    
    print("\n" + "=" * 40)
    print("✓ Setup completed successfully!")
    print("\nTo start the application:")
    if platform.system() == "Windows":
        print("  python app.py")
    else:
        print("  python3 app.py")
    print("\nThen open your browser to: http://localhost:5000")

if __name__ == "__main__":
    main()
