
#!/bin/bash

echo "Email Guardian - Mac/Linux Installation"
echo "======================================"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    echo "Please install Python 3.8 or higher"
    echo "On Mac: brew install python3"
    echo "On Ubuntu/Debian: sudo apt-get install python3 python3-pip"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "Python $PYTHON_VERSION detected"

# Check if pip3 is available
if ! command -v pip3 &> /dev/null; then
    echo "Error: pip3 is not installed"
    echo "Please install pip3"
    exit 1
fi

# Upgrade pip
echo "Upgrading pip..."
python3 -m pip install --upgrade pip

# Install requirements
echo "Installing dependencies..."
python3 -m pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "Failed to install dependencies"
    exit 1
fi

# Run setup script
echo "Running setup script..."
python3 setup.py
if [ $? -ne 0 ]; then
    echo "Setup failed"
    exit 1
fi

echo ""
echo "======================================"
echo "Installation completed successfully!"
echo ""
echo "To start the application:"
echo "  python3 app.py"
echo ""
echo "Then open your browser to: http://localhost:5000"
echo "======================================"
