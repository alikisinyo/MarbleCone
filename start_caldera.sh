#!/bin/bash

echo "========================================"
echo "MarbleCone Threat Emulator - APT-33 Replica"
echo "========================================"
echo

echo "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in PATH"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

echo "Installing dependencies..."
pip3 install -r requirements.txt

echo
echo "Starting MarbleCone Threat Emulator..."
echo
echo "Access the web interface at: http://localhost:5000"
echo "Login credentials: admin / admin123"
echo
echo "Press Ctrl+C to stop the server"
echo

python3 app.py 