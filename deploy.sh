#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "======Starting custom deployment script..."

# --- Install system dependencies ---
echo "======Running apt-get update and installing system dependencies..."
# apt-get update
# apt-get install -y build-essential python3-dev pkg-config libxml2-dev libxslt1-dev libxmlsec1-dev libxmlsec1-openssl

sudo apt-get update
sudo apt-get install -y build-essential python3-dev pkg-config libxml2-dev libxslt1-dev libxmlsec1-dev libxmlsec1-openssl
 
# --- Run the default Oryx build for Python ---
# This command will activate the virtual environment and run pip install -r requirements.txt
# It's crucial to call the default Oryx build script to ensure your Python dependencies are installed.
echo "======Running default Oryx build for Python..."
/opt/startup/startup.sh

echo "======Custom deployment script finished."