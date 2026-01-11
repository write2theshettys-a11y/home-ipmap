#!/bin/bash
# Run the application with sudo using the virtual environment's python.
# This is necessary because ARP scanning requires root privileges.

# Get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if .venv exists
if [ -d "$DIR/.venv" ]; then
    echo "Using .venv python..."
    sudo "$DIR/.venv/bin/python" "$DIR/app.py"
else
    echo "Virtual environment not found. Please create it or run: python3 -m venv .venv"
    exit 1
fi
