#!/usr/bin/env python3
"""
BSI Application Launcher
Runs Streamlit with default server configuration
"""

import subprocess
import sys

if __name__ == "__main__":
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "app.py",
        "--server.address",
        "0.0.0.0",
        "--server.port",
        "8502"
    ]
    
    subprocess.run(cmd)
