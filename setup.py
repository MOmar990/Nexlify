import os
import subprocess
import sys
import platform
import venv
import shutil
from pathlib import Path

def check_python_version():
    """Ensure Python is 3.8 or higher."""
    if sys.version_info < (3, 8):
        print("[!] Error: Nexlify requires Python 3.8 or higher.")
        print(f"    Current version: {sys.version.split()[0]}")
        sys.exit(1)
    print("[*] Python version check passed:", sys.version.split()[0])

def create_virtualenv(venv_path):
    """Create a virtual environment if it doesn't exist."""
    if not os.path.exists(venv_path):
        print("[*] Creating virtual environment at", venv_path)
        venv.create(venv_path, with_pip=True)
    else:
        print("[*] Virtual environment already exists at", venv_path)

def activate_virtualenv(venv_path):
    """Provide instructions to activate the virtual environment."""
    system = platform.system()
    if system == "Windows":
        activate_script = os.path.join(venv_path, "Scripts", "activate.bat")
        print(f"[*] To activate the virtual environment, run:\n    {activate_script}")
    else:
        activate_script = os.path.join(venv_path, "bin", "activate")
        print(f"[*] To activate the virtual environment, run:\n    source {activate_script}")

def install_dependencies():
    """Install dependencies from requirements.txt."""
    print("[*] Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("[*] Dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error installing dependencies: {e}")
        print("    Try running 'pip install -r requirements.txt' manually after activating the virtual environment.")
        sys.exit(1)

def check_tkinter():
    """Check if Tkinter is installed, prompt to install on Linux."""
    try:
        import tkinter
        print("[*] Tkinter is installed.")
    except ImportError:
        print("[!] Tkinter is not installed.")
        if platform.system() == "Linux":
            print("[*] On Debian/Ubuntu, you can install it with:")
            print("    sudo apt-get install python3-tk")
            if input("[?] Install Tkinter now? (y/n): ").lower() == "y":
                try:
                    subprocess.check_call(["sudo", "apt-get", "install", "-y", "python3-tk"])
                    print("[*] Tkinter installed successfully.")
                except subprocess.CalledProcessError as e:
                    print(f"[!] Error installing Tkinter: {e}")
                    print("    Please install Tkinter manually and try again.")
                    sys.exit(1)
        else:
            print("[!] Please install Tkinter manually or ensure Python includes it (e.g., install from python.org on macOS/Windows).")
            sys.exit(1)

def check_port():
    """Prompt to ensure port 9999 is open."""
    print("[*] Nexlify uses port 9999 by default for hosting.")
    print("[*] Ensure this port is open in your firewall.")
    if platform.system() == "Linux":
        print("    Example: sudo ufw allow 9999")
    elif platform.system() == "Windows":
        print("    Check Windows Firewall settings to allow port 9999.")
    input("[?] Press Enter to continue...")

def main():
    print("=====================================")
    print("      Nexlify Installation Wizard     ")
    print("=====================================")
    print("[*] Welcome to Nexlify setup! Let's get you started.\n")

    # Step 1: Check Python version
    check_python_version()

    # Step 2: Create virtual environment
    venv_path = os.path.join(os.getcwd(), "myenv")
    create_virtualenv(venv_path)
    activate_virtualenv(venv_path)

    # Step 3: Install dependencies
    install_dependencies()

    # Step 4: Check Tkinter
    check_tkinter()

    # Step 5: Check port
    check_port()

    print("\n[*] Setup complete! To run Nexlify:")
    print("    1. Activate the virtual environment (see instructions above).")
    print("    2. Run: python3 nexlify.py")
    print("[*] For the best UI experience, install JetBrains Mono font from: https://www.jetbrains.com/lp/mono/")
    print("[*] See README.markdown for usage instructions.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Setup interrupted by user.")
        sys.exit(1)