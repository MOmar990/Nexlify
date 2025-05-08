# Nexlify 💾🔒

[![Latest Release](https://img.shields.io/github/v/release/MOmar990/Nexlify?color=00F5E1&style=flat-square)](https://github.com/MOmar990/Nexlify/releases/tag/v1.0.0)

**Nexlify** is a secure, peer-to-peer messaging application built with Python and Tkinter. Designed for privacy and performance, it offers end-to-end encryption, a cyberpunk-inspired interface, and flexible host-client architecture. Whether you're running a secure node or connecting to one, Nexlify ensures your communications are protected with AES-GCM encryption, anonymized codenames, and optional message compression.

## 🚀 Features

- **End-to-End Encryption**: Secure messages with AES-GCM using a shared passphrase and token.
- **Host/Client Modes**: Host a node to accept connections or join as a client.
- **Concurrent Users**: Supports up to 20 concurrent users, depending on hardware and network conditions.
- **Stealth Mode**: Anonymize your identity with hashed codenames for extra privacy.
- **Message Compression**: Optimize data transfer with optional zlib compression.
- **Cyberpunk UI**: Neon-themed Tkinter interface with JetBrains Mono font for a futuristic vibe.
- **In-App Commands**:
  - `/ping`: Measure latency to the host (client only).
  - `/who`: List connected clients.
  - `/ghost`: Toggle stealth mode.
  - `/compress`: Enable/disable compression.
  - `/clear`: Clear the chat window.
  - `/exit`: Disconnect and return to mode selection.
- **Robust Logging**: Detailed debug logs in `secure_node_logs/` for troubleshooting.
- **Cross-Platform**: Runs on Windows, macOS, and Linux with Python 3.8+.

## 🛠️ Installation

### Prerequisites

- **Python 3.8+**: Ensure Python is installed (`python3 --version`).
- **Tkinter**: Included with Python or install via `sudo apt-get install python3-tk` (Debian/Ubuntu).
- **JetBrains Mono Font**: Optional for the best UI experience. Download from [JetBrains](https://www.jetbrains.com/lp/mono/).

### Option 1: Manual Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/MOmar990/Nexlify.git
   cd Nexlify
   ```

2. **Create a Virtual Environment**:
   ```bash
   python3 -m venv myenv
   source myenv/bin/activate  # On Windows: myenv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run Nexlify**:
   ```bash
   python3 nexlify.py
   ```

