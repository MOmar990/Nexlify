# Nexlify 💾🔒

**Nexlify** is a secure, peer-to-peer messaging application built with Python and Tkinter. Engineered for privacy and performance, it delivers end-to-end encryption, a cyberpunk-inspired interface, and a flexible host-client architecture. Whether hosting a secure node or connecting as a client, Nexlify protects your communications with AES-GCM encryption, anonymized codenames, and optional message compression.

## 🚀 Features

- **End-to-End Encryption**: Messages secured with AES-GCM using a shared passphrase and token.
- **Host/Client Architecture**: Host a node to accept connections or join as a client.
- **Concurrent Users**: Supports up to 20 concurrent users, depending on hardware and network conditions (see [Known Limitations](#-known-limitations)).
- **Stealth Mode**: Anonymize your identity with hashed codenames for enhanced privacy.
- **Message Compression**: Optimize data transfer with optional zlib compression.
- **Cyberpunk UI**: Neon-themed Tkinter interface with JetBrains Mono font for a futuristic aesthetic.
- **In-App Commands**:
  - `/ping`: Measure latency to the host (client only).
  - `/who`: List connected clients.
  - `/ghost`: Toggle stealth mode.
  - `/compress`: Enable/disable compression.
  - `/clear`: Clear the chat window.
  - `/exit`: Disconnect and return to mode selection.
- **Robust Logging**: Detailed debug logs in `secure_node_logs/` for troubleshooting.
- **Cross-Platform**: Runs on Windows, macOS, and Linux with Python 3.8+.
- **Installation Wizard**: CLI-based `setup.py` automates setup for ease of use.

## 🛠️ Installation

### Prerequisites

- **Python 3.8+**: Verify with `python3 --version`.
- **Tkinter**: Included with Python or install via `sudo apt-get install python3-tk` (Debian/Ubuntu).
- **JetBrains Mono Font**: Optional for optimal UI. Download from [JetBrains](https://www.jetbrains.com/lp/mono/).

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

### Option 2: Installation Wizard (Recommended)

Use the CLI wizard to automate setup, including virtual environment creation, dependency installation, and system checks.

1. **Run the Wizard**:
   ```bash
   python3 setup.py
   ```

2. Follow prompts to:
   - Verify Python version.
   - Create and activate a virtual environment.
   - Install dependencies.
   - Check Tkinter and port settings.

3. Activate the virtual environment as instructed and run:
   ```bash
   python3 nexlify.py
   ```

## 📡 Usage

### Running as a Host

1. Launch Nexlify and select **Initialize Node (Host)**.
2. Enter a codename (or "random"), a passphrase, and a port (default: 9999).
3. Copy the generated authentication token.
4. Share the passphrase, port, and token with clients.
5. Start messaging once clients connect.

### Running as a Client

1. Launch Nexlify and select **Connect to Node (Client)**.
2. Enter a codename, the host’s IP (e.g., `127.0.0.1` for local), port, passphrase, and token.
3. Connect and begin chatting.

### Commands

Use these in the chat input:
- `/ping`: Check host latency (client only).
- `/who`: List active clients.
- `/ghost`: Enable/disable stealth mode.
- `/compress`: Toggle message compression.
- `/clear`: Clear the chat display.
- `/exit`: Disconnect from the network.

## 🔍 Troubleshooting

- **Tkinter Not Found**:
  - Linux: `sudo apt-get install python3-tk`
  - macOS/Windows: Install Python from [python.org](https://www.python.org) to include Tkinter.
- **Port 9999 Blocked**:
  - Linux: `sudo ufw allow 9999`
  - Windows: Allow port 9999 in Windows Firewall.
  - Try a different port if conflicts occur.
- **Dependency Issues**:
  - Update pip: `pip install --upgrade pip`
  - Ensure Python 3.8+: `python3 --version`
- **Messaging Problems**:
  - Check `secure_node_logs/*.log` for errors (set `DEBUG_MODE = True` in `nexlify.py`).
  - Verify host IP, port, passphrase, and token match.
  - Test with fewer clients if performance degrades (e.g., >20 users).
- **Font Fallback**:
  - Install JetBrains Mono for the optimal UI, or accept the default font.

## 🗂️ Logs

Debug logs are saved in `secure_node_logs/` with timestamps (e.g., `darkwire_20250508_*.log`). Enable `DEBUG_MODE = True` in `nexlify.py` for verbose output.

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m "Add your feature"`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a pull request with a detailed description.

Adhere to PEP 8 style guidelines and follow the [Code of Conduct](CODE_OF_CONDUCT.md) (coming soon).

## 📜 License

Nexlify is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 📬 Contact

For issues, feature requests, or feedback:
- Open a GitHub issue at [MOmar990/Nexlify](https://github.com/MOmar990/Nexlify/issues).
- Contact: [omarmajectytaher2@gmail.com](omarmajectytaher2@gmail.com).

## 🎉 Latest Release

[Nexlify v1.0.0](https://github.com/MOmar990/Nexlify/releases/tag/v1.0.0) - Initial release with secure messaging, end-to-end encryption, concurrent user support, and a cyberpunk-inspired UI.

## 🔮 Known Limitations

- **Scalability**: Single-threaded server supports up to 20 concurrent users, depending on hardware. Performance may degrade with more users; multi-threading or asyncio planned for future releases.
- **No Automated Tests**: Manual testing recommended for this release.
- **Font Dependency**: JetBrains Mono is optional; UI falls back to default font if unavailable.
- **Installation Wizard**: Requires manual virtual environment activation.

---

**Nexlify**: Secure. Sleek. Connected.  
