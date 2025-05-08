# Nexlify

Nexlify is a secure, peer-to-peer messaging application built with Python and Tkinter. Featuring end-to-end encryption, customizable codenames, and a cyberpunk-inspired interface, Nexlify ensures private and reliable communication for both local and networked environments. It supports host-client architecture, stealth mode for anonymized messaging, and optional message compression.

## Features

- **End-to-End Encryption**: Messages are encrypted using AES-GCM with a shared passphrase and token.
- **Host or Client Mode**: Run as a host to accept connections or as a client to join a network.
- **Stealth Mode**: Anonymize your identity with hashed codenames.
- **Message Compression**: Optional zlib compression for efficient data transfer.
- **Cyberpunk UI**: Sleek, neon-themed Tkinter interface with JetBrains Mono font.
- **Commands**: Supports `/ping`, `/who`, `/ghost`, `/compress`, and more for enhanced control.
- **Robust Logging**: Detailed logs for debugging and monitoring.

## Installation

### Prerequisites

- Python 3.8 or higher
- Tkinter (included with Python or install via `sudo apt-get install python3-tk` on Debian/Ubuntu)
- JetBrains Mono font (optional, for optimal UI experience)

### Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/Python-Chat.git
   cd Python-Chat
   ```

2. **Set Up a Virtual Environment** (recommended):
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

## Usage

### Running as a Host

1. Launch Nexlify and select **Initialize Node (Host)**.
2. Enter a codename (or use "random"), a passphrase, and a port (default: 9999).
3. Note the generated authentication token.
4. Share the passphrase, port, and token with clients.
5. Start chatting once clients connect.

### Running as a Client

1. Launch Nexlify and select **Connect to Node (Client)**.
2. Enter a codename, the host's IP (e.g., `127.0.0.1` for local), port, passphrase, and token.
3. Connect and start messaging.

### Commands

- `/ping`: Check latency to the host (client only).
- `/who`: List connected clients.
- `/ghost`: Toggle stealth mode.
- `/compress`: Toggle message compression.
- `/clear`: Clear the chat window.
- `/exit`: Disconnect and return to the mode selection screen.

## Logs

Logs are stored in the `secure_node_logs/` directory with timestamps (e.g., `darkwire_20250508_*.log`). Enable debug mode in `nexlify.py` (`DEBUG_MODE = True`) for verbose logging.

## Contributing

We welcome contributions to Nexlify! To contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request with a clear description.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) and ensure your code adheres to PEP 8 style guidelines.

## License

Nexlify is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contact

For issues or feature requests, open a GitHub issue or contact the maintainers at [your.email@example.com](mailto:your.email@example.com).

---

Built with 💾 and 🔒 by the Nexlify Team