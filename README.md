# Cup and String P2P File Sync

Cup and String is a simple, secure peer-to-peer (P2P) file synchronization tool built in Go. It allows two users to share files directly over the internet or a local network without relying on having control of central servers. The tool uses freely available IRC (Internet Relay Chat) for peer discovery and libp2p for establishing secure P2P connections. It's designed for ease of use, with automatic setup and NAT traversal features to work behind firewalls and routers, but this does require elevated privileges to use.  If you do not have admin access to your machine, the automatic firewall and router configuration probably will not work.  This was written entirely by AI (mostly Grok and Claude) at my direction.  The code is free to use for whatever purposes

## Features
- **Direct P2P File Transfer**: Files are sent directly between peers using libp2p, with support for hole punching and relays for NAT traversal.
- **IRC-Based Discovery**: Peers find each other in a shared IRC channel using a configurable pairing secret for authentication.
- **Dual-Lane Transfer**: Separate "export" (outgoing) and "import" (incoming) folders for bidirectional syncing.
- **Filename Obfuscation**: Files are renamed to nondescript temporary names during transfer to enhance privacy, with a manifest file to restore original names on receipt.
- **Secure Connections**: Transfers use libp2p's built-in encryption (Noise protocol or TLS) for secure data transmission.
- **Automatic Setup**: Interactive wizard for configuration, with UPnP support for port forwarding and firewall rules on Windows.
- **Cross-Internet Compatibility**: Works over WAN with public IP detection and relays; fallback to LAN for local networks.

## Installation
1. Download the pre-built executable (`cupandstring.exe`) for Windows from
 	Dropbox: https://www.dropbox.com/scl/fi/hvpcba3qisqdk1oiw6l57/cupandstring.rar?rlkey=fqyw7yj020qur0wdqvb8pbo8y&st=rrwo4tbb&dl=0
2. Place it in a directory where you want to run the tool.
3. Right-click and run `cupandstring.exe` in administrator mode to start the setup wizard.

IMPORTANT: You must run 'cupandstring.exe' with administrative privileges if you want it to be able to open ports.  If not, you will need to open the ports and the firewall manually.


Note: Windows may flag the executable as suspicious because it is an unsigned binary from an unknown developer. This is a common false positive for custom tools—it performs no malicious actions, such as unauthorized access or data exfiltration. You can bypass the warning by clicking "More info" > "Run anyway," or add an exception in Windows Defender.  You don't have to trust me, have your favorite AI look at the project and sniff it out for nefarious bits. For peace of mind, compile from source yourself it is surprisingly easy with GO.

## Usage
Run the executable:
```
cupandstring.exe
```
The first run triggers an interactive setup wizard. Subsequent runs load the saved configuration from `mysetup.json`.

### Command-Line Options
- `-config <file>`: Specify a custom config file (default: `mysetup.json`).
  - Example: `cupandstring.exe -config customsetup.json`
- `-setup`: Force the setup wizard even if a config file exists (useful for reconfiguration).
  - Example: `cupandstring.exe -setup`

### Configuration with `mysetup.json`
The configuration is stored in a JSON file (`mysetup.json` by default). You can edit it manually with a text editor to tweak settings without rerunning the wizard. If you delete or rename the file, the next run will trigger the setup wizard automatically.

Most of these settings you can use the defaults and it will run fine

You WILL need to have a custom username and recipient name... and a shared secret password
these three things must match!!!  Case matters! 

#### Settings Explanation
- **`export_folder`**: Path to the folder where you place files to send (outgoing). Files added here are automatically queued for transfer to the recipient.  
- **`import_folder`**: Path to the folder where received files are saved (incoming).
 During auto-config, these folders will be created if they do not exist, if you move the folder containing this software, the stored path will be incorrect and will cause crashes when autoloading the settings.  Delete the settings file and start the program again, or edit the settings file manually to reflect the new import/export locations.  You can change these locations to be anywhere on your computer, independant of where the program itself resides.


- **`irc_server`**: IRC server hostname for peer discovery (default: `irc.libera.chat`).
	any free pubic IRC server will do, there are many.
- **`irc_port`**: IRC server port (default: 6697 for TLS).
- **`channel_name`**: IRC channel where peers rendezvous (default: `cupandstring`). Use a unique name to avoid busy channels.
- **`tls`**: Enable TLS for secure IRC connections (default: true).
- **`your_username`**: Just a short name for yourself, between 3 and 10 characters
- **`recipient_username`**: the name your intended recipient chose for themselves when answering the last question
- **`local_port`**: Local TCP port for libp2p listening (default: 4200). The app auto-finds a free port if busy.
- **`external_ip`**: Your public IP (WAN) or local IP (LAN). Auto-detected, but editable for manual override.  
- **`pairing_secret`**: Shared secret for authenticating peers (default: "Practice"). Peers challenge each other with "What are we talking about?" and respond with this secret.  If they have the same secret, then they exchange connection information and begin trading files.

After editing, restart the app to apply changes.

## How It Works
### Dual Lanes of Transfer
The tool supports bidirectional file syncing:
- **Export (Sending)**: Drop files into the export folder. They are copied to a temp dir, hashed, and queued. When a peer connects, files are sent in batches.
- **Import (Receiving)**: Files arrive in the import folder. Duplicates are detected via hashes and declined to avoid redundancy.

Transfers are triggered when files are present in the export queue, activating IRC scanning to find the recipient.

### Filename Obfuscation and Manifest
To protect privacy during transfer:
- Files are renamed to generic names like `data_<short_hash>.bin`.
- A JSON manifest is sent first, containing original names, temp names, and hashes.
- On receipt, the manifest restores original filenames. Partial transfers are cleaned up (`.part` files deleted).

This obfuscation prevents eavesdroppers from inferring file contents from names.

### Encryption During Transfer
All P2P data is encrypted using libp2p's secure transport protocols (Noise or TLS). Connections are authenticated and encrypted end-to-end, ensuring files remain confidential in transit. No custom encryption is applied beyond libp2p's built-in security.

### NAT Traversal
- UPnP for automatic port forwarding on supported routers.
- Hole punching via libp2p.
- Fallback to public relays (IPFS bootstrap nodes) if direct connection fails.

## Building from Source
Requires Go 1.22+.
```
go mod tidy
go build -o cupandstring.exe
```

## Troubleshooting
- **Busy IRC Channel**: If >5 users, consider a unique `channel_name`.
- **Connection Issues**: Ensure port forwarding (manual if UPnP fails) and matching configs/secrets between peers.
- **Windows Firewall**: The app auto-creates rules, but check if blocked.
- **Logs**: Check console/timestamps for errors.

## License
MIT License. See LICENSE file (if included) or assume open-source for personal use.

For issues or contributions, open a GitHub issue (repository not specified).
