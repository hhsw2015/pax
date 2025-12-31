# Pax - Automated SSH SOCKS5 Proxy

Pax is a lightweight Rust tool designed to **replace manual SSH SOCKS5 commands** (e.g., `ssh -D 1080 ...`). instead of hardcoding credentials, Pax fetches them dynamically from a remote API, establishes the tunnel, and keeps it alive.

## Why use Pax?

| **Manual Method** | **Pax** |
| :--- | :--- |
| You run `ssh -D 1080 -N -C user@host` | Pax runs this automatically in the background. |
| Credentials are static or typed manually | Credentials are fetched from a JSON API (Auto-rotate). |
| Connection drops? You must restart it | **Auto-reconnects** immediately upon failure. |
| Complex private key management | Handles **Local Keys** & **API-provided Keys** (Raw content). |

## Features

*   **Dynamic Config**: Fetches Host, User, Port, Password/Key from a URL.
*   **Auto-Healing**: Detects SSH disconnects (Timeout, EOF) and restarts.
*   **Expiration Aware**: Alerts you if the account is expiring soon (<24h).
*   **Smart Auth**: Supports Password, Local Key paths, and Raw Key content (temp files).
*   **Zero-Config CLI**: Just run it, or override specific settings via flags.

## Usage

### 1. Build & Run
```bash
cargo run --release
```

### 2. Command Line Arguments
```bash
# Default behavior (uses default API)
./pax

# Use a custom API endpoint (e.g., local python server or Gist)
./pax --api "http://127.0.0.1:8000/config.json"

# Force use of a local private key (Overrides API auth)
# This is useful if the API provides the IP/User, but you use your own key.
./pax -k "/Users/me/.ssh/id_rsa"

# Change local SOCKS5 port (Default: 1080)
./pax --local-port 2080
```

## API Response Format

Pax expects the remote URL to return a single JSON object.

### Mode A: Password Authentication
```json
{
  "auth_type": "password",
  "host": "1.2.3.4",
  "port": "22",
  "user": "root",
  "password": "my_secret_password",
  "exp_at": "2025-12-31 23:59:59"
}
```

### Mode B: Private Key Authentication
The `private_key` field supports **File Paths** OR **Raw Key Content**.

```json
{
  "auth_type": "key",
  "host": "1.2.3.4",
  "user": "root",
  // Option 1: Absolute path to a local file
  "private_key": "/home/user/.ssh/id_rsa",
  // Option 2: Raw PEM content (Pax creates a secure temp file automatically)
  // "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "password": "passphrase_if_needed"
}
```

## Requirements
*   **OS**: Linux, macOS, or Windows (with OpenSSH Client installed).
*   **Runtime**: The `ssh` command must be available in your `$PATH`.
