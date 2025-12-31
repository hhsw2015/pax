use crate::config::{SshConfig, AuthType};
use anyhow::{anyhow, Result};
use expectrl::{Eof, Regex, Session};
use std::process::Command;
use tracing::{info, warn};

/// Starts the SSH process using `expectrl`.
/// Assumes `config.private_key` is a valid file path if AuthType is Key.
pub fn start_ssh_process(local_port: u16, config: &SshConfig) -> Result<()> {
    let mut cmd = Command::new("ssh");

    cmd.arg("-D").arg(local_port.to_string())
       .arg("-N") // Do not execute a remote command
       .arg("-C") // Compression
       .arg("-v") // Verbose
       .arg("-o").arg("StrictHostKeyChecking=no")
       .arg("-o").arg("UserKnownHostsFile=/dev/null")
       .arg("-o").arg("ServerAliveInterval=15")
       .arg("-o").arg("ConnectTimeout=10");

    if config.auth_type == AuthType::Key {
        if let Some(ref key_path) = config.private_key {
            info!("Using private key: {}", key_path);
            cmd.arg("-i").arg(key_path);
        }
    }

    cmd.arg("-p").arg(&config.port)
       .arg(format!("{}@{}", config.user, config.host));

    info!("Executing SSH process...");

    let mut p = Session::spawn(cmd).map_err(|e| anyhow!("Failed to spawn SSH: {}", e))?;

    // Interaction loop
    loop {
        let output = p.expect(Regex("password:|Enter passphrase|Connection refused|timed out|denied"))
            .map_err(|e| anyhow!("Interaction error: {}", e))?;

        let match_str = String::from_utf8_lossy(output.get(0).unwrap_or(&[]));
        let buf_str = String::from_utf8_lossy(output.before());

        // A. Password prompt
        if match_str.contains("password:") {
            if config.auth_type == AuthType::Password {
                if let Some(ref pwd) = config.password {
                    info!("Sending password...");
                    p.send_line(pwd)?;
                    break;
                } else {
                    return Err(anyhow!("Server asked for password but none provided!"));
                }
            } else {
                return Err(anyhow!("Server asked for password, but AuthType is Key."));
            }
        }

        // B. Key Passphrase prompt
        if match_str.contains("Enter passphrase") {
            info!("Key passphrase required.");
            if let Some(ref pwd) = config.password {
                info!("Sending passphrase...");
                p.send_line(pwd)?;
                break;
            } else {
                 return Err(anyhow!("Passphrase required but 'password' field is empty!"));
            }
        }

        // C. Errors
        if buf_str.contains("Connection refused") || buf_str.contains("timed out") {
            return Err(anyhow!("Connection failed (Refused/Timeout)"));
        }

        if buf_str.contains("denied") {
            return Err(anyhow!("Permission denied (Wrong password/key?)"));
        }
    }

    info!("Tunnel established. SOCKS5: 127.0.0.1:{}", local_port);

    match p.expect(Eof) {
        Ok(_) => {
            warn!("SSH process exited (EOF).");
            Err(anyhow!("SSH exited normally"))
        }
        Err(e) => Err(anyhow!("Monitor error: {}", e)),
    }
}
