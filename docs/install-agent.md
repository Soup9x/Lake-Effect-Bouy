# Installing the ClamAV console agent

The agent runs on each client endpoint, asks the local clamd for its status (`PING` and `VERSION` only) and reports it to the console over outbound HTTPS. It never listens on a network port.

| | Linux | Windows |
|---|---|---|
| Runs as | systemd unit `clamav-agent`, user `clamav-agent` | service `ClamAVAgent`, virtual account `NT SERVICE\ClamAVAgent` |
| Binary | `/usr/local/bin/clamav-agent` | `%ProgramFiles%\ClamAVAgent\clamav-agent.exe` |
| Config | `/etc/clamav-agent/agent.yaml` (root, 0644, no secrets) | `%ProgramData%\ClamAVAgent\agent.yaml` (service: read only) |
| Credential | `/var/lib/clamav-agent/credential` (clamav-agent, 0600; dir 0700) | `%ProgramData%\ClamAVAgent\credential` (service + Administrators only) |
| Logs | journal: `journalctl -u clamav-agent` | `%ProgramData%\ClamAVAgent\logs\agent.log` (5 MB x 3), plus stderr |
| clamd | Unix socket (auto-detected) | `tcp://127.0.0.1:3310` (read from `clamd.conf`) |

## What you need

- The console URL, e.g. `https://console.example.com` (must be https).
- An enrollment token for the client's tenant (`cav_enr_...`), created in the console under *Tenant → Enrollment tokens*. It is shown once.
- ClamAV with clamd installed and running. (The agent still installs without it and reports `not_installed` / `not_responding`.)

## Linux

Supported: systemd distributions on amd64 and arm64. Run as root:

```sh
curl -fsSL https://console.example.com/downloads/install.sh -o install.sh
CAV_SERVER_URL=https://console.example.com CAV_ENROLL_TOKEN=cav_enr_... sh install.sh
```

Inputs (environment variables):

| Variable | Required | Meaning |
|---|---|---|
| `CAV_SERVER_URL` | yes | Console URL, `https://` only |
| `CAV_ENROLL_TOKEN` | to enroll | Enrollment token. Passed to the agent via the environment, never on a command line |
| `CAV_CLAMD_ADDR` | no | `unix:///path/to/clamd.sock` or `tcp://127.0.0.1:3310`. Default: first existing of `/run/clamav/clamd.ctl` (Debian/Ubuntu), `/run/clamd.scan/clamd.sock` (RHEL), `/var/run/clamav/clamd.ctl` |

What `install.sh` does:

1. Downloads `clamav-agent_linux_<arch>`, `clamav-agent.service` and their `.minisig` files from `$CAV_SERVER_URL/downloads/`.
2. **Verifies the minisign signatures** with the release public key embedded in the script (see below). Nothing is installed if verification fails.
3. Creates the system user `clamav-agent` (no login shell) and adds it to the group that owns the clamd socket.
4. Installs the binary, runs `clamav-agent enroll`, sets ownership/permissions, installs and starts the hardened systemd unit.

It is idempotent: running it again upgrades the binary and unit and keeps the existing enrollment (no token needed). `sh install.sh --reinstall` enrolls again with a new token and asks the console to replace this machine's previous agent.

Uninstall: `sh uninstall.sh` (or `--keep-data` to keep config and credential). Then revoke the endpoint in the console.

## Windows

Windows Server 2016+ / Windows 10+, amd64, Windows PowerShell 5.1 or PowerShell 7. In an elevated PowerShell:

```powershell
Invoke-WebRequest https://console.example.com/downloads/install.ps1 -OutFile install.ps1
$env:CAV_ENROLL_TOKEN = 'cav_enr_...'
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -ServerUrl https://console.example.com
```

Parameters: `-ServerUrl` (required, https), `-EnrollToken` (or `$env:CAV_ENROLL_TOKEN`; the environment variable keeps the token out of the process list), `-ClamdAddress` (default: `TCPAddr`/`TCPSocket` from `%ProgramFiles%\ClamAV\clamd.conf`, else `tcp://127.0.0.1:3310`), `-Reinstall`.

What `install.ps1` does:

1. Downloads `clamav-agent_windows_amd64.exe` and its `.minisig`.
2. **Verifies the minisign signature** with the embedded release public key. Windows has no built-in Ed25519 or BLAKE2b, so the script compiles a small C# verifier (`Add-Type`).
3. Installs the binary to `%ProgramFiles%\ClamAVAgent`, creates the `ClamAVAgent` service (automatic start) running as `NT SERVICE\ClamAVAgent`, recovery = restart on crash.
4. Sets ACLs on `%ProgramData%\ClamAVAgent` (inheritance disabled; Administrators full, SYSTEM on the folder only, service Modify so it can replace its credential atomically), enrolls, then locks the credential to the service account + Administrators and makes the config read-only for the service.
5. Starts the service and prints `clamav-agent status`.

> **Interim Windows verifier.** The inline C# minisign verifier in `install.ps1` is a stopgap until we have a Windows code-signing certificate. It is tested against the Project Wycheproof Ed25519 vectors and the BLAKE2b reference vectors on Windows PowerShell 5.1 and PowerShell 7 (`packaging/windows/tests/Test-Verifier.ps1`, run in CI). Once a certificate is in place, the Windows binary will be Authenticode-signed and `install.ps1` will verify it with `Get-AuthenticodeSignature` (status `Valid` and the expected signer certificate thumbprint) instead, and the inline verifier will be removed.

It is idempotent; `-Reinstall` enrolls again. Uninstall: `.\uninstall.ps1` (or `-KeepData`), then revoke the endpoint in the console.

clamd on Windows must listen on loopback. The agent refuses any clamd address other than `127.0.0.0/8`, `::1` or `localhost`.

## What the scripts verify, and the trust chain

Agent binaries are signed offline with a minisign (Ed25519) key that never touches the console server (see [release-signing.md](release-signing.md)). The public key is compiled into the agent and baked into both install scripts at build time; it is **never** fetched from the server. The scripts check the key id, the file signature (prehashed `ED` or legacy `Ed`) and the trusted-comment signature, and abort on any mismatch. On Linux they use the `minisign` CLI when installed, otherwise `openssl` 3.x + `b2sum`; if neither is available they abort.

The one-liners above fetch the install script itself from the console, so a compromised console could serve a modified script. For the strictest trust, deploy the install script from the signed release bundle (via your RMM or a file share) and check its own signature first with any minisign verifier, e.g. `minisign -Vm install.sh -P <release public key>`, or `clamav-agent verify install.sh install.sh.minisig` with an agent you already trust.

You can also check any downloaded file by hand:

```sh
sh install.sh --verify-only clamav-agent_linux_amd64 clamav-agent_linux_amd64.minisig
```
```powershell
.\install.ps1 -VerifyOnly -VerifyFile .\clamav-agent_windows_amd64.exe -VerifySignatureFile .\clamav-agent_windows_amd64.exe.minisig
```

## Checking status

- Linux: `sudo clamav-agent status`, `systemctl status clamav-agent`, `journalctl -u clamav-agent -f`
- Windows: `& "$env:ProgramFiles\ClamAVAgent\clamav-agent.exe" status`, `Get-Service ClamAVAgent`, `Get-Content $env:ProgramData\ClamAVAgent\logs\agent.log -Tail 50`

`status` shows the config, whether a credential is present (never its value) and a live clamd query. The console marks an endpoint offline after 3 minutes without a heartbeat.

## Troubleshooting

**clamd `not_responding` with "permission denied" (Linux).** The agent user must be in the group that owns the clamd socket. Check `ls -l /run/clamav/clamd.ctl` and `id clamav-agent`. If the socket's group is `root`, set `LocalSocketGroup` (e.g. `clamav`) and `LocalSocketMode 660` in `clamd.conf`, restart clamd, then rerun `install.sh` (or `usermod -aG <group> clamav-agent && systemctl restart clamav-agent`).

**clamd `not_installed`.** No clamd binary was found (`/usr/sbin/clamd`, `/usr/bin/clamd`, `/usr/local/sbin/clamd`, or `%ProgramFiles%\ClamAV\clamd.exe`) and clamd did not answer.

**Agent stopped with exit code 78.** Exit code 78 means the console revoked this agent (HTTP 401 with code `agent_revoked`), or the agent is not enrolled / its config is invalid. systemd (`RestartPreventExitStatus=78`) and the Windows service (stops with service-specific code 78, not treated as a crash) do **not** restart it. Check the log, then re-enroll with a new token: `install.sh --reinstall` / `install.ps1 -Reinstall`.

**Repeated "HEARTBEAT REJECTED WITH 401 (not a revocation)" in the log.** Any 401 other than `agent_revoked` (a proxy, a server bug, a credential the server does not recognise) is logged at error level and retried every 30 to 60 minutes; the agent keeps running so a server-side mistake cannot take down a fleet. Fix the server or proxy, or re-enroll if the credential is genuinely bad.

**Network errors / 5xx / 429.** Retried with exponential backoff from 60 s up to 5 minutes, then the normal interval resumes.

**Self-hosted or private CA.** The agent uses the system trust store. Optionally pin the console's certificate chain with `ca_cert_pin` (base64 SHA-256 of a SubjectPublicKeyInfo in the chain) in `agent.yaml`, or pass `--ca-cert-pin` to `clamav-agent enroll`. Compute it with:
`openssl x509 -in ca.pem -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`

**Proxy.** The agent honours `HTTPS_PROXY`/`NO_PROXY` (set them in a systemd drop-in, or in the service's environment on Windows).

**Signature verification failed.** Do not work around it. Either the download was corrupted or tampered with, or the server hosts a bundle signed with a different key than the one in your install script. Get a fresh install script from the signed release bundle.
