# go-tangra-client

Linux agent that unifies two infrastructure functions: **IPAM device sync** and **LCM certificate management**. Runs as a systemd daemon or one-shot CLI tool.

## Features

- **Device Registration & Sync** — Collects hostname, IPs, CPUs, memory, disks, NICs, board/BIOS info and syncs with IPAM
- **VM/Container Detection** — Identifies KVM, VMware, Hyper-V, WSL2, Docker, LXC, etc.
- **Auto-create Subnets & IPs** — Reports host CIDRs and ensures subnets/IP records exist in IPAM
- **Certificate Streaming** — Streams real-time certificate updates from LCM with automatic renewal
- **Deploy Hooks** — Executes Bash, Lua, or JavaScript hooks after certificate updates
- **Auto-Registration** — Registers with LCM server using shared secret when no credentials exist
- **Systemd Integration** — Runs as a hardened daemon with security restrictions

## Commands

```bash
# Register client with LCM server
tangra-client register --secret my-shared-secret

# One-time IPAM device sync
tangra-client sync --tenant-id 1

# Dry run — show what would be synced
tangra-client sync --tenant-id 1 --dry-run

# Start daemon (IPAM + LCM continuous sync)
tangra-client daemon --tenant-id 1

# Daemon with auto-registration
tangra-client daemon --tenant-id 1 --secret my-shared-secret

# Show client status and diagnostics
tangra-client status
```

## Configuration

Config file at `/etc/tangra-client/config.yaml`:

```yaml
server: "lcm.example.com:9100"
ipam-server: "ipam.example.com:9400"
tenant-id: 1
cert: "/etc/tangra-client/client.crt"
key: "/etc/tangra-client/client.key"
ca: "/etc/tangra-client/ca.crt"
config-dir: "/etc/tangra-client"
```

## Deploy Hooks

After a certificate is installed or renewed, the daemon can invoke a hook so you can reload services (nginx, haproxy, postfix, …), push the new material to other hosts, or run custom validation.

### Configuration

Hooks are configured via daemon flags (no config-file keys yet):

| Flag | Description | Default |
|---|---|---|
| `--deploy-hook` | Path to a Bash script | unset |
| `--deploy-script-hook` | Path to a `.lua` or `.js` script | unset |
| `--hook-timeout` | Max execution time | `5m` |

`--deploy-hook` and `--deploy-script-hook` are independent — only one is typically set. If both are set, the Bash hook runs and the script hook is ignored.

```bash
tangra-client daemon --tenant-id 1 \
  --deploy-hook /etc/tangra-client/hooks/reload-nginx.sh \
  --hook-timeout 2m
```

### Hook types

| Type | When it fires | Status |
|---|---|---|
| `deploy` | After a new or renewed cert is written to disk | implemented |
| `pre-renewal` | Before the client requests a renewal | declared, not yet wired |
| `post-renewal` | After renewal completes | declared, not yet wired |

The hook receives `LCM_IS_RENEWAL=true` when invoked for a renewal and `false` for initial issuance; use that to branch behaviour inside a single `deploy` hook rather than registering separate scripts.

### Execution context

The same data is passed to every hook — as environment variables to Bash, and as globals + a `LCM_CONTEXT` object to Lua/JS:

| Variable | Description |
|---|---|
| `LCM_HOOK_TYPE` | `deploy` / `pre-renewal` / `post-renewal` |
| `LCM_CERT_NAME` | Cert identifier (used as the on-disk directory name) |
| `LCM_CERT_PATH` | Path to the leaf certificate PEM |
| `LCM_KEY_PATH` | Path to the private key PEM (mode 0600) |
| `LCM_CHAIN_PATH` | Path to the intermediate chain PEM |
| `LCM_FULLCHAIN_PATH` | Path to `leaf + chain` (what most servers want) |
| `LCM_COMMON_NAME` | Subject CN |
| `LCM_DNS_NAMES` | Comma-separated SANs |
| `LCM_IP_ADDRESSES` | Comma-separated IP SANs |
| `LCM_SERIAL_NUMBER` | Certificate serial |
| `LCM_EXPIRES_AT` | RFC3339 expiry timestamp |
| `LCM_IS_RENEWAL` | `true` / `false` |

Bash hooks run with `cmd.Dir` set to the script's parent directory (override with `WorkDir` in code). Lua and JavaScript scripts are executed via [go-scripts](https://github.com/tx7do/go-scripts) engine pools (lazy-initialised, 1–5 engines per type).

### Helper functions (Lua / JavaScript only)

| Function | Signature | Notes |
|---|---|---|
| `exec(command)` | `(string) -> (string, error)` | Runs via `sh -c`; returns combined stdout+stderr |
| `readFile(path)` | `(string) -> (string, error)` | |
| `writeFile(path, content)` | `(string, string) -> error` | Writes with mode 0644 |
| `fileExists(path)` | `(string) -> bool` | |
| `getEnv(key)` | `(string) -> string` | |
| `log(msg)` | `(string) -> ()` | Prints to daemon stdout |

### Examples

**Bash — reload nginx after deploy or renewal**

```bash
#!/usr/bin/env bash
set -euo pipefail

logger -t tangra-client "deploying $LCM_CERT_NAME (renewal=$LCM_IS_RENEWAL)"

nginx -t && systemctl reload nginx
```

**Lua — conditional post-renewal action**

```lua
log("hook fired for " .. LCM_CERT_NAME)

if LCM_IS_RENEWAL then
  local out, err = exec("systemctl reload haproxy")
  if err ~= nil then
    log("reload failed: " .. tostring(err))
    error(err)
  end
  log(out)
end
```

**JavaScript — push cert to a remote peer**

```js
if (LCM_CONTEXT.isRenewal) {
  const out = exec(
    `scp ${LCM_FULLCHAIN_PATH} ${LCM_KEY_PATH} peer:/etc/ssl/private/`
  );
  log(out);
}
```

### Result handling & observability

A hook is considered failed if the script exits non-zero, times out, or (for Lua/JS) raises. Failures are logged with exit code and stderr; they do **not** roll back the deployed cert — the new material is already on disk before the hook runs. On success, `last_hook_execution` is recorded in the per-cert metadata, visible via `tangra-client status`.

If nginx is detected on the host and no explicit hook is configured, the daemon also runs its built-in nginx auto-deployer (see `internal/nginx/`). The deploy hook runs first; nginx auto-deploy runs second.

## Installation

```bash
# Build and install (requires root)
make install

# Or build packages
make package VERSION=1.0.0 ARCH=amd64

# Enable systemd service
systemctl enable --now tangra-client
```

## Build

```bash
make build          # Build binary
make tidy           # Tidy Go modules
make package        # Build .deb and .rpm packages
make clean          # Remove build artifacts
```

## CI/CD

GitHub Actions release workflow triggers on `v*` tags. Builds static binaries and `.deb`/`.rpm` packages for amd64 and arm64, then creates a GitHub Release.

## Architecture

```
cmd/
├── daemon/     # Continuous sync (IPAM + LCM goroutines with errgroup)
├── sync/       # One-shot IPAM sync
├── register/   # Client registration
└── status/     # Diagnostics
internal/
├── machine/    # System info collection (CPU, memory, disks, NICs, DMI, VM detection)
├── ipam/       # Device sync, subnet/IP auto-creation, change detection
├── lcm/        # Certificate streaming and syncing
├── storage/    # Persistent state (certbot-like cert store + device state)
├── hook/       # Deploy hook execution (Bash/Lua/JS)
└── registration/ # Shared registration logic
```

## Security

- All server communication uses mTLS
- Private keys stored with mode 0600
- Systemd hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`
- Hook execution with configurable timeout (default 5 minutes)
