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
