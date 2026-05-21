#!/usr/bin/env bash
#
# Example tangra-client deploy hook: dump every hook variable into a
# timestamped file so an operator can inspect what the agent passed
# on the most recent cert update.
#
# Wire up via:
#   tangra-client daemon --deploy-hook /path/to/dump-vars.sh
#
# All LCM_* variables come from the agent's hook runner — see
# internal/hook/hook.go:buildEnvVars for the full list.
#
# NOTE: The systemd unit ships with PrivateTmp=true, which hides /tmp
# from outside the service. We write under the config directory
# instead — /etc/tangra-client/ is writable on every released unit
# version (it's where the daemon stores live/, registration metadata,
# and self-updates), so the hook works regardless of whether the
# operator has the latest systemd unit installed.

set -euo pipefail

logdir="/etc/tangra-client/hook-logs"
mkdir -p "$logdir"
out="$logdir/hook-bash.$(date +%Y%m%d-%H%M%S).log"

{
  echo "=== tangra-client deploy hook (bash) ==="
  echo "fired_at: $(date -Iseconds)"
  echo
  echo "hook_type:      ${LCM_HOOK_TYPE:-}"
  echo "cert_name:      ${LCM_CERT_NAME:-}"
  echo "common_name:    ${LCM_COMMON_NAME:-}"
  echo "dns_names:      ${LCM_DNS_NAMES:-}"
  echo "ip_addresses:   ${LCM_IP_ADDRESSES:-}"
  echo "serial_number:  ${LCM_SERIAL_NUMBER:-}"
  echo "expires_at:     ${LCM_EXPIRES_AT:-}"
  echo "is_renewal:     ${LCM_IS_RENEWAL:-}"
  echo
  echo "cert_path:      ${LCM_CERT_PATH:-}"
  echo "key_path:       ${LCM_KEY_PATH:-}"
  echo "chain_path:     ${LCM_CHAIN_PATH:-}"
  echo "fullchain_path: ${LCM_FULLCHAIN_PATH:-}"
} > "$out"

echo "wrote $out"
