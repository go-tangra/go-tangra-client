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
# NOTE: The systemd unit ships with PrivateTmp=true, which gives the
# daemon its own /tmp namespace invisible to other processes. We
# write under /var/log/tangra-client/ instead — /var is already in
# ReadWritePaths so the sandbox allows it, and the directory is
# visible from any shell without sudo gymnastics.

set -euo pipefail

logdir="/var/log/tangra-client"
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
