-- Example tangra-client deploy hook (Lua): dump every hook variable
-- into a timestamped file.
--
-- Wire up via:
--   tangra-client daemon --deploy-script-hook /path/to/dump-vars.lua
--
-- All LCM_* values are registered as globals by the hook runner
-- (see internal/hook/hook.go:registerHookContext). The `writeFile`
-- helper is also injected — it accepts (path, content) and returns
-- an error if the write fails.
--
-- NOTE: The systemd unit ships with PrivateTmp=true, which hides
-- /tmp from outside the service. We write under the config
-- directory instead — /etc/tangra-client/ is writable on every
-- released unit version, so the hook works regardless of whether
-- the operator has the latest systemd unit installed.

exec("mkdir -p /etc/tangra-client/hook-logs")

local timestamp = os.date("%Y%m%d-%H%M%S")
local out = "/etc/tangra-client/hook-logs/hook-lua." .. timestamp .. ".log"

local lines = {
  "=== tangra-client deploy hook (lua) ===",
  "fired_at: " .. os.date("!%Y-%m-%dT%H:%M:%SZ"),
  "",
  "hook_type:      " .. tostring(LCM_HOOK_TYPE),
  "cert_name:      " .. tostring(LCM_CERT_NAME),
  "common_name:    " .. tostring(LCM_COMMON_NAME),
  "dns_names:      " .. tostring(LCM_DNS_NAMES),
  "ip_addresses:   " .. tostring(LCM_IP_ADDRESSES),
  "serial_number:  " .. tostring(LCM_SERIAL_NUMBER),
  "expires_at:     " .. tostring(LCM_EXPIRES_AT),
  "is_renewal:     " .. tostring(LCM_IS_RENEWAL),
  "",
  "cert_path:      " .. tostring(LCM_CERT_PATH),
  "key_path:       " .. tostring(LCM_KEY_PATH),
  "chain_path:     " .. tostring(LCM_CHAIN_PATH),
  "fullchain_path: " .. tostring(LCM_FULLCHAIN_PATH),
}

writeFile(out, table.concat(lines, "\n") .. "\n")
log("wrote " .. out)
