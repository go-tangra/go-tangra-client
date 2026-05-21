// Example tangra-client deploy hook (JavaScript): dump every hook
// variable into a timestamped file.
//
// Wire up via:
//   tangra-client daemon --deploy-script-hook /path/to/dump-vars.js
//
// All LCM_* values are registered as globals by the hook runner
// (see internal/hook/hook.go:registerHookContext). The `writeFile`
// helper is also injected — it accepts (path, content) and returns
// an error if the write fails.
//
// NOTE: The systemd unit ships with PrivateTmp=true, which gives
// the daemon its own /tmp namespace invisible to other processes.
// We write under /var/log/tangra-client/ instead — /var is in
// ReadWritePaths and the directory is visible from any shell.

exec('mkdir -p /var/log/tangra-client');

var d = new Date();
var pad = function (n) { return (n < 10 ? '0' : '') + n; };
var timestamp =
  d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) + '-' +
  pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds());

var out = '/var/log/tangra-client/hook-js.' + timestamp + '.log';

var lines = [
  '=== tangra-client deploy hook (javascript) ===',
  'fired_at: ' + d.toISOString(),
  '',
  'hook_type:      ' + LCM_HOOK_TYPE,
  'cert_name:      ' + LCM_CERT_NAME,
  'common_name:    ' + LCM_COMMON_NAME,
  'dns_names:      ' + LCM_DNS_NAMES,
  'ip_addresses:   ' + LCM_IP_ADDRESSES,
  'serial_number:  ' + LCM_SERIAL_NUMBER,
  'expires_at:     ' + LCM_EXPIRES_AT,
  'is_renewal:     ' + LCM_IS_RENEWAL,
  '',
  'cert_path:      ' + LCM_CERT_PATH,
  'key_path:       ' + LCM_KEY_PATH,
  'chain_path:     ' + LCM_CHAIN_PATH,
  'fullchain_path: ' + LCM_FULLCHAIN_PATH,
];

writeFile(out, lines.join('\n') + '\n');
log('wrote ' + out);
