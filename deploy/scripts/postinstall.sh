#!/bin/sh
set -e

systemctl daemon-reload
# Apply unit changes on upgrade (no-op on first install or when inactive).
systemctl try-restart tangra-client.service 2>/dev/null || true

echo ""
echo "tangra-client installed successfully!"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/tangra-client/config.yaml"
echo "  2. Register or place mTLS certs in /etc/tangra-client/"
echo "  3. systemctl enable --now tangra-client"
echo ""
