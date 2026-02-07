#!/bin/sh
set -e

systemctl daemon-reload

echo ""
echo "tangra-client installed successfully!"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/tangra-client/config.yaml"
echo "  2. Register or place mTLS certs in /etc/tangra-client/"
echo "  3. systemctl enable --now tangra-client"
echo ""
