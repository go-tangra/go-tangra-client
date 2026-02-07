#!/bin/sh
set -e

if systemctl is-active --quiet tangra-client 2>/dev/null; then
    systemctl stop tangra-client
fi

if systemctl is-enabled --quiet tangra-client 2>/dev/null; then
    systemctl disable tangra-client
fi
