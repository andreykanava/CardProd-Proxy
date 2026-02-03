#!/usr/bin/env bash
set -euo pipefail

WG_IFACE="${WG_IFACE:-wg0}"

echo "[*] Bringing up WireGuard ${WG_IFACE}..."
wg-quick down "${WG_IFACE}" >/dev/null 2>&1 || true
wg-quick up "${WG_IFACE}"

echo "[*] wg show:"
wg show "${WG_IFACE}" || true

# keep netns alive
tail -f /dev/null
