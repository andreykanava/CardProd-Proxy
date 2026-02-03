#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
WG_IFACE="${WG_IFACE:-wg0}"

CONTROLLER_URL="${CONTROLLER_URL:-}"
JOIN_TOKEN="${JOIN_TOKEN:-}"
NODE_ID="${NODE_ID:-}"

if [ -z "$CONTROLLER_URL" ] || [ -z "$JOIN_TOKEN" ] || [ -z "$NODE_ID" ]; then
  echo "Missing env: CONTROLLER_URL, JOIN_TOKEN, NODE_ID"
  exit 1
fi

mkdir -p "$DATA_DIR" /etc/wireguard

KEY_PRIV="$DATA_DIR/proxy.key"
KEY_PUB="$DATA_DIR/proxy.pub"
JOIN_FILE="$DATA_DIR/join.json"

# ---------- keys ----------
if [ ! -f "$KEY_PRIV" ] || [ ! -f "$KEY_PUB" ]; then
  echo "[*] Generating WireGuard keypair for proxy..."
  umask 077
  wg genkey | tee "$KEY_PRIV" | wg pubkey > "$KEY_PUB"
fi

PROXY_PUBKEY="$(cat "$KEY_PUB")"
export PROXY_PUBKEY

# ---------- join controller ----------
echo "[*] Proxy joining controller..."
python3 - <<'PY'
import os, time, requests, sys

url = os.environ["CONTROLLER_URL"].rstrip("/") + "/join"
hdr = {"X-Join-Token": os.environ["JOIN_TOKEN"]}
payload = {
    "node_id": os.environ["NODE_ID"],
    "node_pubkey": os.environ["PROXY_PUBKEY"],
}

for attempt in range(1, 11):
    try:
        r = requests.post(url, json=payload, headers=hdr, timeout=20)
        if r.status_code >= 400:
            print(r.text, file=sys.stderr)
            r.raise_for_status()
        open("/data/join.json", "w").write(r.text)
        print("[*] Proxy join OK")
        break
    except Exception as e:
        print(f"[!] join attempt {attempt}/10 failed: {e}", file=sys.stderr)
        time.sleep(2)
else:
    raise SystemExit("Proxy join failed")
PY

PROXY_IP="$(python3 -c 'import json; print(json.load(open("/data/join.json"))["node_ip"])')"
CTRL_PUB="$(python3 -c 'import json; print(json.load(open("/data/join.json"))["controller_pubkey"])')"
ENDPOINT="$(python3 -c 'import json; print(json.load(open("/data/join.json"))["endpoint"])')"
ALLOWED="$(python3 -c 'import json; print(json.load(open("/data/join.json"))["allowed_ips"])')"

if [ -z "$ENDPOINT" ] || [ "$ENDPOINT" = "None" ]; then
  echo "Controller did not provide WG_ENDPOINT"
  exit 1
fi

PRIVKEY="$(cat "$KEY_PRIV")"

# ---------- write wg config ----------
cat > "/etc/wireguard/${WG_IFACE}.conf" <<EOF
[Interface]
Address = ${PROXY_IP}/32
PrivateKey = ${PRIVKEY}

[Peer]
PublicKey = ${CTRL_PUB}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED}
PersistentKeepalive = 25
EOF

# ---------- bring up wg ----------
echo "[*] Bringing up WireGuard (${WG_IFACE})..."
wg-quick down "${WG_IFACE}" >/dev/null 2>&1 || true
wg-quick up "${WG_IFACE}"

echo "[*] wg show:"
wg show "${WG_IFACE}" || true

# ---------- keep container alive ----------
echo "[*] Edge net ready. Keeping container alive..."
exec sleep infinity
