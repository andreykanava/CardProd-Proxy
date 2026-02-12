cd ~/CardProd-Proxy
mkdir -p bind9/keys
tsig-keygen -a hmac-sha256 acme-key > bind9/keys/tsig.key
