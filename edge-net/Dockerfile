FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl iproute2 iptables wireguard-tools \
    python3 python3-venv python3-pip \
 && rm -rf /var/lib/apt/lists/*

# venv
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir \
    requests \
    fastapi \
    "uvicorn[standard]"

ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

CMD ["./entrypoint.sh"]
