FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools iproute2 iptables ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

CMD ["./entrypoint.sh"]
