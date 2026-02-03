from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Literal, List

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

APP_TOKEN = os.environ.get("AGENT_TOKEN", "")
TRAEFIK_DYNAMIC_DIR = Path(os.environ.get("TRAEFIK_DYNAMIC_DIR", "/etc/traefik/dynamic")).resolve()
STATE_FILE = Path(os.environ.get("STATE_FILE", "/data/state.json")).resolve()

TRAEFIK_ENTRYPOINT = os.environ.get("TRAEFIK_ENTRYPOINT", "websecure")
TRAEFIK_CERTRESOLVER = os.environ.get("TRAEFIK_CERTRESOLVER", "dnsresolver")

app = FastAPI(title="Edge Proxy Agent", version="0.1.0")


def require_token(x_agent_token: str):
    if not APP_TOKEN:
        raise HTTPException(status_code=500, detail="AGENT_TOKEN not set")
    if x_agent_token != APP_TOKEN:
        raise HTTPException(status_code=403, detail="forbidden")


def sh_ok(*args: str) -> None:
    subprocess.run(list(args), check=True)


def ensure_forwarding_enabled() -> None:
    try:
        sh_ok("sysctl", "-w", "net.ipv4.ip_forward=1")
    except Exception:
        pass


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {"http_routes": {}, "tcp_forwards": {}}
    return json.loads(STATE_FILE.read_text())


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True))


def traefik_write_yaml(route_id: str, yaml_text: str) -> Path:
    TRAEFIK_DYNAMIC_DIR.mkdir(parents=True, exist_ok=True)
    p = TRAEFIK_DYNAMIC_DIR / f"{route_id}.yml"
    p.write_text(yaml_text)
    return p


def traefik_delete_yaml(route_id: str) -> None:
    p = TRAEFIK_DYNAMIC_DIR / f"{route_id}.yml"
    if p.exists():
        p.unlink()


def iptables_rule_exists(table: str, chain: str, rule_parts: List[str]) -> bool:
    try:
        sh_ok("iptables", "-t", table, "-C", chain, *rule_parts)
        return True
    except subprocess.CalledProcessError:
        return False


def iptables_add_unique(table: str, chain: str, rule_parts: List[str]) -> None:
    if not iptables_rule_exists(table, chain, rule_parts):
        sh_ok("iptables", "-t", table, "-A", chain, *rule_parts)


def iptables_del_if_exists(table: str, chain: str, rule_parts: List[str]) -> None:
    if iptables_rule_exists(table, chain, rule_parts):
        sh_ok("iptables", "-t", table, "-D", chain, *rule_parts)


class HttpRouteCreate(BaseModel):
    route_id: str = Field(..., examples=["vm-123"])
    hostname: str = Field(..., examples=["vm-123.service.com"])
    target_url: str = Field(..., examples=["http://10.50.0.12:8080"])
    entrypoint: str = Field(default=TRAEFIK_ENTRYPOINT)
    certresolver: str = Field(default=TRAEFIK_CERTRESOLVER)


class TcpForwardCreate(BaseModel):
    forward_id: str = Field(..., examples=["vm-123-ssh"])
    public_port: int = Field(..., ge=1, le=65535, examples=[22015])
    target_ip: str = Field(..., examples=["10.50.0.12"])     # WG-IP ноды
    target_port: int = Field(..., ge=1, le=65535, examples=[32215])  # порт на ноде
    proto: Literal["tcp"] = "tcp"


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/http/routes")
def create_http_route(payload: HttpRouteCreate, x_agent_token: str = Header(default="")):
    require_token(x_agent_token)

    if "://" not in payload.target_url:
        raise HTTPException(status_code=400, detail="target_url must include scheme (http://...)")

    yml = f"""http:
  routers:
    {payload.route_id}:
      rule: "Host(`{payload.hostname}`)"
      entryPoints: ["{payload.entrypoint}"]
      tls:
        certResolver: "{payload.certresolver}"
      service: {payload.route_id}-svc

  services:
    {payload.route_id}-svc:
      loadBalancer:
        servers:
          - url: "{payload.target_url}"
"""
    traefik_write_yaml(payload.route_id, yml)

    st = load_state()
    st["http_routes"][payload.route_id] = payload.model_dump()
    save_state(st)

    return {"ok": True, "route_id": payload.route_id}


@app.delete("/http/routes/{route_id}")
def delete_http_route(route_id: str, x_agent_token: str = Header(default="")):
    require_token(x_agent_token)

    traefik_delete_yaml(route_id)
    st = load_state()
    st["http_routes"].pop(route_id, None)
    save_state(st)

    return {"ok": True, "route_id": route_id}


@app.get("/http/routes")
def list_http_routes(x_agent_token: str = Header(default="")):
    require_token(x_agent_token)
    return {"ok": True, "routes": load_state().get("http_routes", {})}


@app.post("/tcp/forwards")
def create_tcp_forward(payload: TcpForwardCreate, x_agent_token: str = Header(default="")):
    require_token(x_agent_token)
    ensure_forwarding_enabled()

    preroute = [
        "-p", payload.proto,
        "--dport", str(payload.public_port),
        "-j", "DNAT",
        "--to-destination", f"{payload.target_ip}:{payload.target_port}",
    ]
    iptables_add_unique("nat", "PREROUTING", preroute)

    forward = [
        "-p", payload.proto,
        "-d", payload.target_ip,
        "--dport", str(payload.target_port),
        "-j", "ACCEPT",
    ]
    iptables_add_unique("filter", "FORWARD", forward)

    st = load_state()
    st["tcp_forwards"][payload.forward_id] = payload.model_dump()
    save_state(st)

    return {"ok": True, "forward_id": payload.forward_id}


@app.delete("/tcp/forwards/{forward_id}")
def delete_tcp_forward(forward_id: str, x_agent_token: str = Header(default="")):
    require_token(x_agent_token)

    st = load_state()
    fw = st.get("tcp_forwards", {}).get(forward_id)
    if not fw:
        return {"ok": True, "forward_id": forward_id, "deleted": False}

    public_port = int(fw["public_port"])
    target_ip = fw["target_ip"]
    target_port = int(fw["target_port"])
    proto = fw.get("proto", "tcp")

    preroute = [
        "-p", proto, "--dport", str(public_port),
        "-j", "DNAT", "--to-destination", f"{target_ip}:{target_port}",
    ]
    iptables_del_if_exists("nat", "PREROUTING", preroute)

    forward = ["-p", proto, "-d", target_ip, "--dport", str(target_port), "-j", "ACCEPT"]
    iptables_del_if_exists("filter", "FORWARD", forward)

    st["tcp_forwards"].pop(forward_id, None)
    save_state(st)

    return {"ok": True, "forward_id": forward_id, "deleted": True}


@app.get("/tcp/forwards")
def list_tcp_forwards(x_agent_token: str = Header(default="")):
    require_token(x_agent_token)
    return {"ok": True, "forwards": load_state().get("tcp_forwards", {})}
