#!/usr/bin/env python3
"""
Interactive CSR tool for Cisco ISE (ISE 3.1+ OpenAPI Certificates).

Features:
- Menu-driven interactive CLI
- Generate CSR per node and export CSR PEM files
- Bind signed certificate PEM per node to previously generated CSR
- Maintains a csr_map.json under output_dir

Notes:
- API shapes/field names can vary slightly across ISE versions.
- Endpoints used are typical for ISE 3.1+ /api/v1/certs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth

DEFAULT_TIMEOUT = 60

TEMPLATES: Dict[str, Dict[str, Any]] = {
    "admin": {
        "csr_defaults": {
            "admin": True,
            "eap": False,
            "portal": False,
            "pxgrid": False,
            "radius": False,
            "saml": False,
            "ims": False,
        },
        "bind_defaults": {
            "admin": True,
            "eap": False,
            "portal": False,
            "pxgrid": False,
            "radius": False,
            "saml": False,
            "ims": False,
        },
    },
    "pxgrid": {
        "csr_defaults": {
            "admin": False,
            "eap": False,
            "portal": False,
            "pxgrid": True,
            "radius": False,
            "saml": False,
            "ims": False,
        },
        "bind_defaults": {
            "admin": False,
            "eap": False,
            "portal": False,
            "pxgrid": True,
            "radius": False,
            "saml": False,
            "ims": False,
        },
    },
}

STATE_DEFAULT_PATH = Path.home() / ".ise-certman" / "state.json"


# ----------------------------
# Helpers
# ----------------------------

def die(msg: str, code: int = 2) -> None:
    print(f"\nERROR: {msg}\n", file=sys.stderr)
    raise SystemExit(code)


def prompt(msg: str, default: Optional[str] = None) -> str:
    if default:
        val = input(f"{msg} [{default}]: ").strip()
        return val if val else default
    return input(f"{msg}: ").strip()


def yes_no(msg: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    val = input(f"{msg} ({d}): ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes", "j", "ja")


def load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        die(f"Failed to read JSON from {path}: {e}")


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception as e:
        die(f"Failed to read file {path}: {e}")


def http_request(
    method: str,
    base_url: str,
    user: str,
    password: str,
    verify_tls: bool,
    path: str,
    *,
    json_body: Optional[Dict[str, Any]] = None,
    accept: str = "application/json",
) -> requests.Response:
    url = base_url.rstrip("/") + path
    headers = {"Accept": accept}
    if json_body is not None:
        headers["Content-Type"] = "application/json"

    try:
        return requests.request(
            method=method,
            url=url,
            headers=headers,
            json=json_body,
            auth=HTTPBasicAuth(user, password),
            verify=verify_tls,
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.exceptions.SSLError as e:
        die(
            "TLS/SSL error while connecting to ISE. "
            "If ISE uses a self-signed cert, set ise.verify_tls=false in config.json. "
            f"Details: {e}"
        )
    except requests.exceptions.Timeout as e:
        die(f"Request timed out after {DEFAULT_TIMEOUT}s: {url}\n{e}")
    except requests.exceptions.ConnectionError as e:
        die(
            "Connection error while reaching ISE. "
            "Check ise.base_url, DNS resolution, and network reachability.\n"
            f"URL: {url}\n{e}"
        )
    except requests.exceptions.RequestException as e:
        die(f"HTTP request failed: {url}\n{e}")


def ensure_ok(resp: requests.Response, ctx: str) -> None:
    if 200 <= resp.status_code < 300:
        return
    body = resp.text.strip()
    die(f"{ctx} failed: HTTP {resp.status_code}\n{body[:2000]}")


def response_json(resp: requests.Response, ctx: str) -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception as e:
        body = resp.text.strip()
        die(f"{ctx} returned invalid JSON: {e}\n{body[:2000]}")


def extract_csr_id(resp_json: Dict[str, Any]) -> Optional[str]:
    # Try a few common shapes
    if "id" in resp_json and isinstance(resp_json["id"], (str, int)):
        return str(resp_json["id"])
    if "response" in resp_json and isinstance(resp_json["response"], dict):
        rid = resp_json["response"].get("id")
        if rid is not None:
            return str(rid)
    return None


def extract_pem_from_export(resp: requests.Response) -> str:
    # If API returns raw PEM
    if "BEGIN CERTIFICATE REQUEST" in resp.text:
        return resp.text if resp.text.endswith("\n") else resp.text + "\n"

    # JSON-based export
    try:
        data = resp.json()
    except Exception:
        die("Export CSR response was not JSON and did not contain PEM text.")

    for key in ("csr", "data"):
        if key in data and isinstance(data[key], str) and "BEGIN" in data[key]:
            pem = data[key].strip()
            return pem if pem.endswith("\n") else pem + "\n"

    if "response" in data and isinstance(data["response"], dict):
        for key in ("csr", "data"):
            val = data["response"].get(key)
            if isinstance(val, str) and "BEGIN" in val:
                pem = val.strip()
                return pem if pem.endswith("\n") else pem + "\n"

    die(f"Could not find CSR PEM in export response: {data}")


def read_cert_pem(path: Path) -> str:
    pem = read_text(path).strip()
    if "BEGIN CERTIFICATE" not in pem:
        die(f"{path} does not look like a PEM certificate (missing BEGIN CERTIFICATE).")
    return pem


def normalize_base_url(base_url: str) -> str:
    base_url = base_url.strip()
    if not base_url:
        die("Missing ise.base_url in config.")
    if not base_url.startswith(("http://", "https://")):
        die("ise.base_url must include scheme (http:// or https://).")
    return base_url.rstrip("/")


def env_password() -> str:
    return os.environ.get("ISE_PASSWORD", "").strip()


def extract_cn(subject: str) -> Optional[str]:
    match = re.search(r"CN=([^,]+)", subject)
    if match:
        return match.group(1).strip()
    return None


def resolve_name(name: str) -> bool:
    try:
        socket.getaddrinfo(name, None)
        return True
    except socket.gaierror:
        return False


def validate_names(
    host: str,
    subject: str,
    sans: list[str],
    *,
    validate_dns: bool,
    allow_unresolvable: bool,
) -> None:
    if not validate_dns:
        return

    cn = extract_cn(subject)
    if not cn:
        die(f"{host}: subject missing CN, cannot validate DNS: {subject}")

    to_check = [cn]
    for san in sans:
        if san.startswith("DNS:"):
            to_check.append(san.replace("DNS:", "", 1).strip())

    unresolved = [name for name in to_check if name and not resolve_name(name)]
    if unresolved and not allow_unresolvable:
        names = ", ".join(unresolved)
        die(f"{host}: DNS validation failed for {names}. Set allow_unresolvable to override.")


def state_path(path_override: Optional[str]) -> Path:
    if path_override:
        return Path(path_override).expanduser().resolve()
    return STATE_DEFAULT_PATH


def load_state(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"connections": {}, "templates": {}, "csr_map": {}}
    return load_json(path)


def save_state(path: Path, data: Dict[str, Any]) -> None:
    save_json(path, data)


def prompt_bool(msg: str, default: bool) -> bool:
    return yes_no(msg, default)


def parse_san_list(raw: str) -> list[str]:
    if not raw.strip():
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


# ----------------------------
# Config model
# ----------------------------

@dataclass
class IseConfig:
    base_url: str
    username: str
    password: str
    verify_tls: bool


@dataclass
class AppConfig:
    ise: IseConfig
    output_dir: Path
    signed_dir: Path
    csr_defaults: Dict[str, Any]
    bind_defaults: Dict[str, Any]
    validate_dns: bool
    allow_unresolvable: bool
    nodes: list[Dict[str, Any]]


def load_app_config(config_path: Path) -> AppConfig:
    raw = load_json(config_path)

    ise_raw = raw.get("ise") or {}
    base_url = normalize_base_url(str(ise_raw.get("base_url") or ""))
    username = ise_raw.get("username") or die("Missing ise.username in config.")
    password = ise_raw.get("password") or env_password() or ""

    verify_tls = bool(ise_raw.get("verify_tls", True))

    output_dir = Path(raw.get("output_dir", "./out")).resolve()
    signed_dir = Path(raw.get("signed_dir", "./signed")).resolve()

    csr_defaults = raw.get("csr_defaults") or {}
    bind_defaults = raw.get("bind_defaults") or {}
    validate_dns = bool(raw.get("validate_dns", True))
    allow_unresolvable = bool(raw.get("allow_unresolvable", False))
    nodes = raw.get("nodes") or []
    if not nodes:
        die("Config has no nodes[]. Add at least one node with hostName.")

    deduped_nodes: list[Dict[str, Any]] = []
    seen_hosts = set()
    for node in nodes:
        host = node.get("hostName")
        if not host:
            die("Every node entry must include hostName.")
        if host in seen_hosts:
            die(f"Duplicate hostName in nodes: {host}")
        seen_hosts.add(host)
        deduped_nodes.append(node)

    # Prompt for password if blank/placeholder
    if not password or password.strip().upper() in ("CHANGEME", "CHANGE_ME", "PASSWORD"):
        password = getpass("ISE API password (input hidden): ").strip()
        if not password:
            die("Password required.")

    return AppConfig(
        ise=IseConfig(base_url=base_url, username=username, password=password, verify_tls=verify_tls),
        output_dir=output_dir,
        signed_dir=signed_dir,
        csr_defaults=csr_defaults,
        bind_defaults=bind_defaults,
        validate_dns=validate_dns,
        allow_unresolvable=allow_unresolvable,
        nodes=deduped_nodes,
    )


def build_template_config(template: str) -> Dict[str, Any]:
    base = {
        "ise": {
            "base_url": "https://ise.example.local",
            "username": "admin",
            "password": "CHANGEME",
            "verify_tls": True,
        },
        "output_dir": "./out",
        "signed_dir": "./signed",
        "validate_dns": True,
        "allow_unresolvable": False,
        "csr_defaults": {
            "subject_template": "CN={host}",
            "keyLength": 2048,
            "digest": "SHA256",
            "san": [],
        },
        "bind_defaults": {
            "friendlyName": "ise-signed",
            "validateCertificateExtensions": True,
            "allowOutOfDateCert": False,
            "allowExtendedValidity": False,
            "allowReplacementOfCertificates": True,
            "allowReplacementOfPortalGroupTag": True,
        },
        "nodes": [
            {
                "hostName": "ise-1.example.local",
                "subject": "CN=ise-1.example.local",
                "san": ["DNS:ise-1.example.local"],
            }
        ],
    }
    if template not in TEMPLATES:
        die(f"Unknown template: {template}")
    base["csr_defaults"].update(TEMPLATES[template]["csr_defaults"])
    base["bind_defaults"].update(TEMPLATES[template]["bind_defaults"])
    return base


def print_template(template: str) -> None:
    data = build_template_config(template)
    print(json.dumps(data, indent=2))


# ----------------------------
# State + interactive helpers
# ----------------------------

def fetch_cluster_nodes(ise: IseConfig) -> list[Dict[str, Any]]:
    r = http_request(
        "GET",
        ise.base_url,
        ise.username,
        ise.password,
        ise.verify_tls,
        "/api/v1/deployment/node",
    )
    ensure_ok(r, "Fetch cluster nodes")
    data = r.json()
    nodes_raw = data.get("response") or data.get("nodes") or []
    nodes: list[Dict[str, Any]] = []
    for item in nodes_raw:
        host = item.get("hostName") or item.get("hostname") or item.get("name")
        if host:
            nodes.append({"hostName": host})
    if not nodes:
        die("No nodes returned from cluster.")
    return nodes


def select_nodes(all_nodes: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    print("\nAvailable nodes:")
    for idx, node in enumerate(all_nodes, start=1):
        print(f"{idx}) {node['hostName']}")
    choice = prompt("Select nodes (comma-separated numbers or 'all')", "all")
    if choice.lower() == "all":
        return all_nodes
    selections = []
    for part in choice.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            die(f"Invalid selection: {part}")
        idx = int(part)
        if idx < 1 or idx > len(all_nodes):
            die(f"Selection out of range: {part}")
        selections.append(all_nodes[idx - 1])
    if not selections:
        die("No nodes selected.")
    return selections


def choose_connection(state: Dict[str, Any], *, state_file: Path) -> Tuple[str, Dict[str, Any]]:
    connections = state.get("connections", {})
    if connections:
        print("\nConnections:")
        names = sorted(connections.keys())
        for idx, name in enumerate(names, start=1):
            print(f"{idx}) {name} ({connections[name].get('base_url')})")
        print(f"{len(names) + 1}) Create new connection")
        choice = prompt("Select connection", "1")
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            name = names[int(choice) - 1]
            return name, connections[name]
        if choice == str(len(names) + 1):
            return create_connection(state, state_file=state_file)
        die("Invalid connection selection.")
    return create_connection(state, state_file=state_file)


def create_connection(state: Dict[str, Any], *, state_file: Path) -> Tuple[str, Dict[str, Any]]:
    print("\nCreate new connection:")
    name = prompt("Connection name")
    base_url = normalize_base_url(prompt("ISE base URL (https://...)"))
    username = prompt("ISE username")
    verify_tls = prompt_bool("Verify TLS certificates?", True)
    connection = {
        "base_url": base_url,
        "username": username,
        "verify_tls": verify_tls,
    }
    state.setdefault("connections", {})[name] = connection
    save_state(state_file, state)
    return name, connection


def prompt_template_details() -> Dict[str, Any]:
    print("\nDefine certificate template details:")
    subject_template = prompt("Subject template (use {host})", "CN={host}")
    key_length = int(prompt("Key length", "2048"))
    digest = prompt("Digest", "SHA256")
    san_raw = prompt("Default SANs (comma-separated, use DNS:..., empty for none)", "")
    san = parse_san_list(san_raw)

    def usage_flags(prefix: str) -> Dict[str, bool]:
        return {
            "admin": prompt_bool(f"{prefix} admin?", True),
            "eap": prompt_bool(f"{prefix} eap?", True),
            "portal": prompt_bool(f"{prefix} portal?", False),
            "pxgrid": prompt_bool(f"{prefix} pxgrid?", False),
            "radius": prompt_bool(f"{prefix} radius?", False),
            "saml": prompt_bool(f"{prefix} saml?", False),
            "ims": prompt_bool(f"{prefix} ims?", False),
        }

    validate_dns = prompt_bool("Validate CN/SAN via DNS?", True)
    allow_unresolvable = prompt_bool("Allow unresolvable names?", False)

    csr_defaults = {
        "subject_template": subject_template,
        "keyLength": key_length,
        "digest": digest,
        "san": san,
        **usage_flags("CSR"),
    }
    bind_defaults = {
        "friendlyName": prompt("Friendly name", "ise-signed"),
        **usage_flags("Bind"),
        "validateCertificateExtensions": prompt_bool("Validate cert extensions?", True),
        "allowOutOfDateCert": prompt_bool("Allow out-of-date cert?", False),
        "allowExtendedValidity": prompt_bool("Allow extended validity?", False),
        "allowReplacementOfCertificates": prompt_bool("Allow replacement of certificates?", True),
        "allowReplacementOfPortalGroupTag": prompt_bool("Allow replacement of portal group tag?", True),
    }

    return {
        "validate_dns": validate_dns,
        "allow_unresolvable": allow_unresolvable,
        "csr_defaults": csr_defaults,
        "bind_defaults": bind_defaults,
    }


def create_template(
    state: Dict[str, Any],
    *,
    state_file: Path,
    connection_name: str,
    nodes: list[Dict[str, Any]],
) -> str:
    print("\nCreate new certificate template:")
    name = prompt("Template name")
    details = prompt_template_details()
    apply_nodes = select_nodes(nodes)
    template = {
        "connection": connection_name,
        "nodes": [node["hostName"] for node in apply_nodes],
        "validate_dns": details["validate_dns"],
        "allow_unresolvable": details["allow_unresolvable"],
        "csr_defaults": details["csr_defaults"],
        "bind_defaults": details["bind_defaults"],
    }
    state.setdefault("templates", {})[name] = template
    save_state(state_file, state)
    return name


def choose_template(
    state: Dict[str, Any],
    *,
    state_file: Path,
    connection_name: str,
    nodes: list[Dict[str, Any]],
) -> str:
    templates = state.get("templates", {})
    filtered = {k: v for k, v in templates.items() if v.get("connection") == connection_name}
    if filtered:
        names = sorted(filtered.keys())
        print("\nTemplates:")
        for idx, name in enumerate(names, start=1):
            print(f"{idx}) {name}")
        print(f"{len(names) + 1}) Create new template")
        choice = prompt("Select template", "1")
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            return names[int(choice) - 1]
        if choice == str(len(names) + 1):
            return create_template(state, state_file=state_file, connection_name=connection_name, nodes=nodes)
        die("Invalid template selection.")
    return create_template(state, state_file=state_file, connection_name=connection_name, nodes=nodes)


def build_config_from_template(
    connection: Dict[str, Any],
    *,
    password: str,
    template: Dict[str, Any],
    nodes: list[Dict[str, Any]],
) -> AppConfig:
    return AppConfig(
        ise=IseConfig(
            base_url=connection["base_url"],
            username=connection["username"],
            password=password,
            verify_tls=bool(connection.get("verify_tls", True)),
        ),
        output_dir=Path("./out").resolve(),
        signed_dir=Path("./signed").resolve(),
        csr_defaults=template.get("csr_defaults", {}),
        bind_defaults=template.get("bind_defaults", {}),
        validate_dns=bool(template.get("validate_dns", True)),
        allow_unresolvable=bool(template.get("allow_unresolvable", False)),
        nodes=nodes,
    )


def update_state_csr_map(
    state: Dict[str, Any],
    *,
    state_file: Path,
    connection_name: str,
    host: str,
    csr_id: str,
    subject: str,
    template_name: str,
) -> None:
    csr_map = state.setdefault("csr_map", {})
    conn_map = csr_map.setdefault(connection_name, {})
    conn_map[host] = {"id": csr_id, "subject": subject, "template": template_name}
    save_state(state_file, state)


def load_state_csr_map(state: Dict[str, Any], connection_name: str) -> Dict[str, Any]:
    return state.get("csr_map", {}).get(connection_name, {})


# ----------------------------
# CSR map
# ----------------------------

def csr_map_path(cfg: AppConfig) -> Path:
    return cfg.output_dir / "csr_map.json"


def load_csr_map(cfg: AppConfig) -> Dict[str, Any]:
    p = csr_map_path(cfg)
    if p.exists():
        return load_json(p)
    return {"csrs": {}}


def save_csr_map(cfg: AppConfig, data: Dict[str, Any]) -> None:
    save_json(csr_map_path(cfg), data)


# ----------------------------
# Operations
# ----------------------------

def generate_and_export(
    cfg: AppConfig,
    *,
    state: Optional[Dict[str, Any]] = None,
    state_file: Optional[Path] = None,
    connection_name: Optional[str] = None,
    template_name: Optional[str] = None,
) -> None:
    ise = cfg.ise
    csr_map = load_csr_map(cfg)

    csr_defaults = cfg.csr_defaults
    subject_template = csr_defaults.get("subject_template", "CN={host}")

    for node in cfg.nodes:
        host = node.get("hostName")
        if not host:
            print("[SKIP] node without hostName in config.")
            continue

        subject = node.get("subject") or subject_template.format(host=host)
        sans = node.get("san", csr_defaults.get("san", []))
        validate_names(
            host,
            subject,
            sans,
            validate_dns=bool(node.get("validate_dns", cfg.validate_dns)),
            allow_unresolvable=bool(node.get("allow_unresolvable", cfg.allow_unresolvable)),
        )

        payload = {
            "hostName": host,
            "subject": subject,
            "keyLength": int(node.get("keyLength", csr_defaults.get("keyLength", 2048))),
            "digest": node.get("digest", csr_defaults.get("digest", "SHA256")),
            "subjectAltNames": sans,
            "admin": bool(node.get("admin", csr_defaults.get("admin", True))),
            "eap": bool(node.get("eap", csr_defaults.get("eap", True))),
            "portal": bool(node.get("portal", csr_defaults.get("portal", False))),
            "pxgrid": bool(node.get("pxgrid", csr_defaults.get("pxgrid", False))),
            "radius": bool(node.get("radius", csr_defaults.get("radius", False))),
            "saml": bool(node.get("saml", csr_defaults.get("saml", False))),
            "ims": bool(node.get("ims", csr_defaults.get("ims", False))),
        }

        # Create CSR
        r = http_request(
            "POST",
            ise.base_url,
            ise.username,
            ise.password,
            ise.verify_tls,
            "/api/v1/certs/certificate-signing-request",
            json_body=payload,
        )
        ensure_ok(r, f"Create CSR for {host}")
        data = response_json(r, f"Create CSR for {host}")
        csr_id = extract_csr_id(data)
        if not csr_id:
            die(f"CSR creation returned no id for {host}. Response: {data}")

        csr_map["csrs"][host] = {"id": csr_id, "subject": subject}
        save_csr_map(cfg, csr_map)
        if state and state_file and connection_name and template_name:
            update_state_csr_map(
                state,
                state_file=state_file,
                connection_name=connection_name,
                host=host,
                csr_id=csr_id,
                subject=subject,
                template_name=template_name,
            )

        # Export CSR
        r2 = http_request(
            "GET",
            ise.base_url,
            ise.username,
            ise.password,
            ise.verify_tls,
            f"/api/v1/certs/certificate-signing-request/{host}/{csr_id}",
            accept="application/json",
        )
        ensure_ok(r2, f"Export CSR for {host}")
        pem = extract_pem_from_export(r2)

        csr_file = cfg.output_dir / "csrs" / f"{host}.csr.pem"
        write_text(csr_file, pem)

        print(f"[OK] {host}: CSR id={csr_id} exported -> {csr_file}")

    print(f"\nDone.\nCSR map -> {csr_map_path(cfg)}")


def bind_signed(cfg: AppConfig, *, csr_map_override: Optional[Dict[str, Any]] = None) -> None:
    ise = cfg.ise
    csr_map = csr_map_override or load_csr_map(cfg)

    csrs = csr_map.get("csrs", {})
    if not csrs:
        die(f"No CSRs in {csr_map_path(cfg)}. Run 'Generate & Export' first.")

    bind_defaults = cfg.bind_defaults or {}

    print(f"\nLooking for signed certs in: {cfg.signed_dir}")
    print("Expected filename per node: <hostName>.crt.pem  (you can also use .pem, but keep the name)\n")

    for host, meta in csrs.items():
        csr_id = meta.get("id")
        if not csr_id:
            print(f"[SKIP] {host}: missing csr id in csr_map.json")
            continue

        # Accept a couple extensions
        candidates = [
            cfg.signed_dir / f"{host}.crt.pem",
            cfg.signed_dir / f"{host}.pem",
            cfg.signed_dir / f"{host}.crt",
        ]
        cert_path = next((p for p in candidates if p.exists()), None)
        if not cert_path:
            print(f"[SKIP] {host}: no signed cert found (tried .crt.pem/.pem/.crt)")
            continue

        cert_pem = read_cert_pem(cert_path)

        payload = {
            "hostName": host,
            "id": csr_id,
            "data": cert_pem,

            "name": bind_defaults.get("friendlyName", f"{host}-signed"),
            "admin": bool(bind_defaults.get("admin", True)),
            "eap": bool(bind_defaults.get("eap", True)),
            "portal": bool(bind_defaults.get("portal", False)),
            "pxgrid": bool(bind_defaults.get("pxgrid", False)),
            "radius": bool(bind_defaults.get("radius", False)),
            "saml": bool(bind_defaults.get("saml", False)),
            "ims": bool(bind_defaults.get("ims", False)),

            "validateCertificateExtensions": bool(bind_defaults.get("validateCertificateExtensions", True)),
            "allowOutOfDateCert": bool(bind_defaults.get("allowOutOfDateCert", False)),
            "allowExtendedValidity": bool(bind_defaults.get("allowExtendedValidity", False)),
            "allowReplacementOfCertificates": bool(bind_defaults.get("allowReplacementOfCertificates", True)),
            "allowReplacementOfPortalGroupTag": bool(bind_defaults.get("allowReplacementOfPortalGroupTag", True)),
        }

        r = http_request(
            "POST",
            ise.base_url,
            ise.username,
            ise.password,
            ise.verify_tls,
            "/api/v1/certs/signed-certificate/bind",
            json_body=payload,
        )
        ensure_ok(r, f"Bind signed cert for {host}")
        print(f"[OK] {host}: bound signed cert ({cert_path.name}) -> CSR id={csr_id}")

    print("\nDone.")


def show_csr_map(cfg: AppConfig) -> None:
    m = load_csr_map(cfg)
    csrs = m.get("csrs", {})
    if not csrs:
        print(f"\nNo CSR map found or empty: {csr_map_path(cfg)}\n")
        return

    print(f"\nCSR map: {csr_map_path(cfg)}\n")
    for host, meta in csrs.items():
        print(f"- {host}: id={meta.get('id')} subject={meta.get('subject')}")
    print("")


# ----------------------------
# Interactive Menu
# ----------------------------

def print_menu() -> None:
    print(
        "\nCisco ISE CSR Tool (interactive)\n"
        "--------------------------------\n"
        "1) Generate CSR on all nodes + Export CSR PEM files\n"
        "2) Bind signed cert PEM files to previous CSR\n"
        "3) Show CSR map (node -> CSR id)\n"
        "4) Exit\n"
    )

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interactive CSR tool for Cisco ISE (ISE 3.1+ OpenAPI Certificates).",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Path to config.json (if provided, uses config-based mode).",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive confirmation prompt.",
    )
    parser.add_argument(
        "--template",
        choices=sorted(TEMPLATES.keys()),
        help="Print a starter config template and exit.",
    )
    parser.add_argument(
        "--state",
        help=f"Path to state file (default: {STATE_DEFAULT_PATH}).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("\nCisco ISE CSR Tool (interactive)\n")

    if args.template:
        print_template(args.template)
        return

    if args.config:
        cfg_path = Path(args.config).expanduser().resolve()
        if not cfg_path.exists():
            die(f"Config file not found: {cfg_path}")

        cfg = load_app_config(cfg_path)

        print("\nLoaded config:")
        print(f"- ISE base_url : {cfg.ise.base_url}")
        print(f"- ISE username : {cfg.ise.username}")
        print(f"- verify_tls   : {cfg.ise.verify_tls}")
        print(f"- output_dir   : {cfg.output_dir}")
        print(f"- signed_dir   : {cfg.signed_dir}")
        print(f"- nodes        : {len(cfg.nodes)}")

        if not args.yes and not yes_no("\nContinue?", True):
            raise SystemExit(0)

        while True:
            print_menu()
            choice = input("Select option (1-4): ").strip()

            if choice == "1":
                generate_and_export(cfg)
            elif choice == "2":
                bind_signed(cfg)
            elif choice == "3":
                show_csr_map(cfg)
            elif choice == "4":
                print("\nBye.\n")
                break
            else:
                print("Invalid choice. Please select 1-4.")
        return

    state_file = state_path(args.state)
    state = load_state(state_file)
    connection_name, connection = choose_connection(state, state_file=state_file)
    password = env_password() or getpass("ISE API password (input hidden): ").strip()
    if not password:
        die("Password required.")

    ise = IseConfig(
        base_url=connection["base_url"],
        username=connection["username"],
        password=password,
        verify_tls=bool(connection.get("verify_tls", True)),
    )
    nodes = fetch_cluster_nodes(ise)

    while True:
        print(
            "\nConnection menu\n"
            "---------------\n"
            f"Active connection: {connection_name}\n"
            "1) Generate CSR from template\n"
            "2) Bind signed certs from template\n"
            "3) Manage templates\n"
            "4) Switch connection\n"
            "5) Show saved CSR state\n"
            "6) Exit\n"
        )
        choice = prompt("Select option", "1")

        if choice == "1":
            template_name = choose_template(
                state,
                state_file=state_file,
                connection_name=connection_name,
                nodes=nodes,
            )
            template = state["templates"][template_name]
            template_nodes = [n for n in nodes if n["hostName"] in template.get("nodes", [])]
            use_template_nodes = prompt_bool("Use template node list?", True)
            if use_template_nodes and not template_nodes:
                print("Template has no matching nodes for this cluster. Please select nodes.")
                selected_nodes = select_nodes(nodes)
            else:
                selected_nodes = template_nodes if use_template_nodes else select_nodes(nodes)
            cfg = build_config_from_template(
                connection,
                password=password,
                template=template,
                nodes=selected_nodes,
            )
            generate_and_export(
                cfg,
                state=state,
                state_file=state_file,
                connection_name=connection_name,
                template_name=template_name,
            )
        elif choice == "2":
            template_name = choose_template(
                state,
                state_file=state_file,
                connection_name=connection_name,
                nodes=nodes,
            )
            template = state["templates"][template_name]
            selected_nodes = [n for n in nodes if n["hostName"] in template.get("nodes", [])]
            cfg = build_config_from_template(
                connection,
                password=password,
                template=template,
                nodes=selected_nodes or nodes,
            )
            csr_map = load_state_csr_map(state, connection_name)
            filtered_csrs = {host: meta for host, meta in csr_map.items() if meta.get("template") == template_name}
            if not filtered_csrs:
                print("\nNo CSR state found for this template. Generate CSRs first.\n")
                continue
            filtered_map = {"csrs": filtered_csrs}
            bind_signed(cfg, csr_map_override=filtered_map)
        elif choice == "3":
            choose_template(
                state,
                state_file=state_file,
                connection_name=connection_name,
                nodes=nodes,
            )
        elif choice == "4":
            connection_name, connection = choose_connection(state, state_file=state_file)
            password = env_password() or getpass("ISE API password (input hidden): ").strip()
            if not password:
                die("Password required.")
            ise = IseConfig(
                base_url=connection["base_url"],
                username=connection["username"],
                password=password,
                verify_tls=bool(connection.get("verify_tls", True)),
            )
            nodes = fetch_cluster_nodes(ise)
        elif choice == "5":
            csr_map = load_state_csr_map(state, connection_name)
            if not csr_map:
                print("\nNo CSR state saved for this connection.\n")
            else:
                print("\nSaved CSR state:")
                for host, meta in csr_map.items():
                    print(
                        f"- {host}: id={meta.get('id')} subject={meta.get('subject')} "
                        f"template={meta.get('template')}"
                    )
        elif choice == "6":
            print("\nBye.\n")
            break
        else:
            print("Invalid choice. Please select 1-6.")


if __name__ == "__main__":
    # Reduce noisy TLS warnings if user disables verification
    try:
        import urllib3  # type: ignore
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    main()
