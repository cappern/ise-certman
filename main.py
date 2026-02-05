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
import sys
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth

DEFAULT_TIMEOUT = 60


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
        nodes=deduped_nodes,
    )


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

def generate_and_export(cfg: AppConfig) -> None:
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

        payload = {
            "hostName": host,
            "subject": subject,
            "keyLength": int(node.get("keyLength", csr_defaults.get("keyLength", 2048))),
            "digest": node.get("digest", csr_defaults.get("digest", "SHA256")),
            "subjectAltNames": node.get("san", csr_defaults.get("san", [])),
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


def bind_signed(cfg: AppConfig) -> None:
    ise = cfg.ise
    csr_map = load_csr_map(cfg)

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
        default="./config.json",
        help="Path to config.json (default: ./config.json).",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive confirmation prompt.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("\nCisco ISE CSR Tool (interactive)\n")

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


if __name__ == "__main__":
    # Reduce noisy TLS warnings if user disables verification
    try:
        import urllib3  # type: ignore
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    main()
