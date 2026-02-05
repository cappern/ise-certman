# Cisco ISE CSR Tool

Interactive CLI to generate and export CSRs per Cisco ISE node, then bind signed certificates to those CSRs.

## Prerequisites

- Python 3.10+
- Network access to your ISE node(s)
- An ISE account with API access

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

This tool supports two modes:

1. **State-driven (recommended)**: interactively create connections and certificate templates, stored in a lightweight state file.
2. **Config-driven**: supply a static `config.json` with explicit node list (legacy workflow).

### State-driven mode (recommended)

On launch, you can create/select a **connection** (cluster) and then create **certificate templates** that define CSR/bind parameters and which nodes they apply to. The tool will fetch all nodes in the cluster automatically and store lightweight CSR state per cluster and template.

You can override the state file location with `--state` (default: `~/.ise-certman/state.json`).

### Config-driven mode

Create a `config.json` in the repo root (or pass `--config` to point elsewhere). You can also generate a starter file using a template:

```bash
python main.py --template admin > config.json
```

Available templates: `admin`, `pxgrid`.

```json
{
  "ise": {
    "base_url": "https://ise.example.local",
    "username": "admin",
    "password": "CHANGEME",
    "verify_tls": true
  },
  "output_dir": "./out",
  "signed_dir": "./signed",
  "validate_dns": true,
  "allow_unresolvable": false,
  "csr_defaults": {
    "subject_template": "CN={host}",
    "keyLength": 2048,
    "digest": "SHA256",
    "san": ["DNS:ise.example.local"],
    "admin": true,
    "eap": true,
    "portal": false,
    "pxgrid": false,
    "radius": false,
    "saml": false,
    "ims": false
  },
  "bind_defaults": {
    "friendlyName": "ise-signed",
    "admin": true,
    "eap": true,
    "portal": false,
    "pxgrid": false,
    "radius": false,
    "saml": false,
    "ims": false,
    "validateCertificateExtensions": true,
    "allowOutOfDateCert": false,
    "allowExtendedValidity": false,
    "allowReplacementOfCertificates": true,
    "allowReplacementOfPortalGroupTag": true
  },
  "nodes": [
    {
      "hostName": "ise-1.example.local",
      "subject": "CN=ise-1.example.local",
      "san": ["DNS:ise-1.example.local"],
      "validate_dns": true,
      "allow_unresolvable": false
    },
    {
      "hostName": "ise-2.example.local",
      "subject": "CN=ise-2.example.local",
      "san": ["DNS:ise-2.example.local"]
    }
  ]
}
```

**Password handling**

- If `ise.password` is missing or set to `CHANGEME`, you will be prompted.
- Alternatively, set `ISE_PASSWORD` in the environment to avoid prompts:

```bash
export ISE_PASSWORD='your-password'
```

### DNS validation

When `validate_dns` is true, the tool resolves the subject `CN` and any `DNS:` SAN entries before creating CSRs. If resolution fails, set `allow_unresolvable` to `true` (global or per-node) to override.

## Run

```bash
python main.py
```

Optional flags:

- `--state` to point at a different state file.
- `--config` to use config-driven mode with a specific config file.
- `--yes` to skip the confirmation prompt (config-driven only).
- `--template` to print a starter config (e.g., `admin` or `pxgrid`).

## Typical workflow (state-driven)

1. **Create/select a connection** when the tool starts.
2. **Create a certificate template** (e.g., admin cert for DMZ ISE, admin cert for internal ISE).
3. **Select nodes** that the template applies to.
4. **Generate CSRs** (option `1`) to create CSRs and export them to `out/csrs/`.
5. **Sign CSRs** with your CA.
6. **Place signed certs** as `signed/<hostName>.crt.pem` (or `.pem` / `.crt`).
7. **Bind certs** (option `2`) to apply them to ISE.

The tool keeps a lightweight state file for connections, templates, and CSR ids per cluster.

## Troubleshooting

- Ensure `ise.base_url` includes the scheme (e.g., `https://ise.example.local`).
- If TLS is inspected by a proxy, set `verify_tls` to `false` or install the proxy CA.
- Confirm the ISE user has API permissions for certificate endpoints.
