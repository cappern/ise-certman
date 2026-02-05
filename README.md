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
python main.py --config ./config.json
```

Optional flags:

- `--yes` to skip the confirmation prompt.
- `--config` to point at a different config file.
- `--template` to print a starter config (e.g., `admin` or `pxgrid`).

## Typical workflow

1. **Generate CSRs**: choose option `1` to create CSRs and export them to `output_dir/csrs/`.
2. **Sign CSRs**: have your CA sign each `*.csr.pem` file.
3. **Place signed certs**: save each signed certificate as `signed/<hostName>.crt.pem` (or `.pem` / `.crt`).
4. **Bind certs**: choose option `2` to bind the signed certs back to ISE.

The tool keeps a `csr_map.json` in `output_dir` to track the CSR ids per host.

## Troubleshooting

- Ensure `ise.base_url` includes the scheme (e.g., `https://ise.example.local`).
- If TLS is inspected by a proxy, set `verify_tls` to `false` or install the proxy CA.
- Confirm the ISE user has API permissions for certificate endpoints.
