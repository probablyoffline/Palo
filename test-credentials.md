# test-credentials.py

Verify API credentials by fetching the first few security rules from the target host. Supports both standalone firewall (vsys) and Panorama (device group) modes.

## Prerequisites

Credentials must be stored in `~/.palo/credentials.conf`:

```ini
[palo]
firewall = your-firewall-or-panorama-hostname
api_key  = your-panos-api-key
```

Use `credentials.conf.example` in the project root as a template.

## Usage

```
python test-credentials.py [--dg DEVICE_GROUP] [--vsys VSYS] [--rulebase pre|post] [--limit N]
```

## Arguments

| Argument | Description | Default |
|---|---|---|
| `--dg DEVICE_GROUP` | Panorama device group name. Presence of this flag switches to Panorama mode. | *(omit for firewall mode)* |
| `--vsys VSYS` | Vsys name. Used in firewall mode only. | `vsys1` |
| `--rulebase pre\|post` | Rulebase to query. Used in Panorama mode only. | `pre` |
| `--limit N` | Number of rule names to display. | `5` |

## Examples

**Firewall mode** (default — no device group required):
```bash
python test-credentials.py
```

**Firewall mode — different vsys:**
```bash
python test-credentials.py --vsys vsys2
```

**Panorama mode:**
```bash
python test-credentials.py --dg "DG-MyGroup"
```

**Panorama mode — post-rulebase, show 10 rules:**
```bash
python test-credentials.py --dg "DG-MyGroup" --rulebase post --limit 10
```

## Output

On success the script prints the target host, mode, and the first N rule names:

```
Target   : panorama.example.com
Mode     : panorama  DG=DG-MyGroup  pre-rulebase
Fetching : first 5 security rules …

Rules (42 total, showing first 5):
    1. Allow-DNS-Outbound
    2. Allow-Web-Outbound
    3. Block-Malicious-IPs
    4. Allow-AD-Traffic
    5. Allow-NTP

Credentials OK.
```

On failure the script exits with a descriptive error message indicating whether the problem was a connection failure, HTTP error, or an API-level rejection (e.g. bad API key, invalid device group name).
