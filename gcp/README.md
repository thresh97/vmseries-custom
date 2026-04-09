# GCP VM-Series Infrastructure Tool

A Python CLI to deploy, manage, and build custom images from Palo Alto Networks VM-Series firewalls on Google Cloud Platform.

## GCP Networking Architecture

GCP requires each NIC on an instance to belong to a **different VPC network**. This tool creates the standard 3-NIC VM-Series topology:

```
mgmt-vpc    (10.0.0.0/24)  — NIC0: SSH+HTTPS management, static external IP
untrust-vpc (10.0.1.0/24)  — NIC1: untrust dataplane, static external IP
trust-vpc   (10.0.2.0/24)  — NIC2: trust dataplane, internal only (no external IP)
```

## Prerequisites

- Python 3.12+
- GCP project with the **Compute Engine API** enabled
- GCP credentials configured:
  ```
  gcloud auth application-default login
  ```
- Accepted Marketplace terms for Palo Alto Networks VM-Series (if using Marketplace images)
- Python dependencies:
  ```
  pip install -r requirements.txt
  ```

## Commands

### `create` — Deploy a VM-Series firewall

```bash
python gcp_create_infra.py create \
    --project-id my-gcp-project \
    --region us-east1 \
    --name-tag pa-fw-test \
    --allowed-ips "YOUR_IP/32" \
    --license-type byol \
    --ssh-key-file ~/.ssh/id_rsa
```

Creates 3 VPC networks + subnets, firewall rules, 2 static external IPs, and a VM-Series instance. Waits for the chassis to be ready before returning.

**Key options:**
| Option | Default | Description |
|--------|---------|-------------|
| `--project-id` | (required) | GCP project ID |
| `--region` | (required) | GCP region (e.g., `us-east1`) |
| `--zone` | `{region}-b` | GCP zone for the instance |
| `--machine-type` | `n2-standard-4` | GCP machine type |
| `--license-type` | `byol` | `byol`, `bundle1`, or `bundle2` |
| `--mgmt-cidr` | `10.0.0.0/24` | Mgmt subnet CIDR |
| `--untrust-cidr` | `10.0.1.0/24` | Untrust subnet CIDR |
| `--trust-cidr` | `10.0.2.0/24` | Trust subnet CIDR |
| `--custom-image-self-link` | — | Use a custom GCP image instead of Marketplace |

### `destroy` — Tear down all resources

```bash
python gcp_create_infra.py destroy --deployment-file abc123-state.json
```

Ordered teardown: instance → static IPs → firewall rules → subnets → VPC networks → state file.

### `set-admin-password`

```bash
python gcp_create_infra.py set-admin-password --deployment-file abc123-state.json
```

Generates a random password, sets it via SSH, commits, and saves it to the state file.

### `upgrade-content`

```bash
python gcp_create_infra.py upgrade-content --deployment-file abc123-state.json
```

### `upgrade-panos`

```bash
python gcp_create_infra.py upgrade-panos \
    --deployment-file abc123-state.json \
    --target-version 11.1
```

Accepts `X.Y`, `X.Y.Z`, or `X.Y.latest`.

### `upgrade-antivirus`

```bash
python gcp_create_infra.py upgrade-antivirus --deployment-file abc123-state.json
```

### `create-image` — Create a GCP image from a stopped instance

```bash
python gcp_create_infra.py create-image \
    --deployment-file abc123-state.json \
    --image-name my-vmseries-image
```

Stops the instance and creates a GCP Compute image from its boot disk.

### `create-custom-image` — Full golden image lifecycle

```bash
python gcp_create_infra.py create-custom-image \
    --project-id my-gcp-project \
    --region us-east1 \
    --name-tag golden-image \
    --allowed-ips "YOUR_IP/32" \
    --auth-code "YOUR-AUTH-CODE" \
    --pin-id "YOUR-PIN-ID" \
    --pin-value "YOUR-PIN-VALUE" \
    --target-upgrade-version 11.1 \
    --auto-destroy
```

**Steps performed:**
1. Deploy 3-NIC VM-Series instance with bootstrap metadata
2. Wait for auto-registration (serial number assigned)
3. Set admin password
4. Upgrade content packages
5. (Optional) Upgrade antivirus — use `--upgrade-antivirus`
6. Upgrade PAN-OS to target version
7. Wait for SSH post-reboot
8. `request system private-data-reset shutdown`
9. Create GCP image from boot disk
10. (Optional) Destroy temporary infrastructure — use `--auto-destroy`

### `create-custom-image-restart` — Resume an interrupted workflow

```bash
python gcp_create_infra.py create-custom-image-restart \
    --deployment-file abc123-state.json
```

Reads the state file to determine which steps have already completed and resumes from where it left off.

## State File

Each deployment creates a `<prefix>-state.json` file tracking all created resources:

```json
{
  "deployment_prefix": "abc123",
  "project_id": "my-gcp-project",
  "region": "us-east1",
  "zone": "us-east1-b",
  "mgmt_network_name": "abc123-pa-fw-test-mgmt-net",
  "untrust_network_name": "abc123-pa-fw-test-untrust-net",
  "trust_network_name": "abc123-pa-fw-test-trust-net",
  "public_ip": "1.2.3.4",
  "untrust_public_ip": "5.6.7.8",
  "instance_name": "abc123-pa-fw-test-vm",
  "admin_password": "...",
  "actions_performed": [...],
  "created_images": [...]
}
```

## Marketplace Explorer

Discover available VM-Series images:

```bash
# List marketplace images for byol (interactive if --license-type omitted)
python gcp_marketplace_explorer.py list-images --license-type byol

# List custom images in your project
python gcp_marketplace_explorer.py list-custom-images --project-id my-gcp-project
```

## Bootstrap Mechanism

VM-Series on GCP is bootstrapped via **instance metadata key-value pairs**. The tool automatically sets:

- `mgmt-interface-swap: enable` — swaps mgmt to NIC0 (required for 3-NIC topology)
- `type: dhcp-client`
- `op-command-modes: mgmt-interface-swap`
- `authcodes: <auth-code>` — BYOL license activation
- `vm-series-auto-registration-pin-id: <pin-id>` — auto-registration
- `vm-series-auto-registration-pin-value: <pin-value>` — auto-registration

## marketplace_images.yaml

Maps license types to GCP image project/family. Update this file if PAN publishes new image families:

```yaml
byol:
  project: paloaltonetworks-public
  family: vmseries-flex-byol-1014
bundle1:
  project: paloaltonetworks-public
  family: vmseries-flex-bundle1-1014
bundle2:
  project: paloaltonetworks-public
  family: vmseries-flex-bundle2-1014
```

> **Note:** GCP image family names include a content version suffix (e.g., `1014` = content version 10.14). Run `gcp_marketplace_explorer.py list-images` to discover the currently available families and update this file accordingly.
