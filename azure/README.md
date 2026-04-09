Azure Infrastructure CLI for Palo Alto Networks VM-Series
A Python CLI tool to deploy, manage, upgrade, and snapshot Palo Alto Networks VM-Series firewalls in Azure. Automates the end-to-end lifecycle for development, testing, and golden Managed Image creation.

---

License
MIT License — see [LICENSE](../LICENSE) for full text.

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

---

Warning & Disclaimer
**This tool is intended for lab, demo, development, and testing purposes only. It is not designed, tested, or supported for use in production environments.**

This script creates Azure resources that will incur costs. Always destroy infrastructure with the `destroy` command when finished to avoid unexpected charges. The user is solely responsible for all associated Azure costs, any licensing fees, and ensuring compliance with Palo Alto Networks' terms of service and Azure Marketplace subscription agreements.

This project is not affiliated with, endorsed by, or supported by Palo Alto Networks, Inc. or Microsoft Corporation.

---

Features
- **create**: Deploys a Resource Group, VNet, public/private subnets, NSG, Public IPs, NICs, and a 3-NIC VM-Series VM. Optionally bootstraps via `custom_data`.
- **destroy**: Deletes the Resource Group, which cascade-deletes all resources inside it. No ordered teardown required.
- **set-admin-password**: Sets a strong random admin password and saves it to the state file for API access.
- **upgrade-content**: Downloads and installs the latest content update via the PAN-OS API. Requires a licensed firewall.
- **upgrade-panos**: Upgrades PAN-OS software to a specified version via the API. Supports exact, partial, and `latest` version specs.
- **upgrade-antivirus**: Downloads and installs the latest antivirus update via the API.
- **create-image**: Deallocates, generalizes, and creates a Managed Image from an existing deployment VM.
- **create-custom-image**: Compound workflow — deploys with bootstrap `custom_data` (auto-registration), upgrades content and PAN-OS, optionally upgrades antivirus, performs private-data-reset, deallocates, generalizes, and captures a golden Managed Image.
- **create-custom-image-restart**: Resumes an interrupted `create-custom-image` from its state file.

---

Prerequisites
- Python 3.12+ and pip
- Azure credentials configured (`az login`)
- Azure subscription with Marketplace terms accepted for VM-Series (`vmseries-flex`)
- Accepted Marketplace terms (one-time per subscription):
  ```
  az vm image terms accept --publisher paloaltonetworks --offer vmseries-flex --plan byol
  ```

Install dependencies:

```
pip install -r requirements.txt
```

---

File Overview

| File | Description |
|---|---|
| `azure_create_infra.py` | Main script for all create, manage, and upgrade operations |
| `azure_marketplace_explorer.py` | Utility for discovering VM-Series versions available in Azure regions |
| `marketplace_skus.yaml` | Maps license type names to Azure Marketplace SKU names |
| `requirements.txt` | Python package dependencies |

---

Authentication
This tool uses `DefaultAzureCredential` from the Azure Identity SDK. It automatically picks up credentials from `az login`, environment variables, managed identity, or other configured sources. No explicit credentials are required in the script.

```
az login
```

If you have multiple subscriptions, specify `--subscription-id` to target a specific one. Otherwise, the first subscription in your account is used.

---

Networking Layout

The tool creates a 3-NIC VM-Series configuration mirroring the AWS layout:

| Interface | Role | Subnet | Public IP | IP Forwarding |
|---|---|---|---|---|
| eth0 | Management | Public subnet | Yes (static, NSG-protected) | No |
| eth1 | Untrust | Public subnet | Yes (static) | Yes |
| eth2 | Trust | Private subnet | No | Yes |

NSG rules allow SSH (22) and HTTPS (443) from `--allowed-ips` to eth0 only.

---

Usage

All commands follow the pattern:

```
python azure_create_infra.py <command> [options]
```

---

### create

Deploys a new Resource Group and VM-Series VM. Generates a state file (e.g., `abc123-state.json`) used by all subsequent commands.

```
python azure_create_infra.py create \
    --region eastus \
    --name-tag "pa-fw-test" \
    --allowed-ips "YOUR_IP/32"
```

| Argument | Required | Default | Description |
|---|---|---|---|
| `--region` | Yes | — | Azure region (e.g., `eastus`) |
| `--name-tag` | Yes | — | Base name for resource tags |
| `--allowed-ips` | Yes | — | Comma-separated CIDRs for SSH/HTTPS access |
| `--license-type` | No | `byol` | License type (see `marketplace_skus.yaml`) |
| `--custom-image-id` | No | — | ARM resource ID of a custom Managed Image; bypasses Marketplace |
| `--version` | No | — | Marketplace image version (e.g., `12.1.5`). Partial `X.Y` selects latest patch |
| `--ssh-key-file` | No | `~/.ssh/id_rsa.pub` | Path to SSH public or private key file |
| `--vm-size` | No | `Standard_D8s_v5` | Azure VM size |
| `--vnet-cidr` | No | `10.0.0.0/16` | VNet CIDR block |
| `--public-subnet-cidr` | No | `10.0.1.0/24` | Public subnet CIDR |
| `--private-subnet-cidr` | No | `10.0.2.0/24` | Private subnet CIDR |
| `--subscription-id` | No | *(current az login)* | Azure subscription ID |
| `--deployment-prefix` | No | *(auto-generated)* | 6-char prefix for resource names |
| `--custom-data` | No | — | Path to a custom-data file or raw string |
| `--auth-code` | No | — | BYOL auth code for basic bootstrapping (requires `--pin-id` and `--pin-value`) |
| `--pin-id` | No | — | VM-Series auto-registration PIN ID |
| `--pin-value` | No | — | VM-Series auto-registration PIN value |

**Deploying from a custom Managed Image:**

When using `--custom-image-id`, you must still specify `--license-type` so the correct plan metadata is attached to the VM (required by Azure when deploying from generalized images based on Marketplace sources).

```
python azure_create_infra.py create \
    --region eastus \
    --name-tag "pa-fw-from-image" \
    --allowed-ips "YOUR_IP/32" \
    --custom-image-id "/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/images/my-image" \
    --license-type byol
```

---

### destroy

Deletes the Resource Group, which cascade-deletes everything inside it (VNet, subnets, NSG, Public IPs, NICs, VM).

```
python azure_create_infra.py destroy --deployment-file abc123-state.json
```

---

### set-admin-password

Sets a random admin password and saves it to the state file. Required before any API operations.

```
python azure_create_infra.py set-admin-password --deployment-file abc123-state.json
```

---

### upgrade-content

Downloads and installs the latest content update.

```
python azure_create_infra.py upgrade-content --deployment-file abc123-state.json
```

---

### upgrade-antivirus

Downloads and installs the latest antivirus update. The firewall must be licensed.

```
python azure_create_infra.py upgrade-antivirus --deployment-file abc123-state.json
```

---

### upgrade-panos

Upgrades PAN-OS software to a specified version.

```
python azure_create_infra.py upgrade-panos \
    --deployment-file abc123-state.json \
    --target-version "12.1.5"
```

Accepts exact (`11.1.2`), partial (`11.1`), or explicit-latest (`11.1.latest`) version specs.

---

### create-image

Deallocates, generalizes, and creates a Managed Image from the deployment VM. The VM must be stopped first (e.g., after a private-data-reset).

```
python azure_create_infra.py create-image \
    --deployment-file abc123-state.json \
    --image-name "my-custom-panos-image"
```

`--image-name` is optional; a name will be generated if omitted.

**Note:** This command also deallocates the VM as part of the capture process. After image creation, the source VM can no longer be started — it exists only as a Managed Image source.

---

### create-custom-image

Compound workflow: deploys a temporary environment, auto-registers the firewall via bootstrap `custom_data`, upgrades PAN-OS (and optionally antivirus), performs a private data reset, and captures a golden Managed Image. Optionally destroys the temporary infrastructure afterwards.

```
python azure_create_infra.py create-custom-image \
    --region eastus \
    --name-tag "my-golden-image" \
    --allowed-ips "YOUR_IP/32" \
    --auth-code "YOUR-AUTH-CODE" \
    --pin-id "YOUR-PIN-ID" \
    --pin-value "YOUR-PIN-VALUE" \
    --target-upgrade-version "12.1"
```

| Argument | Required | Default | Description |
|---|---|---|---|
| `--region` | Yes | — | Azure region |
| `--name-tag` | Yes | — | Base name for resources |
| `--allowed-ips` | Yes | — | Comma-separated CIDRs for SSH/HTTPS access |
| `--auth-code` | Yes | — | BYOL auth code for bootstrap auto-registration |
| `--pin-id` | Yes | — | VM-Series auto-registration PIN ID |
| `--pin-value` | Yes | — | VM-Series auto-registration PIN value |
| `--target-upgrade-version` | Yes | — | Target PAN-OS version — exact (`12.1.5`), partial (`12.1`), or `12.1.latest` |
| `--license-type` | No | `byol` | License type |
| `--version` | No | — | Base Marketplace image version. If omitted and `--target-upgrade-version` is partial, same `X.Y` is used |
| `--ssh-key-file` | No | `~/.ssh/id_rsa.pub` | Path to SSH public or private key file |
| `--vm-size` | No | `Standard_D8s_v5` | Azure VM size |
| `--vnet-cidr` | No | `10.0.0.0/16` | VNet CIDR block |
| `--public-subnet-cidr` | No | `10.0.1.0/24` | Public subnet CIDR |
| `--private-subnet-cidr` | No | `10.0.2.0/24` | Private subnet CIDR |
| `--subscription-id` | No | *(current az login)* | Azure subscription ID |
| `--upgrade-antivirus` | No | `false` | Also upgrade antivirus after content upgrade |
| `--auto-destroy` | No | `false` | Destroy temporary infrastructure after image creation |

**Workflow steps:**

1. Deploy Resource Group, VNet, subnets, NSG, Public IPs, NICs, VM
2. Wait for chassis ready (SSH `show chassis-ready`)
3. Wait for serial number (SSH poll `show system info`)
4. Set admin password
5. Resolve `--target-upgrade-version` to exact version via live firewall
6. Upgrade content
7. Optionally upgrade antivirus (`--upgrade-antivirus`)
8. Upgrade PAN-OS to resolved version (firewall reboots)
9. Wait for SSH post-reboot
10. `request system private-data-reset shutdown` via SSH
11. Wait for VM stopped state
12. Deallocate VM (`begin_deallocate`)
13. Generalize VM (`generalize`)
14. Create Managed Image
15. Print summary
16. Optionally destroy Resource Group (`--auto-destroy`)

**Version resolution:**

| Form | Example | Behavior |
|---|---|---|
| Exact | `12.1.5` | Upgrades to exactly `12.1.5` |
| Partial | `12.1` | Resolves to the latest `12.1.x` available on the update server at run time |
| Explicit latest | `12.1.latest` | Same as partial |

When a partial spec is used and `--version` is omitted, the base Marketplace image is also selected from the same `X.Y` family (latest available in the Marketplace). This means a single argument drives both the starting image and the upgrade target:

```
# Deploy latest 12.1.x Marketplace image, upgrade to latest 12.1.x patch
python azure_create_infra.py create-custom-image ... --target-upgrade-version 12.1

# Deploy 12.1.5 specifically, upgrade to latest 12.1.x patch
python azure_create_infra.py create-custom-image ... --target-upgrade-version 12.1 --version 12.1.5

# Deploy latest 12.1.x Marketplace image, upgrade to exactly 12.1.5
python azure_create_infra.py create-custom-image ... --target-upgrade-version 12.1.5
```

---

### create-custom-image-restart

Resumes an interrupted `create-custom-image` from its state file. Inspects completed steps and picks up where the workflow left off.

```
python azure_create_infra.py create-custom-image-restart --deployment-file abc123-state.json
```

`--ssh-key-file` is optional; falls back to the path recorded in the state file.

---

## Azure Marketplace Explorer

`azure_marketplace_explorer.py` is a standalone utility for discovering VM-Series versions available in Azure regions. Useful for planning deployments and understanding Marketplace lag before running `create` or `create-custom-image`.

```
python azure_marketplace_explorer.py <command> [options]
```

---

### list-versions

Lists available VM-Series Marketplace versions for a region and license type, sorted newest first.

```
# Interactive license type selection
python azure_marketplace_explorer.py list-versions --region eastus

# Non-interactive
python azure_marketplace_explorer.py list-versions --region eastus --license-type byol
```

| Argument | Required | Default | Description |
|---|---|---|---|
| `--region` | No | `eastus` | Azure region to query |
| `--license-type` | No | — | License type (e.g., `byol`). If omitted, an interactive menu is shown |

---

### find-regional-inconsistencies

Scans a curated set of Azure regions for a given license type and reports which versions are missing from which regions. Useful for validating Marketplace availability before a multi-region rollout.

```
python azure_marketplace_explorer.py find-regional-inconsistencies --license-type byol
```

---

## Azure CLI: Marketplace Discovery

The `azure_marketplace_explorer.py` script is the recommended way to discover VM-Series versions. If you prefer native Azure CLI commands directly, the following are equivalent.

**List all available VM-Series SKUs (license types) for an offer:**

```bash
az vm image list-skus \
  --publisher paloaltonetworks \
  --offer vmseries-flex \
  --location eastus \
  --output table
```

**List all versions for a SKU, sorted newest first:**

```bash
az vm image list \
  --publisher paloaltonetworks \
  --offer vmseries-flex \
  --sku byol \
  --location eastus \
  --all \
  --query 'sort_by(@, &version) | reverse(@) | [].version' \
  --output table
```

**Show full detail for a specific version (includes deprecation status):**

```bash
az vm image show \
  --publisher paloaltonetworks \
  --offer vmseries-flex \
  --sku byol \
  --version 12.1.5 \
  --location eastus
```

Check `imageDeprecationStatus.imageState` in the output — deprecated versions will return `ImageVersionDeprecated` and cannot be deployed.

**Check what versions are available in a different region:**

```bash
az vm image list \
  --publisher paloaltonetworks \
  --offer vmseries-flex \
  --sku byol \
  --location westeurope \
  --all \
  --query 'sort_by(@, &version) | reverse(@) | [0:5].version' \
  --output table
```

**Accept Marketplace terms (one-time per subscription per SKU):**

```bash
az vm image terms accept \
  --publisher paloaltonetworks \
  --offer vmseries-flex \
  --plan byol
```

---

## Azure CLI: Regional Image Distribution

Azure Managed Images are region-specific. The recommended production approach for multi-region distribution is **Azure Compute Gallery**, which handles replication automatically.

### Option A — Azure Compute Gallery (recommended)

```bash
# 1. Create a gallery (one-time)
az sig create \
  --resource-group my-rg \
  --gallery-name VMSeriesGallery \
  --location eastus

# 2. Create an image definition (one-time per license type)
az sig image-definition create \
  --resource-group my-rg \
  --gallery-name VMSeriesGallery \
  --gallery-image-definition vm-series-byol \
  --publisher PaloAltoNetworks \
  --offer VM-Series \
  --sku byol \
  --os-type Linux \
  --location eastus

# 3. Add a version from a Managed Image — specify all target regions here
az sig image-version create \
  --resource-group my-rg \
  --gallery-name VMSeriesGallery \
  --gallery-image-definition vm-series-byol \
  --gallery-image-version 12.1.5 \
  --managed-image /subscriptions/SUB/resourceGroups/my-rg/providers/Microsoft.Compute/images/my-golden-image \
  --target-regions eastus westus2 westeurope northeurope \
  --replica-count 1
```

The gallery version ID can then be used as `--custom-image-id` in `azure_create_infra.py`.

**Check replication status:**

```bash
az sig image-version show \
  --resource-group my-rg \
  --gallery-name VMSeriesGallery \
  --gallery-image-definition vm-series-byol \
  --gallery-image-version 12.1.5 \
  --query 'replicationStatus'
```

### Option B — az image copy extension (simpler, no gallery)

```bash
# Install extension once
az extension add --name image-copy-extension

# Copy Managed Image to additional regions
az image copy \
  --source-resource-group my-rg \
  --source-object-name my-golden-image \
  --target-location westus2 westeurope \
  --target-resource-group my-rg \
  --cleanup
```

This creates a separate Managed Image in each target region. Suitable for small-scale distribution; Compute Gallery is preferred for more than 2–3 regions.

---

## Full Argument Reference

```
python azure_create_infra.py --help
python azure_create_infra.py create --help
python azure_create_infra.py create-custom-image --help

python azure_marketplace_explorer.py --help
python azure_marketplace_explorer.py list-versions --help
```

---

## State File

Each deployment generates a `<prefix>-state.json` file that tracks all created resources. This file is required for all subsequent commands (`destroy`, `set-admin-password`, `upgrade-*`, etc.).

**Keep this file safe** — it contains passwords and Azure resource IDs. It is excluded from git by `.gitignore`.

Example state file structure:

```json
{
  "deployment_prefix": "abc123",
  "subscription_id": "...",
  "resource_group": "abc123-my-tag-rg",
  "region": "eastus",
  "vnet_id": "...",
  "public_subnet_id": "...",
  "private_subnet_id": "...",
  "nsg_id": "...",
  "public_ip_mgmt_id": "...",
  "public_ip_untrust_id": "...",
  "nic_mgmt_id": "...",
  "nic_untrust_id": "...",
  "nic_trust_id": "...",
  "vm_name": "abc123-my-tag-vm",
  "vm_id": "...",
  "public_ip": "1.2.3.4",
  "admin_password": "...",
  "actions_performed": [...],
  "created_images": [...]
}
```
