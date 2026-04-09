AWS Infrastructure CLI for Palo Alto Networks VM-Series
A Python CLI tool to deploy, manage, license, upgrade, and snapshot Palo Alto Networks VM-Series firewalls in AWS. Automates the end-to-end lifecycle for development, testing, and golden image creation.

---

License
MIT License — see [LICENSE](../LICENSE) for full text.

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

---

Warning & Disclaimer
**This tool is intended for lab, demo, development, and testing purposes only. It is not designed, tested, or supported for use in production environments.**

This script creates AWS resources that will incur costs. Always destroy infrastructure with the `destroy` command when finished to avoid unexpected charges. The user is solely responsible for all associated AWS costs, any licensing fees, and ensuring compliance with Palo Alto Networks' terms of service and AWS Marketplace subscription agreements.

This project is not affiliated with, endorsed by, or supported by Palo Alto Networks, Inc. or Amazon Web Services, Inc.

---

Features
- **create**: Deploys a complete AWS environment — VPC, public/private subnets, IGW, route tables, security groups, and a multi-NIC VM-Series instance. Optionally bootstraps the firewall via instance metadata (auto-registration).
- **destroy**: Tears down all created resources in the correct order using the state file.
- **create-restart**: Resumes an interrupted `create` from where it left off.
- **set-admin-password**: Sets a strong random admin password and saves it to the state file for API access.
- **license-firewall**: Applies a BYOL auth code via SSH, handles the required reboot, and verifies licensing. Use when not bootstrapping.
- **upgrade-content**: Downloads and installs the latest content update via the PAN-OS API. Requires a licensed firewall.
- **upgrade-panos**: Upgrades PAN-OS software to a specified version via the API. Requires content to be current.
- **upgrade-antivirus**: Downloads and installs the latest antivirus update via the API. Requires a licensed firewall.
- **upgrade-vmseries-plugin**: Installs a specific VM-Series plugin version.
- **create-ami**: Creates an AMI snapshot from an existing deployment.
- **create-custom-ami**: Compound workflow — deploys with bootstrap user-data (auto-registers, gets serial + device cert on first boot), upgrades content and PAN-OS, performs private-data-reset, and snapshots into a golden AMI.

---

Prerequisites
- Python 3.12+ and pip
- AWS credentials configured (e.g., via `aws configure`)
- AWS Marketplace subscription to the VM-Series product for your target region

Install dependencies:

```
pip install -r requirements.txt
```

---

File Overview

| File | Description |
|---|---|
| `aws_create_infra.py` | Main script for all create, manage, and upgrade operations |
| `aws_marketplace_explorer.py` | Utility for discovering AMI versions and product codes by region |
| `product_codes.yaml` | Maps license type names to AWS Marketplace product codes |
| `requirements.txt` | Python package dependencies |

---

Usage

All commands follow the pattern:

```
python aws_create_infra.py <command> [options]
```

---

### create

Deploys a new VPC and VM-Series instance. Generates a state file (e.g., `abc123-state.json`) used by all subsequent commands.

```
python aws_create_infra.py create \
    --region <aws_region> \
    --name-tag <base_name> \
    --allowed-ips "YOUR_IP/32"
```

All options with defaults can be omitted:

```
python aws_create_infra.py create \
    --region us-west-2 \
    --name-tag "pa-fw-test" \
    --allowed-ips "192.0.2.1/32,198.51.100.1/32" \
    --auth-code "YOUR-AUTH-CODE"
```

| Argument | Required | Default | Description |
|---|---|---|---|
| `--region` | Yes | — | AWS region |
| `--name-tag` | Yes | — | Base name for resource tags |
| `--allowed-ips` | Yes | — | Comma-separated CIDRs for SSH/HTTPS access |
| `--license-type` | No | `byol-x86` | License type (see `product_codes.yaml` for choices) |
| `--ami-id` | No | — | Specific AMI ID, bypasses license/version lookup |
| `--version` | No | — | Specific PAN-OS version (e.g., `11.0.3`) |
| `--ssh-key-file` | No | `~/.ssh/id_rsa.pub` | Path to SSH public or private key file |
| `--instance-type` | No | `m5.xlarge` | EC2 instance type |
| `--vpc-cidr` | No | `10.0.0.0/16` | VPC CIDR block |
| `--public-subnet-cidr` | No | `10.0.1.0/24` | Public subnet CIDR |
| `--private-subnet-cidr` | No | `10.0.2.0/24` | Private subnet CIDR |
| `--deployment-prefix` | No | *(auto-generated)* | 6-char prefix for resource names |
| `--user-data` | No | — | Path to a user-data file or raw string (ignored if bootstrap params provided) |
| `--auth-code` | No | — | BYOL auth code for basic bootstrapping (requires `--pin-id` and `--pin-value`) |
| `--pin-id` | No | — | VM-Series auto-registration PIN ID |
| `--pin-value` | No | — | VM-Series auto-registration PIN value |

**Basic bootstrapping** (auto-registers on first boot, firewall gets serial + device cert automatically):

```
python aws_create_infra.py create \
    --region us-west-2 \
    --name-tag "pa-fw-test" \
    --allowed-ips "192.0.2.1/32" \
    --auth-code "YOUR-AUTH-CODE" \
    --pin-id "YOUR-PIN-ID" \
    --pin-value "YOUR-PIN-VALUE"
```

All three bootstrap params must be provided together. Without them, the firewall boots unlicensed (suitable for deployments that don't require content/PAN-OS upgrades).

**Custom user-data file** (non-bootstrap use):

```
python aws_create_infra.py create \
    --region us-west-2 \
    --name-tag "pa-fw-test" \
    --allowed-ips "192.0.2.1/32" \
    --user-data ./my-userdata.txt
```

---

### destroy

Destroys all resources associated with a deployment.

```
python aws_create_infra.py destroy --deployment-file abc123-state.json
```

---

### create-restart

Resumes an interrupted `create` using its state file.

```
python aws_create_infra.py create-restart --deployment-file abc123-state.json
```

---

### set-admin-password

Sets a random admin password and saves it to the state file. Required before any API operations.

```
python aws_create_infra.py set-admin-password --deployment-file abc123-state.json
```

---

### license-firewall

Applies a BYOL auth code to the firewall, reboots it, and verifies licensing.

```
python aws_create_infra.py license-firewall \
    --deployment-file abc123-state.json \
    --auth-code "YOUR-AUTH-CODE"
```

---

### upgrade-content

Downloads and installs the latest content update.

```
python aws_create_infra.py upgrade-content --deployment-file abc123-state.json
```

---

### upgrade-antivirus

Downloads and installs the latest antivirus update. The firewall must be licensed.

```
python aws_create_infra.py upgrade-antivirus --deployment-file abc123-state.json
```

---

### upgrade-panos

Upgrades PAN-OS software to a specified version.

```
python aws_create_infra.py upgrade-panos \
    --deployment-file abc123-state.json \
    --target-version "11.1.2"
```

---

### upgrade-vmseries-plugin

Installs a specific VM-Series plugin version.

```
python aws_create_infra.py upgrade-vmseries-plugin \
    --deployment-file abc123-state.json \
    --plugin-version "1.0.15"
```

---

### create-ami

Creates an AMI snapshot from an existing deployment.

```
python aws_create_infra.py create-ami \
    --deployment-file abc123-state.json \
    --ami-name "my-custom-panos-ami"
```

`--ami-name` is optional; a name will be generated if omitted.

---

### create-custom-ami

Compound workflow: deploys a temporary environment, licenses it, upgrades PAN-OS (and optionally a plugin), performs a private data reset, and captures a golden AMI. Optionally destroys the temporary infrastructure afterwards.

The firewall is bootstrapped via instance metadata — on first boot it auto-registers, acquires a serial number, and gets a device certificate. No manual licensing step is needed.

Workflow: deploy → wait for serial (auto-registration) → set admin password → upgrade content → upgrade PAN-OS (optional plugin) → private-data-reset + shutdown → create AMI.

```
python aws_create_infra.py create-custom-ami \
    --region us-east-1 \
    --name-tag "my-golden-ami" \
    --allowed-ips "192.0.2.1/32" \
    --auth-code "YOUR-AUTH-CODE" \
    --pin-id "YOUR-PIN-ID" \
    --pin-value "YOUR-PIN-VALUE" \
    --target-upgrade-version "11.1.2"
```

| Argument | Required | Default | Description |
|---|---|---|---|
| `--region` | Yes | — | AWS region |
| `--name-tag` | Yes | — | Base name for resource tags |
| `--allowed-ips` | Yes | — | Comma-separated CIDRs for SSH/HTTPS access |
| `--auth-code` | Yes | — | BYOL auth code for bootstrap auto-registration |
| `--pin-id` | Yes | — | VM-Series auto-registration PIN ID |
| `--pin-value` | Yes | — | VM-Series auto-registration PIN value |
| `--target-upgrade-version` | Yes | — | Target PAN-OS version — exact (`11.1.2`), or partial (`11.1` / `11.1.latest`) to resolve to latest patch |
| `--license-type` | No | `byol-x86` | License type |
| `--version` | No | — | Base AMI version to start from. If omitted and `--target-upgrade-version` is a partial spec, the same `X.Y` is used automatically |
| `--ssh-key-file` | No | `~/.ssh/id_rsa.pub` | Path to SSH public or private key file |
| `--instance-type` | No | `m5.xlarge` | EC2 instance type |
| `--vpc-cidr` | No | `10.0.0.0/16` | VPC CIDR block |
| `--public-subnet-cidr` | No | `10.0.1.0/24` | Public subnet CIDR |
| `--private-subnet-cidr` | No | `10.0.2.0/24` | Private subnet CIDR |
| `--plugin-version` | No | — | VM-Series plugin version to install (e.g., `1.0.15`) |
| `--auto-destroy` | No | `false` | Destroy temporary infrastructure after AMI creation |

**Version resolution**

`--target-upgrade-version` accepts three forms:

| Form | Example | Behavior |
|---|---|---|
| Exact | `11.1.2` | Upgrades to exactly `11.1.2` |
| Partial | `11.1` | Resolves to the latest `11.1.x` available on the update server at run time |
| Explicit latest | `11.1.latest` | Same as partial |

When a partial spec is used and `--version` is omitted, the base AMI is also selected from the same `X.Y` family (latest available in the Marketplace). This means a single argument drives both the starting AMI and the upgrade target:

```
# Deploy latest 11.1.x AMI, upgrade to latest 11.1.x patch
python aws_create_infra.py create-custom-ami ... --target-upgrade-version 11.1

# Deploy 11.1.2 specifically, upgrade to latest 11.1.x patch
python aws_create_infra.py create-custom-ami ... --target-upgrade-version 11.1 --version 11.1.2

# Deploy latest 11.1.x AMI, upgrade to exactly 11.1.6
python aws_create_infra.py create-custom-ami ... --target-upgrade-version 11.1.6
```

---

### create-custom-ami-restart

Resumes an interrupted `create-custom-ami` from its state file. Inspects completed steps and picks up where the workflow left off.

```
python aws_create_infra.py create-custom-ami-restart --deployment-file abc123-state.json
```

`--ssh-key-file` is optional; falls back to the path recorded in the state file.

---

## AWS Marketplace Explorer

`aws_marketplace_explorer.py` is a standalone utility for discovering VM-Series AMI versions and product codes across AWS regions. Useful for planning deployments and validating Marketplace availability before running `create` or `create-custom-ami`.

```
python aws_marketplace_explorer.py <command> [options]
```

---

### list-versions

Lists available VM-Series AMI versions for a region and license type, sorted newest first by version number.

```
# Interactive license type selection
python aws_marketplace_explorer.py list-versions --region us-east-1

# Non-interactive
python aws_marketplace_explorer.py list-versions --region us-east-1 --license-type byol-x86

# By product code directly
python aws_marketplace_explorer.py list-versions --region us-east-1 --product-code 6njl1pau431dv1qxipg63mvah
```

| Argument | Required | Default | Description |
|---|---|---|---|
| `--region` | No | `us-east-1` | AWS region to search |
| `--license-type` | No | — | License type (e.g., `byol-x86`). If omitted, an interactive menu is shown |
| `--product-code` | No | — | AWS Marketplace product code. Overrides `--license-type` |

---

### find-product-code

Looks up the AWS Marketplace product code for a given AMI ID and cross-references it against known license types.

```
python aws_marketplace_explorer.py find-product-code \
    --region us-east-1 \
    --ami-id ami-0123456789abcdef0
```

---

### find-regional-inconsistencies

Scans all enabled AWS regions for a product code and reports which AMI versions are missing from which regions. Useful for validating Marketplace availability before a multi-region rollout.

```
python aws_marketplace_explorer.py find-regional-inconsistencies \
    --product-code 6njl1pau431dv1qxipg63mvah
```

`--region` defaults to `us-east-1` and is used only as the starting point for the region list query.

---

### allow-launch

Performs a DryRun to verify that a given instance type is compatible with a product code in a region. Creates and immediately deletes a temporary VPC and subnet for the check.

```
python aws_marketplace_explorer.py allow-launch \
    --region us-east-1 \
    --product-code 6njl1pau431dv1qxipg63mvah \
    --instance-type m5.xlarge
```

---

## AWS CLI: Marketplace Discovery

The `aws_marketplace_explorer.py` script is the recommended way to discover AMIs. If you prefer native AWS CLI commands directly, the following are equivalent.

**List all available VM-Series AMIs for a license type in a region, sorted newest first:**

```bash
# byol-x86 product code — see product_codes.yaml for others
aws ec2 describe-images \
  --owners aws-marketplace \
  --filters "Name=product-code,Values=6njl1pau431dv1qxipg63mvah" \
  --query 'sort_by(Images, &CreationDate) | reverse(@) | [].[ImageId,Name,CreationDate]' \
  --output table \
  --region us-east-1
```

**Find the product code for a known AMI ID:**

```bash
aws ec2 describe-images \
  --image-ids ami-0123456789abcdef0 \
  --query 'Images[0].ProductCodes' \
  --region us-east-1
```

**Check which AMI versions are available in a different region:**

```bash
aws ec2 describe-images \
  --owners aws-marketplace \
  --filters "Name=product-code,Values=6njl1pau431dv1qxipg63mvah" \
  --query 'sort_by(Images, &CreationDate) | reverse(@) | [0:5].[ImageId,Name,CreationDate]' \
  --output table \
  --region eu-west-1
```

---

## AWS CLI: Regional Image Distribution

AMIs are region-specific. After creating a golden AMI in one region, copy it to each target region before deploying there.

**Copy to a single region:**

```bash
aws ec2 copy-image \
  --source-region us-east-1 \
  --source-image-id ami-0123456789abcdef0 \
  --region us-west-2 \
  --name "vmseries-golden-11.1.2" \
  --description "VM-Series 11.1.2 golden image"
# Returns the new AMI ID in the destination region immediately (copy is async)
```

**Check copy status:**

```bash
aws ec2 describe-images \
  --image-ids ami-NEWID \
  --region us-west-2 \
  --query 'Images[0].[State,Name]' \
  --output text
# State will be "pending" until available
```

**Copy to multiple regions (loop):**

```bash
SOURCE_REGION=us-east-1
SOURCE_AMI=ami-0123456789abcdef0
IMAGE_NAME="vmseries-golden-11.1.2"

for REGION in us-west-2 eu-west-1 ap-southeast-1 ap-northeast-1; do
  NEW_AMI=$(aws ec2 copy-image \
    --source-region "$SOURCE_REGION" \
    --source-image-id "$SOURCE_AMI" \
    --region "$REGION" \
    --name "$IMAGE_NAME" \
    --query 'ImageId' --output text)
  echo "$REGION: $NEW_AMI"
done
```

**Wait for all copies to become available:**

```bash
for REGION in us-west-2 eu-west-1 ap-southeast-1; do
  aws ec2 wait image-available --image-ids <AMI-ID-IN-REGION> --region "$REGION"
  echo "$REGION: ready"
done
```

---

## Full Argument Reference

```
python aws_create_infra.py --help
python aws_create_infra.py create --help
python aws_create_infra.py create-custom-ami --help

python aws_marketplace_explorer.py --help
python aws_marketplace_explorer.py list-versions --help
```
