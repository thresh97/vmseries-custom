# OCI VM-Series Infrastructure Tool

Python CLI for deploying and managing Palo Alto Networks VM-Series firewalls on Oracle Cloud Infrastructure (OCI). Mirrors the AWS, Azure, and GCP tools in this repository.

---

## Overview

### Networking Model

One VCN with three regional subnets:

| Interface | Subnet | CIDR | Public IP | skip_src_dst |
|-----------|--------|------|-----------|--------------|
| NIC0 (mgmt) | `mgmt` | 10.0.1.0/24 | Yes (ephemeral) | No |
| NIC1 (untrust) | `untrust` | 10.0.2.0/24 | Yes (ephemeral) | Yes |
| NIC2 (trust) | `trust` | 10.0.3.0/24 | No (private) | Yes |

The primary VNIC (mgmt/NIC0) is attached at instance launch. Secondary VNICs (untrust, trust) are hot-attached after the instance reaches RUNNING state.

### Why `create-custom-image`?

PAN does not publish every PAN-OS version to the OCI Marketplace. This tool automates the golden image workflow:

1. Deploy from the latest Marketplace image (using `--image-ocid` found via the explorer, or auto-subscribed via `--license-type`)
2. Bootstrap with auth code + auto-registration PIN via `user_data`
3. Upgrade to target PAN-OS version via API
4. Run `private-data-reset` + shutdown
5. Capture an OCI custom image

The resulting image can be reused for future deployments with `--image-ocid`.

---

## Prerequisites

- Python 3.12+
- OCI credentials configured:
  - **api_key** (default): `~/.oci/config` — run `oci setup config`
  - **instance_principal**: no config file; runs on OCI compute with IAM policy
  - **security_token**: `~/.oci/config` profile with `security_token_file` entry
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

---

## Quick Start

### 1. Find the image OCID (recommended)

```bash
python oci_marketplace_explorer.py list-listings \
    --compartment-id ocid1.compartment.oc1..xxx \
    --region us-ashburn-1 \
    --license-type byol
```

Copy the "Latest image OCID" from the output. Using `--image-ocid` directly is more reliable than the auto-subscription flow and avoids Marketplace API permission issues.

### 2. Deploy a firewall

```bash
python oci_create_infra.py create \
    --compartment-id ocid1.compartment.oc1..xxx \
    --region us-ashburn-1 \
    --name-tag pa-fw-test \
    --allowed-ips "YOUR_IP/32" \
    --image-ocid ocid1.image.oc1.iad.xxx \
    --ssh-key-file ~/.ssh/id_rsa.pub
```

A state file `<prefix>-state.json` is created to track all resources.

### 3. Set admin password (required before API upgrades)

```bash
python oci_create_infra.py set-admin-password \
    --deployment-file abc123-state.json
```

### 4. Destroy the deployment

```bash
python oci_create_infra.py destroy --deployment-file abc123-state.json
```

---

## Commands

| Command | Description |
|---------|-------------|
| `create` | Deploy VCN + 3 subnets + 3-NIC VM-Series instance |
| `destroy` | Ordered teardown of all resources |
| `set-admin-password` | Set a random admin password via SSH |
| `upgrade-content` | Install latest content update via API |
| `upgrade-panos` | Upgrade PAN-OS to a target version via API |
| `upgrade-antivirus` | Install latest antivirus update via API |
| `create-image` | Stop instance and capture OCI custom image |
| `create-custom-image` | Full golden image workflow (deploy → upgrade → reset → snapshot) |
| `create-custom-image-restart` | Resume an interrupted `create-custom-image` |

---

## `create-custom-image` Example

```bash
python oci_create_infra.py create-custom-image \
    --compartment-id ocid1.compartment.oc1..xxx \
    --region us-ashburn-1 \
    --name-tag golden-image \
    --allowed-ips "YOUR_IP/32" \
    --license-type byol \
    --auth-code "YOUR-AUTH-CODE" \
    --pin-id "YOUR-PIN-ID" \
    --pin-value "YOUR-PIN-VALUE" \
    --target-upgrade-version "11.1" \
    --ssh-key-file ~/.ssh/id_rsa.pub \
    --auto-destroy
```

If the process is interrupted, resume it with:

```bash
python oci_create_infra.py create-custom-image-restart \
    --deployment-file <prefix>-state.json
```

---

## Key Parameters

### `create` / `create-custom-image`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--compartment-id` | required | OCI compartment OCID |
| `--region` | required | OCI region (e.g., `us-ashburn-1`) |
| `--availability-domain` | first AD in region | Full AD name (e.g., `Uocm:IAD-AD-1`) |
| `--name-tag` | required | Base name for all resources |
| `--image-ocid` | — | Image OCID (bypasses Marketplace lookup) |
| `--license-type` | `byol` | `byol` / `bundle1` / `bundle2` |
| `--shape` | `VM.Standard3.Flex` | OCI compute shape |
| `--ocpu-count` | `4` | OCPUs (flexible shapes) |
| `--memory-gb` | `16` | Memory in GB (flexible shapes) |
| `--vcn-cidr` | `10.0.0.0/16` | VCN CIDR block |
| `--mgmt-cidr` | `10.0.1.0/24` | Mgmt subnet CIDR |
| `--untrust-cidr` | `10.0.2.0/24` | Untrust subnet CIDR |
| `--trust-cidr` | `10.0.3.0/24` | Trust subnet CIDR |
| `--allowed-ips` | required | Comma-separated CIDRs for mgmt SSH/HTTPS access |
| `--ssh-key-file` | `~/.ssh/id_rsa.pub` | SSH public or private key path |
| `--auth-method` | `api_key` | `api_key` / `instance_principal` / `security_token` |

---

## State File

Each deployment creates `<prefix>-state.json` tracking all resource OCIDs:

```json
{
  "deployment_prefix": "abc123",
  "compartment_id": "ocid1.compartment.oc1...",
  "region": "us-ashburn-1",
  "availability_domain": "Uocm:IAD-AD-1",
  "vcn_id": "ocid1.vcn...",
  "internet_gateway_id": "ocid1.internetgateway...",
  "default_route_table_id": "ocid1.routetable...",
  "trust_route_table_id": "ocid1.routetable...",
  "mgmt_security_list_id": "ocid1.securitylist...",
  "untrust_security_list_id": "ocid1.securitylist...",
  "trust_security_list_id": "ocid1.securitylist...",
  "mgmt_subnet_id": "ocid1.subnet...",
  "untrust_subnet_id": "ocid1.subnet...",
  "trust_subnet_id": "ocid1.subnet...",
  "instance_id": "ocid1.instance...",
  "mgmt_vnic_id": "ocid1.vnic...",
  "untrust_vnic_attachment_id": "ocid1.vnicattachment...",
  "untrust_vnic_id": "ocid1.vnic...",
  "trust_vnic_attachment_id": "ocid1.vnicattachment...",
  "trust_vnic_id": "ocid1.vnic...",
  "public_ip": "1.2.3.4",
  "untrust_public_ip": "5.6.7.8",
  "admin_password": "...",
  "actions_performed": [...],
  "created_images": [...]
}
```

Creation is **idempotent**: if a run is interrupted, re-running the same command with the same prefix resumes from the last saved step.

---

## OCI CLI: Marketplace Discovery

`oci_marketplace_explorer.py` is the recommended discovery tool. If you prefer native OCI CLI commands directly, the following are equivalent.

**Search for VM-Series listings:**

```bash
oci marketplace listing list \
  --compartment-id ocid1.compartment.oc1..xxx \
  --name "Palo Alto Networks VM-Series" \
  --output table \
  --query 'data[*].{name:name, id:id, "pricing-types":"pricing-types"}'
```

**List packages (versions) for a listing, sorted newest first:**

```bash
oci marketplace package list \
  --listing-id ocid1.appcataloglisting.oc1..xxx \
  --compartment-id ocid1.compartment.oc1..xxx \
  --sort-by TIME_CREATED \
  --sort-order DESC \
  --output table \
  --query 'data[*].{version:version, "image-ocid":"app-catalog-listing-resource-id", "listing-resource-version":"app-catalog-listing-resource-version"}'
```

**Show detail for a specific package version:**

```bash
oci marketplace package get \
  --listing-id ocid1.appcataloglisting.oc1..xxx \
  --package-version "11.1.2" \
  --compartment-id ocid1.compartment.oc1..xxx
```

**List custom images you have created in a compartment, sorted newest first:**

```bash
oci compute image list \
  --compartment-id ocid1.compartment.oc1..xxx \
  --sort-by TIMECREATED \
  --sort-order DESC \
  --output table \
  --query 'data[*].{name:"display-name", ocid:id, created:"time-created", state:"lifecycle-state"}'
```

**Filter custom images by name prefix:**

```bash
oci compute image list \
  --compartment-id ocid1.compartment.oc1..xxx \
  --display-name "custom-byol" \
  --sort-by TIMECREATED \
  --sort-order DESC \
  --query 'data[*].{name:"display-name", ocid:id, created:"time-created"}'
```

---

## OCI CLI: Regional Image Distribution

OCI custom images are region-specific. After creating a golden image in one region, copy it to each target region before deploying there.

**Copy image to another region:**

```bash
oci compute image copy \
  --image-id ocid1.image.oc1.iad.xxx \
  --destination-region us-phoenix-1
# Returns the new image OCID in the destination region (copy is async)
```

**Check copy status in the destination region:**

```bash
oci compute image get \
  --image-id ocid1.image.oc1.phx.NEWID \
  --region us-phoenix-1 \
  --query 'data.{state:"lifecycle-state", name:"display-name"}'
# State will be "IMPORTING" until available
```

**Copy to multiple regions (loop):**

```bash
SOURCE_IMAGE=ocid1.image.oc1.iad.xxx

for REGION in us-phoenix-1 eu-frankfurt-1 ap-sydney-1 ap-tokyo-1; do
  NEW_OCID=$(oci compute image copy \
    --image-id "$SOURCE_IMAGE" \
    --destination-region "$REGION" \
    --query 'data.id' --raw-output)
  echo "$REGION: $NEW_OCID"
done
```

**Poll until all copies are AVAILABLE:**

```bash
# Run in the destination region; repeat per region
oci compute image get \
  --image-id ocid1.image.oc1.phx.NEWID \
  --region us-phoenix-1 \
  --query 'data."lifecycle-state"' --raw-output
# Keep polling until output is "AVAILABLE"
```

**Share an image with another compartment in the same tenancy:**

OCI images are shared via IAM policies rather than explicit permission grants on the image itself. Grant the target compartment's principals `use` permission on `compute-images` in the source compartment:

```bash
# Example policy statement (add via OCI Console or CLI)
# Allow group TargetGroup to use compute-images in compartment source-compartment
oci iam policy create \
  --compartment-id ocid1.tenancy.oc1..xxx \
  --name image-share-policy \
  --statements '["Allow group TargetGroup to use compute-images in compartment source-compartment"]' \
  --description "Allow TargetGroup to use VM-Series golden images"
```

---

## Destroy Order

Resources are deleted in dependency order:

1. Terminate instance → wait `TERMINATED`
2. Delete trust / untrust / mgmt subnets
3. Clear default route table routes
4. Delete trust private route table
5. Delete Internet Gateway
6. Delete mgmt / untrust / trust security lists
7. Delete VCN
