VM-Series Infrastructure CLI
Python CLI tools for deploying, upgrading, and capturing golden images of Palo Alto Networks VM-Series firewalls on AWS and Azure.

---

License
MIT License — see [LICENSE](LICENSE) for full text.

This software is provided "as is", without warranty of any kind. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability arising from use of this software.

---

Warning & Disclaimer
**These tools are intended for lab, demo, development, and testing purposes only. They are not designed, tested, or supported for use in production environments.**

Running these tools creates cloud resources that incur costs. Always destroy infrastructure when finished. The user is solely responsible for all cloud costs, licensing fees, and compliance with Palo Alto Networks' terms of service and Marketplace subscription agreements.

This project is not affiliated with, endorsed by, or supported by Palo Alto Networks, Inc., Amazon Web Services, Inc., or Microsoft Corporation.

---

Why These Tools Exist
Palo Alto Networks publishes VM-Series firewall images to the AWS and Azure Marketplaces, but **not every PAN-OS version is published, and there is a lag between a PAN-OS release and its Marketplace availability.** When you need a specific version — for compliance, consistency with an existing fleet, or to pick up a recent patch — you cannot always deploy it directly.

The solution documented by PAN is:

1. Deploy whatever version **is** available in the Marketplace.
2. Boot the firewall and upgrade it to the desired version via the PAN-OS API.
3. Perform a private-data-reset to wipe instance-specific state.
4. Capture the result as a reusable golden image (AMI on AWS, Managed Image on Azure).

Subsequent deployments use that golden image, so every instance starts at exactly the right version without any post-boot upgrade step.

These tools automate that full lifecycle — from first deploy through upgrade, reset, and image capture — in a single command (`create-custom-ami` / `create-custom-image`), with a state file that lets interrupted runs resume where they left off.

**Reference documentation:**
- [Create a Custom AMI — VM-Series on AWS](https://docs.paloaltonetworks.com/vm-series/11-1/vm-series-deployment/set-up-the-vm-series-firewall-on-aws/deploy-the-vm-series-firewall-on-aws/create-custom-ami)
- [Create a Custom VM-Series Image for Azure](https://docs.paloaltonetworks.com/vm-series/11-1/vm-series-deployment/set-up-the-vm-series-firewall-on-azure/create-a-custom-vm-series-image-for-azure)

---

Device Certificate Requirement
PAN-OS content and software upgrades require a **Device Certificate**. Without one, upgrade API calls fail — which means the `create-custom-ami` / `create-custom-image` workflow cannot complete.

**Why `--pin-id` / `--pin-value` are required, not optional:**
The only automated path to a Device Certificate is via bootstrap registration PIN. When `--pin-id` and `--pin-value` are passed, the firewall auto-enrolls a Device Certificate on first boot before any upgrade is attempted. Generate a Registration PIN in the [Customer Support Portal](https://support.paloaltonetworks.com) under Assets → Device Certificates.

Without PIN bootstrap, the only alternative is a manual OTP procedure: boot the firewall, retrieve the serial number, generate a one-time password in the CSP, then install the Device Certificate by SSH or API before upgrades can run. The serial number is not known until after the firewall boots and registers, so it cannot be scripted end-to-end without PIN. See [Install a Device Certificate on the VM-Series Firewall](https://docs.paloaltonetworks.com/vm-series/11-1/vm-series-deployment/license-the-vm-series-firewall/vm-series-models/install-a-device-certificate-on-the-vm-series-firewall) for the manual procedure.

**`private-data-reset` before image capture wipes the Device Certificate** — this is correct and expected. Each deployment from the golden image re-enrolls automatically via bootstrap PIN params at first boot.

[PAN Advisory: PAN-OS Certificate Expirations and Device Certificate Management](https://live.paloaltonetworks.com/t5/customer-advisories/update-to-additional-pan-os-certificate-expirations-and-new/ta-p/572158)

---

How It Works

### Golden image workflow (both clouds)

```
Deploy from Marketplace
        │
        ▼
Bootstrap (auto-registration via instance metadata)
        │
        ▼
Wait for serial number (licensing complete)
        │
        ▼
Set admin password
        │
        ▼
Upgrade content
        │
        ▼
Upgrade PAN-OS to target version  ◄── resolves X.Y → latest X.Y.Z
        │  (firewall reboots)
        ▼
Wait for SSH
        │
        ▼
private-data-reset + shutdown
        │
        ▼
Capture golden image
        │
        ▼ (optional)
Destroy temporary infrastructure
```

### AWS vs Azure differences

| | AWS | Azure |
|---|---|---|
| Golden image | AMI | Managed Image |
| Capture process | `create_image()` (instance can be running or stopped) | Stop → deallocate → generalize → `images.create()` |
| Destroy | Ordered teardown of each resource | Delete Resource Group (cascade) |
| Auth | `aws configure` / IAM | `az login` / DefaultAzureCredential |

---

Repository Layout

```
aws/
  aws_create_infra.py          # AWS CLI
  aws_marketplace_explorer.py  # Discover available AMI versions by region
  product_codes.yaml           # License type → Marketplace product code
  requirements.txt
  README.md

azure/
  azure_create_infra.py        # Azure CLI
  azure_marketplace_explorer.py  # Discover available versions by region
  marketplace_skus.yaml        # License type → Azure Marketplace SKU
  requirements.txt
  README.md
```

---

Getting Started

See the cloud-specific README for full usage:

- **[aws/README.md](aws/README.md)** — AWS setup, commands, and argument reference
- **[azure/README.md](azure/README.md)** — Azure setup, commands, and argument reference
