#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Azure Infrastructure CLI for Palo Alto Networks VM-Series

A Python CLI tool to create, destroy, monitor, or build custom Managed Images from a
Palo Alto Networks VM-Series firewall on Azure.

This script provides the following commands:
  1. `create`: Deploys a Resource Group, VNet, subnets, NSG, Public IPs, NICs, and a
     3-NIC VM-Series firewall VM. Creates a state file to track resources.
  2. `destroy`: Deletes the Resource Group (cascade-deletes all resources inside).
  3. `set-admin-password`: Connects to an existing deployment and sets a new
     random password for the 'admin' user.
  4. `upgrade-content`: Downloads and installs the latest content update via API.
  5. `upgrade-panos`: Upgrades the PAN-OS software via API to a specific version.
  6. `upgrade-antivirus`: Downloads and installs the latest antivirus update via API.
  7. `create-image`: Deallocates, generalizes, and creates a Managed Image from a deployment VM.
  8. `create-custom-image`: Compound command — deploy, upgrade, reset, snapshot.
  9. `create-custom-image-restart`: Resume an interrupted create-custom-image workflow.

Background — Why create-custom-image?
--------------------------------------
PAN does not publish every PAN-OS version to the Azure Marketplace. There is a lag
from PAN-OS release to Marketplace availability. The documented solution is:
  1. Deploy the latest available Marketplace version.
  2. Upgrade via PAN-OS API to the desired target version.
  3. Perform private-data-reset + shutdown.
  4. Deallocate and generalize the VM via Azure SDK.
  5. Capture as a Managed Image.

When deploying from a custom image, Azure requires plan metadata:
  --plan-name byol --plan-product vmseries-flex --plan-publisher paloaltonetworks

Prerequisites:
  - Python 3.12+
  - Azure credentials configured (run 'az login')
  - Required Python packages (see requirements.txt)

Example Usage:

# Create a firewall stack (generates a state file like 'abc123-state.json')
python azure_create_infra.py create \\
    --region eastus \\
    --name-tag "pa-fw-test" \\
    --allowed-ips "YOUR_IP/32"

# Create a custom Managed Image (full lifecycle)
python azure_create_infra.py create-custom-image \\
    --region eastus \\
    --name-tag "my-golden-image" \\
    --allowed-ips "YOUR_IP/32" \\
    --auth-code "YOUR-AUTH-CODE" \\
    --pin-id "YOUR-PIN-ID" \\
    --pin-value "YOUR-PIN-VALUE" \\
    --target-upgrade-version "11.1"
"""

import argparse
import base64
import ipaddress
import json
import logging
import re
import secrets
import string
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import setuptools  # must be imported before panos to provide distutils on Python 3.12+
import paramiko
import yaml

try:
    from panos import firewall
except ImportError as e:
    LOGGER = logging.getLogger(__name__)
    LOGGER.error("A required library is missing or could not be imported.")
    LOGGER.error(f"Specific error: {e}")
    LOGGER.error("Please ensure 'pan-os-python' and all its dependencies are installed correctly.")
    sys.exit(1)

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.subscription import SubscriptionClient
    from azure.core.exceptions import AzureError, ResourceNotFoundError
except ImportError as e:
    LOGGER = logging.getLogger(__name__)
    LOGGER.error("Azure SDK libraries not found.")
    LOGGER.error(f"Specific error: {e}")
    LOGGER.error("Please install dependencies: pip install -r requirements.txt")
    sys.exit(1)


# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOGGER = logging.getLogger(__name__)

# Reduce paramiko logging noise unless debugging
logging.getLogger("paramiko").setLevel(logging.WARNING)


# --- State and Config Management ---

def load_marketplace_skus() -> Dict[str, str]:
    """Loads marketplace SKU mappings from the external YAML file."""
    config_file = Path("marketplace_skus.yaml")
    if not config_file.is_file():
        LOGGER.error(f"Configuration file '{config_file}' not found in the current directory.")
        sys.exit(1)
    with config_file.open("r") as f:
        return yaml.safe_load(f)

MARKETPLACE_SKUS = load_marketplace_skus()


def save_state(prefix: str, state: Dict[str, Any]):
    """Saves the deployment state to a file."""
    state_file = Path(f"{prefix}-state.json")
    with state_file.open("w") as f:
        json.dump(state, f, indent=2)
    LOGGER.info(f"Deployment state saved to {state_file}")


def load_state(state_file_path: str) -> Dict[str, Any]:
    """Loads the deployment state from a file."""
    state_file = Path(state_file_path).expanduser()
    if not state_file.is_file():
        raise FileNotFoundError(f"State file {state_file} not found.")
    with state_file.open("r") as f:
        return json.load(f)


def generate_prefix(length=6):
    """Generates a secure random alphanumeric string for resource naming."""
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_password(length=16):
    """Generates a secure random alphanumeric password."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def get_and_validate_ssh_keys(key_file_arg: str) -> Tuple[Path, Path]:
    """Resolves and validates both the public and private SSH key paths."""
    key_path = Path(key_file_arg).expanduser()

    if key_path.suffix == '.pub':
        ssh_pub_key = key_path
        ssh_priv_key = key_path.with_suffix('')
    else:
        ssh_priv_key = key_path
        ssh_pub_key = key_path.with_suffix('.pub')

    if not ssh_pub_key.is_file():
        LOGGER.error(f"SSH public key file not found at: {ssh_pub_key}")
        sys.exit(1)
    if not ssh_priv_key.is_file():
        LOGGER.error(f"SSH private key file not found at: {ssh_priv_key}")
        sys.exit(1)

    return ssh_pub_key, ssh_priv_key


def get_subscription_id(credential, override: Optional[str] = None) -> str:
    """Returns the subscription ID from CLI arg or current az login context."""
    if override:
        return override
    sub_client = SubscriptionClient(credential)
    subs = list(sub_client.subscriptions.list())
    if not subs:
        LOGGER.error("No Azure subscriptions found. Please run 'az login'.")
        sys.exit(1)
    sub_id = subs[0].subscription_id
    LOGGER.info(f"Using subscription: {sub_id}")
    return sub_id


# --- SSH Interaction Class (cloud-agnostic) ---

class FirewallSSHClient:
    """A wrapper for Paramiko to handle interactive shell sessions with a firewall."""
    def __init__(self, public_ip: str, ssh_priv_key_path: Path, user: str = "admin"):
        self.public_ip = public_ip
        self.ssh_priv_key_path = ssh_priv_key_path
        self.user = user
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.shell = None

    def connect(self, max_retries=30, delay=20):
        """Connects to the firewall, opens a shell, and disables the pager."""
        for attempt in range(max_retries):
            try:
                LOGGER.info(f"Attempting SSH connection to {self.public_ip} (Attempt {attempt + 1}/{max_retries})...")
                self.client.connect(
                    hostname=self.public_ip, username=self.user,
                    key_filename=str(self.ssh_priv_key_path), timeout=15
                )
                LOGGER.info("✅ SSH connection successful with key authentication.")

                LOGGER.info("Opening interactive shell...")
                self.shell = self.client.invoke_shell()
                self.wait_for_prompt(timeout=90)

                LOGGER.info("Disabling CLI pager for this session...")
                self.send_command("set cli pager off")

                LOGGER.info("✅ Interactive shell is ready.")
                return
            except Exception as e:
                LOGGER.warning(f"SSH connection or shell opening failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                else:
                    raise TimeoutError("Could not establish an interactive SSH shell.")

    def close(self):
        """Closes the SSH connection."""
        if self.shell:
            self.shell.close()
        self.client.close()
        LOGGER.info("SSH client closed.")

    def wait_for_prompt(self, prompt_chars=['>', '#'], timeout=30):
        """Waits for one of the possible command prompts to appear and for output to cease."""
        output = ""
        start_time = time.time()
        self.shell.settimeout(timeout)

        while True:
            if time.time() - start_time > timeout:
                LOGGER.error(f"Timeout waiting for prompt. Full buffer received:\n---\n{output}\n---")
                raise TimeoutError("Timeout waiting for command prompt.")

            if self.shell.recv_ready():
                output += self.shell.recv(4096).decode('utf-8', errors='ignore')

            prompt_found = any(p in output for p in prompt_chars)

            if prompt_found:
                time.sleep(1)
                if not self.shell.recv_ready():
                    return output

            time.sleep(0.2)

    def send_command(self, command, prompt_chars=['>', '#'], timeout=60):
        """Sends a command and returns the output once a prompt reappears."""
        self.shell.send(command + '\n')
        full_output = self.wait_for_prompt(prompt_chars, timeout)
        lines = full_output.splitlines()
        if len(lines) > 1:
            return '\n'.join(lines[1:-1])
        return ""

    def reboot_and_reconnect(self, initial_wait=60):
        """Handles a firewall reboot by waiting and re-establishing connection."""
        LOGGER.info(f"Firewall is rebooting. Waiting {initial_wait}s before attempting to reconnect...")
        time.sleep(initial_wait)
        self.close()
        self.connect()


# --- PAN-OS API Functions (cloud-agnostic) ---

def upgrade_content_api(public_ip: str, password: str) -> Optional[str]:
    """Connects to a firewall via API, downloads and installs the latest content."""
    try:
        fw = firewall.Firewall(public_ip, "admin", password)
    except Exception as e:
        raise RuntimeError(f"Failed to connect to firewall API: {e}")

    LOGGER.info("Verifying firewall is licensed before starting content upgrade...")
    system_info = fw.op("show system info")
    serial = system_info.findtext("./result/system/serial")
    if not serial or serial == "unknown":
        raise RuntimeError("Firewall is not licensed. Cannot perform content upgrade.")
    LOGGER.info(f"✅ Firewall is licensed with serial: {serial}")

    updater = fw.content
    LOGGER.info("Requesting download and install of latest content...")
    updater.download_and_install_latest(sync=True)
    LOGGER.info("✅ Content download and installation complete.")
    return serial


def resolve_panos_version(public_ip: str, password: str, version_spec: str) -> str:
    """Resolves 'X.Y' or 'X.Y.latest' to the latest available patch version. Full 'X.Y.Z' passes through."""
    parts = version_spec.split(".")
    if len(parts) == 3 and parts[2].lower() != "latest":
        return version_spec
    if len(parts) == 2 or (len(parts) == 3 and parts[2].lower() == "latest"):
        major, minor = parts[0], parts[1]
    else:
        raise ValueError(f"Invalid version spec '{version_spec}'. Use 'X.Y', 'X.Y.latest', or 'X.Y.Z'.")

    LOGGER.info(f"Resolving '{version_spec}' → querying available PAN-OS versions...")
    fw = firewall.Firewall(public_ip, "admin", password)
    fw.software.check()
    prefix = f"{major}.{minor}."
    matching = [v for v in fw.software.versions.keys() if v.startswith(prefix)]
    if not matching:
        raise RuntimeError(f"No PAN-OS versions found matching {major}.{minor}.x on the update server.")

    def _vkey(v):
        result = []
        for part in v.split("."):
            base, *h = part.split("-h")
            result.append(int(base))
            result.append(int(h[0]) if h else 0)
        return result

    latest = sorted(matching, key=_vkey)[-1]
    LOGGER.info(f"✅ Resolved '{version_spec}' → '{latest}'")
    return latest


def upgrade_panos_api(public_ip: str, password: str, target_version: str) -> Optional[str]:
    """Connects to a firewall via API and upgrades the PAN-OS software."""
    try:
        fw = firewall.Firewall(public_ip, "admin", password)
    except Exception as e:
        raise RuntimeError(f"Failed to connect to firewall API: {e}")

    LOGGER.info("Verifying firewall is licensed before starting PAN-OS upgrade...")
    system_info = fw.op("show system info")
    serial = system_info.findtext("./result/system/serial")
    if not serial or serial == "unknown":
        raise RuntimeError("Firewall is not licensed. Cannot perform PAN-OS upgrade.")
    LOGGER.info(f"✅ Firewall is licensed with serial: {serial}")

    updater = fw.software
    LOGGER.info(f"Starting PAN-OS upgrade to version {target_version}...")
    try:
        updater.upgrade_to_version(target_version)
        LOGGER.info("✅ PAN-OS upgrade process completed successfully.")
    except Exception as e:
        if "no element found" in str(e) or "ParseError" in str(e):
            LOGGER.info("Device is rebooting after upgrade — XML API unavailable as expected. Continuing.")
        else:
            raise

    return serial


def upgrade_antivirus_api(public_ip: str, password: str) -> Optional[str]:
    """Connects to a firewall via API, downloads and installs the latest antivirus update."""
    try:
        fw = firewall.Firewall(public_ip, "admin", password)
    except Exception as e:
        raise RuntimeError(f"Failed to connect to firewall API: {e}")

    LOGGER.info("Verifying firewall is licensed before starting antivirus upgrade...")
    system_info = fw.op("show system info")
    serial = system_info.findtext("./result/system/serial")
    if not serial or serial == "unknown":
        raise RuntimeError("Firewall is not licensed. Cannot perform antivirus upgrade.")
    LOGGER.info(f"✅ Firewall is licensed with serial: {serial}")

    LOGGER.info("Checking for latest antivirus update...")
    check_response = fw.op(
        cmd="<request><anti-virus><upgrade><check/></upgrade></anti-virus></request>",
        cmd_xml=True
    )

    latest_version_info = None
    latest_date = None

    updates_root = check_response.find(".//content-updates")
    if updates_root is not None:
        for entry in updates_root.findall("entry"):
            release_str = entry.findtext("released-on", "").split(" ")[0]
            if not release_str:
                continue
            release_datetime = datetime.strptime(release_str, '%Y/%m/%d')
            if latest_date is None or release_datetime > latest_date:
                latest_date = release_datetime
                latest_version_info = {
                    "version": entry.findtext("version"),
                    "downloaded": entry.findtext("downloaded"),
                    "installed": entry.findtext("current")
                }

    if not latest_version_info:
        LOGGER.warning("Could not determine the latest antivirus version. Aborting.")
        return serial

    LOGGER.info(f"Latest antivirus version available: {latest_version_info['version']}")

    if latest_version_info['installed'] == 'yes':
        LOGGER.info("✅ Latest antivirus version is already installed.")
        return serial

    if latest_version_info['downloaded'] != 'yes':
        LOGGER.info("Requesting download of latest antivirus update...")
        response = fw.op(
            cmd="<request><anti-virus><upgrade><download><latest/></latest></download></upgrade></anti-virus></request>",
            cmd_xml=True
        )
        job_id = response.findtext('./result/job')
        if not job_id:
            raise RuntimeError("Could not find job ID for antivirus download task.")
        LOGGER.info(f"Download job started with ID: {job_id}. Monitoring progress...")
        while True:
            job_info = fw.op(cmd=f"<show><jobs><id>{job_id}</id></show>", cmd_xml=True)
            status = job_info.findtext('.//status')
            if status == "FIN":
                LOGGER.info("✅ Antivirus download complete.")
                break
            progress = job_info.findtext('.//progress')
            LOGGER.info(f"Download in progress - Status: {status}, Progress: {progress}%...")
            time.sleep(10)
    else:
        LOGGER.info("Latest antivirus version is already downloaded.")

    LOGGER.info(f"Requesting installation of version {latest_version_info['version']}...")
    install_cmd = (
        f"<request><anti-virus><upgrade><install>"
        f"<version>{latest_version_info['version']}</version>"
        f"</install></upgrade></anti-virus></request>"
    )
    response = fw.op(cmd=install_cmd, cmd_xml=True)
    job_id = response.findtext('./result/job')
    if not job_id:
        raise RuntimeError("Could not find job ID for antivirus install task.")
    LOGGER.info(f"Installation job started with ID: {job_id}. Monitoring progress...")
    while True:
        job_info = fw.op(cmd=f"<show><jobs><id>{job_id}</id></show>", cmd_xml=True)
        status = job_info.findtext('.//status')
        if status == "FIN":
            LOGGER.info("✅ Antivirus installation complete.")
            break
        progress = job_info.findtext('.//progress')
        LOGGER.info(f"Installation in progress - Status: {status}, Progress: {progress}%...")
        time.sleep(10)

    return serial


def wait_for_ssh_connectivity(public_ip: str, ssh_priv_key_path: Path, max_retries: int = 20, delay: int = 30) -> None:
    """Waits for SSH connectivity to the firewall, confirming it's reachable post-reboot."""
    LOGGER.info(f"Waiting for SSH connectivity to {public_ip} (max {max_retries} attempts, {delay}s delay)...")
    for attempt in range(max_retries):
        ssh = FirewallSSHClient(public_ip, ssh_priv_key_path)
        try:
            ssh.connect(max_retries=1, delay=0)
            LOGGER.info(f"✅ SSH connectivity confirmed on attempt {attempt + 1}.")
            ssh.close()
            return
        except Exception as e:
            LOGGER.warning(f"SSH connectivity check attempt {attempt + 1}/{max_retries} failed: {e}")
            try:
                ssh.close()
            except Exception:
                pass
            if attempt < max_retries - 1:
                time.sleep(delay)
    raise TimeoutError(f"Could not establish SSH connectivity to {public_ip} after {max_retries} attempts.")


def build_bootstrap_custom_data(auth_code: str, pin_id: str, pin_value: str) -> str:
    """Builds the custom_data string for basic VM-Series bootstrapping."""
    return (
        f"authcodes={auth_code}\n"
        f"vm-series-auto-registration-pin-id={pin_id}\n"
        f"vm-series-auto-registration-pin-value={pin_value}\n"
    )


def wait_for_serial_ssh(public_ip: str, ssh_priv_key_path: Path, timeout_minutes: int = 15) -> str:
    """Polls the firewall via SSH until it reports a valid serial number (auto-licensing complete)."""
    deadline = time.time() + timeout_minutes * 60
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            ssh = FirewallSSHClient(public_ip, ssh_priv_key_path)
            ssh.connect()
            try:
                info = ssh.send_command("show system info")
                match = re.search(r"^serial:\s+(\S+)", info, re.MULTILINE)
                if match and match.group(1) != "unknown":
                    serial = match.group(1)
                    LOGGER.info(f"✅ Serial number confirmed: {serial}")
                    return serial
                LOGGER.info(f"Attempt {attempt}: serial not yet assigned, waiting 30s...")
            finally:
                ssh.close()
        except Exception:
            LOGGER.info(f"Attempt {attempt}: SSH not ready, waiting 30s...")
        time.sleep(30)
    raise TimeoutError(f"Firewall did not receive a serial number within {timeout_minutes} minutes.")


def set_firewall_password(public_ip: str, ssh_priv_key_path: Path, new_password: str):
    """Connects to the firewall and sets the admin password."""
    ssh = FirewallSSHClient(public_ip, ssh_priv_key_path)
    try:
        ssh.connect()
        ssh.send_command("configure", prompt_chars=['#'])

        LOGGER.info("Setting admin password...")
        ssh.shell.send("set mgt-config users admin password\n")

        ssh.wait_for_prompt(prompt_chars=['Enter password   : '])
        ssh.shell.send(new_password + '\n')

        ssh.wait_for_prompt(prompt_chars=['Confirm password : '])
        ssh.shell.send(new_password + '\n')

        ssh.wait_for_prompt(prompt_chars=['#'])
        LOGGER.info("Password changed in candidate config.")

        LOGGER.info("Committing configuration...")
        commit_output = ssh.send_command("commit", prompt_chars=['#'], timeout=300)
        if "Configuration committed successfully" in commit_output:
            LOGGER.info("✅ Commit successful.")
        else:
            raise RuntimeError(f"Commit failed. Output:\n{commit_output}")

        ssh.send_command("exit", prompt_chars=['>'])

    finally:
        ssh.close()


def private_data_reset_and_wait_stopped(
    public_ip: str,
    ssh_priv_key_path: Path,
    compute_client: ComputeManagementClient,
    resource_group: str,
    vm_name: str,
):
    """Issues private-data-reset via SSH, then waits for the VM to reach stopped state."""
    ssh = FirewallSSHClient(public_ip, ssh_priv_key_path)
    try:
        ssh.connect()
        LOGGER.info("Sending private-data-reset command to the firewall...")
        ssh.shell.send("request system private-data-reset shutdown\n")

        ssh.wait_for_prompt(prompt_chars=['(y or n)'], timeout=30)
        LOGGER.info("Confirmation prompt received. Sending 'y' to confirm.")
        ssh.shell.send("y\n")

        LOGGER.info("Reset command confirmed. The firewall will now shut down.")
    except Exception as e:
        LOGGER.info(f"SSH session closed as expected after reset command: {e}")
    finally:
        ssh.close()

    LOGGER.info(f"Waiting for VM '{vm_name}' to reach 'stopped' power state...")
    max_wait = 600  # 10 minutes
    start = time.time()
    while time.time() - start < max_wait:
        try:
            vm = compute_client.virtual_machines.get(
                resource_group, vm_name, expand='instanceView'
            )
            statuses = {s.code: s for s in (vm.instance_view.statuses or [])}
            power_state = next(
                (code for code in statuses if code.startswith('PowerState/')), None
            )
            LOGGER.info(f"  Current power state: {power_state or 'unknown'}")
            if power_state in ('PowerState/stopped', 'PowerState/deallocated'):
                LOGGER.info(f"✅ VM '{vm_name}' has reached the '{power_state}' state.")
                return
        except AzureError as e:
            LOGGER.warning(f"Could not query VM state: {e}")
        time.sleep(30)
    raise TimeoutError(f"VM '{vm_name}' did not stop within {max_wait // 60} minutes.")


# --- Azure Resource Management ---

def get_marketplace_image_version(
    compute_client: ComputeManagementClient,
    region: str,
    sku: str,
    version_filter: Optional[str] = None,
) -> str:
    """
    Queries Azure Marketplace for available VM-Series versions and returns the
    version string for the best match. If version_filter is provided (e.g. '11.1'),
    returns the latest patch in that X.Y family.
    """
    LOGGER.info(f"Querying Azure Marketplace for VM-Series '{sku}' versions in '{region}'...")
    images = compute_client.virtual_machine_images.list(
        location=region,
        publisher_name="paloaltonetworks",
        offer="vmseries-flex",
        skus=sku,
    )
    all_versions = [img.name for img in images]
    if not all_versions:
        raise RuntimeError(
            f"No VM-Series images found for SKU '{sku}' in region '{region}'. "
            "Ensure your subscription has accepted the Marketplace terms."
        )

    def _vkey(v):
        result = []
        for part in re.split(r'[.\-]', v):
            try:
                result.append(int(part))
            except ValueError:
                result.append(0)
        return result

    if version_filter:
        prefix = version_filter.rstrip('.')
        matching = [v for v in all_versions if v.startswith(prefix + '.') or v == prefix]
        if not matching:
            raise RuntimeError(
                f"No VM-Series images found matching '{version_filter}' for SKU '{sku}' in '{region}'."
            )
        selected = sorted(matching, key=_vkey)[-1]
    else:
        selected = sorted(all_versions, key=_vkey)[-1]

    LOGGER.info(f"✅ Selected Marketplace image version: {selected}")
    return selected


def create_infrastructure(
    credential,
    subscription_id: str,
    region: str,
    name_tag: str,
    prefix: str,
    state: Dict[str, Any],
    license_type: str,
    version: Optional[str],
    vm_size: str,
    vnet_cidr: str,
    public_subnet_cidr: str,
    private_subnet_cidr: str,
    allowed_ips: List[str],
    ssh_pub_key_path: Path,
    custom_data: Optional[str] = None,
    custom_image_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates or resumes the full Azure stack for the VM-Series firewall."""
    compute_client = ComputeManagementClient(credential, subscription_id)
    network_client = NetworkManagementClient(credential, subscription_id)
    resource_client = ResourceManagementClient(credential, subscription_id)

    sku = MARKETPLACE_SKUS.get(license_type, license_type)
    rg_name = f"{prefix}-{name_tag}-rg"
    LOGGER.info(f"🚀 Starting/resuming infrastructure creation for '{name_tag}'...")

    # --- Resource Group ---
    if not state.get("resource_group"):
        LOGGER.info(f"Creating Resource Group '{rg_name}'...")
        resource_client.resource_groups.create_or_update(rg_name, {"location": region})
        state["resource_group"] = rg_name
        state["subscription_id"] = subscription_id
        save_state(prefix, state)
        LOGGER.info(f"✅ Resource Group created: {rg_name}")
    else:
        rg_name = state["resource_group"]
        LOGGER.info(f"✅ Resource Group exists: {rg_name}")

    # --- VNet ---
    vnet_name = f"{name_tag}-vnet"
    if not state.get("vnet_id"):
        LOGGER.info(f"Creating VNet '{vnet_name}' with CIDR {vnet_cidr}...")
        vnet = network_client.virtual_networks.begin_create_or_update(
            rg_name, vnet_name,
            {
                "location": region,
                "address_space": {"address_prefixes": [vnet_cidr]},
            }
        ).result()
        state["vnet_id"] = vnet.id
        state["vnet_name"] = vnet_name
        save_state(prefix, state)
        LOGGER.info(f"✅ VNet created: {vnet.id}")
    else:
        LOGGER.info(f"✅ VNet exists: {state['vnet_id']}")

    # --- NSG ---
    nsg_name = f"{name_tag}-nsg"
    if not state.get("nsg_id"):
        LOGGER.info(f"Creating NSG '{nsg_name}'...")
        security_rules = []
        for idx, cidr in enumerate(allowed_ips):
            security_rules.append({
                "name": f"allow-mgmt-ssh-{idx}",
                "priority": 100 + idx,
                "protocol": "Tcp",
                "access": "Allow",
                "direction": "Inbound",
                "source_address_prefix": cidr,
                "source_port_range": "*",
                "destination_address_prefix": "*",
                "destination_port_range": "22",
            })
            security_rules.append({
                "name": f"allow-mgmt-https-{idx}",
                "priority": 200 + idx,
                "protocol": "Tcp",
                "access": "Allow",
                "direction": "Inbound",
                "source_address_prefix": cidr,
                "source_port_range": "*",
                "destination_address_prefix": "*",
                "destination_port_range": "443",
            })
        nsg = network_client.network_security_groups.begin_create_or_update(
            rg_name, nsg_name,
            {"location": region, "security_rules": security_rules}
        ).result()
        state["nsg_id"] = nsg.id
        state["nsg_name"] = nsg_name
        save_state(prefix, state)
        LOGGER.info(f"✅ NSG created: {nsg.id}")
    else:
        LOGGER.info(f"✅ NSG exists: {state['nsg_id']}")

    # --- Public Subnet ---
    pub_subnet_name = f"{name_tag}-public-subnet"
    if not state.get("public_subnet_id"):
        LOGGER.info(f"Creating public subnet '{pub_subnet_name}'...")
        pub_subnet = network_client.subnets.begin_create_or_update(
            rg_name, vnet_name, pub_subnet_name,
            {"address_prefix": public_subnet_cidr}
        ).result()
        state["public_subnet_id"] = pub_subnet.id
        state["public_subnet_name"] = pub_subnet_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Public subnet created: {pub_subnet.id}")
    else:
        pub_subnet = type('obj', (object,), {'id': state["public_subnet_id"]})()
        LOGGER.info(f"✅ Public subnet exists: {state['public_subnet_id']}")

    # --- Private Subnet ---
    priv_subnet_name = f"{name_tag}-private-subnet"
    if not state.get("private_subnet_id"):
        LOGGER.info(f"Creating private subnet '{priv_subnet_name}'...")
        priv_subnet = network_client.subnets.begin_create_or_update(
            rg_name, vnet_name, priv_subnet_name,
            {"address_prefix": private_subnet_cidr}
        ).result()
        state["private_subnet_id"] = priv_subnet.id
        state["private_subnet_name"] = priv_subnet_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Private subnet created: {priv_subnet.id}")
    else:
        LOGGER.info(f"✅ Private subnet exists: {state['private_subnet_id']}")

    # --- Public IP for Management (eth0) ---
    pip_mgmt_name = f"{name_tag}-pip-mgmt"
    if not state.get("public_ip_mgmt_id"):
        LOGGER.info(f"Creating management Public IP '{pip_mgmt_name}'...")
        pip_mgmt = network_client.public_ip_addresses.begin_create_or_update(
            rg_name, pip_mgmt_name,
            {
                "location": region,
                "sku": {"name": "Standard"},
                "public_ip_allocation_method": "Static",
            }
        ).result()
        state["public_ip_mgmt_id"] = pip_mgmt.id
        state["public_ip_mgmt_name"] = pip_mgmt_name
        state["public_ip"] = pip_mgmt.ip_address
        save_state(prefix, state)
        LOGGER.info(f"✅ Management Public IP created: {pip_mgmt.ip_address}")
    else:
        # Refresh public IP address in case it wasn't captured
        if not state.get("public_ip"):
            pip_mgmt = network_client.public_ip_addresses.get(rg_name, pip_mgmt_name)
            state["public_ip"] = pip_mgmt.ip_address
            save_state(prefix, state)
        LOGGER.info(f"✅ Management Public IP exists: {state.get('public_ip')}")

    # --- Public IP for Untrust (eth1) ---
    pip_untrust_name = f"{name_tag}-pip-untrust"
    if not state.get("public_ip_untrust_id"):
        LOGGER.info(f"Creating untrust Public IP '{pip_untrust_name}'...")
        pip_untrust = network_client.public_ip_addresses.begin_create_or_update(
            rg_name, pip_untrust_name,
            {
                "location": region,
                "sku": {"name": "Standard"},
                "public_ip_allocation_method": "Static",
            }
        ).result()
        state["public_ip_untrust_id"] = pip_untrust.id
        state["public_ip_untrust_name"] = pip_untrust_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Untrust Public IP created: {pip_untrust.ip_address}")
    else:
        LOGGER.info(f"✅ Untrust Public IP exists: {state['public_ip_untrust_id']}")

    # --- Management NIC (eth0) ---
    nic_mgmt_name = f"{name_tag}-nic-mgmt"
    if not state.get("nic_mgmt_id"):
        LOGGER.info(f"Creating management NIC '{nic_mgmt_name}'...")
        nic_mgmt = network_client.network_interfaces.begin_create_or_update(
            rg_name, nic_mgmt_name,
            {
                "location": region,
                "network_security_group": {"id": state["nsg_id"]},
                "ip_configurations": [{
                    "name": "ipconfig-mgmt",
                    "subnet": {"id": state["public_subnet_id"]},
                    "public_ip_address": {"id": state["public_ip_mgmt_id"]},
                }],
            }
        ).result()
        state["nic_mgmt_id"] = nic_mgmt.id
        state["nic_mgmt_name"] = nic_mgmt_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Management NIC created: {nic_mgmt.id}")
    else:
        LOGGER.info(f"✅ Management NIC exists: {state['nic_mgmt_id']}")

    # --- Untrust NIC (eth1) ---
    nic_untrust_name = f"{name_tag}-nic-untrust"
    if not state.get("nic_untrust_id"):
        LOGGER.info(f"Creating untrust NIC '{nic_untrust_name}'...")
        nic_untrust = network_client.network_interfaces.begin_create_or_update(
            rg_name, nic_untrust_name,
            {
                "location": region,
                "enable_accelerated_networking": True,
                "ip_configurations": [{
                    "name": "ipconfig-untrust",
                    "subnet": {"id": state["public_subnet_id"]},
                    "public_ip_address": {"id": state["public_ip_untrust_id"]},
                }],
            }
        ).result()
        state["nic_untrust_id"] = nic_untrust.id
        state["nic_untrust_name"] = nic_untrust_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Untrust NIC created: {nic_untrust.id}")
    else:
        LOGGER.info(f"✅ Untrust NIC exists: {state['nic_untrust_id']}")

    # --- Trust NIC (eth2) ---
    nic_trust_name = f"{name_tag}-nic-trust"
    if not state.get("nic_trust_id"):
        LOGGER.info(f"Creating trust NIC '{nic_trust_name}'...")
        nic_trust = network_client.network_interfaces.begin_create_or_update(
            rg_name, nic_trust_name,
            {
                "location": region,
                "enable_ip_forwarding": True,
                "enable_accelerated_networking": True,
                "ip_configurations": [{
                    "name": "ipconfig-trust",
                    "subnet": {"id": state["private_subnet_id"]},
                }],
            }
        ).result()
        state["nic_trust_id"] = nic_trust.id
        state["nic_trust_name"] = nic_trust_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Trust NIC created: {nic_trust.id}")
    else:
        LOGGER.info(f"✅ Trust NIC exists: {state['nic_trust_id']}")

    # --- VM ---
    vm_name = f"{name_tag}-vm"
    if not state.get("vm_id"):
        LOGGER.info(f"Launching VM '{vm_name}' ({vm_size})...")

        with open(ssh_pub_key_path, "r") as f:
            ssh_pub_key_data = f.read().strip()

        # Build image reference and plan
        if custom_image_id:
            LOGGER.info(f"Using custom image: {custom_image_id}")
            image_reference = {"id": custom_image_id}
            plan = {
                "name": sku,
                "product": "vmseries-flex",
                "publisher": "paloaltonetworks",
            }
        else:
            img_version = get_marketplace_image_version(compute_client, region, sku, version)
            LOGGER.info(f"Using Marketplace image: paloaltonetworks/vmseries-flex/{sku}/{img_version}")
            image_reference = {
                "publisher": "paloaltonetworks",
                "offer": "vmseries-flex",
                "sku": sku,
                "version": img_version,
            }
            plan = {
                "name": sku,
                "product": "vmseries-flex",
                "publisher": "paloaltonetworks",
            }

        os_profile: Dict[str, Any] = {
            "computer_name": vm_name[:15],  # Azure computer name limit
            "admin_username": "admin",
            "linux_configuration": {
                "disable_password_authentication": True,
                "ssh": {
                    "public_keys": [{
                        "path": "/home/admin/.ssh/authorized_keys",
                        "key_data": ssh_pub_key_data,
                    }]
                },
            },
        }

        if custom_data:
            os_profile["custom_data"] = base64.b64encode(custom_data.encode()).decode()

        vm_params = {
            "location": region,
            "plan": plan,
            "hardware_profile": {"vm_size": vm_size},
            "storage_profile": {
                "image_reference": image_reference,
                "os_disk": {
                    "create_option": "FromImage",
                    "managed_disk": {"storage_account_type": "Premium_LRS"},
                    "delete_option": "Delete",
                },
            },
            "os_profile": os_profile,
            "network_profile": {
                "network_interfaces": [
                    {"id": state["nic_mgmt_id"], "properties": {"primary": True}},
                    {"id": state["nic_untrust_id"], "properties": {"primary": False}},
                    {"id": state["nic_trust_id"], "properties": {"primary": False}},
                ]
            },
        }

        vm = compute_client.virtual_machines.begin_create_or_update(
            rg_name, vm_name, vm_params
        ).result()
        state["vm_id"] = vm.id
        state["vm_name"] = vm_name
        save_state(prefix, state)
        LOGGER.info(f"✅ VM created: {vm.id}")

        # Refresh management public IP now that VM is running
        pip_mgmt = network_client.public_ip_addresses.get(rg_name, state["public_ip_mgmt_name"])
        state["public_ip"] = pip_mgmt.ip_address
        save_state(prefix, state)
        LOGGER.info(f"✅ Management public IP: {state['public_ip']}")
    else:
        LOGGER.info(f"✅ VM exists: {state['vm_id']}")

    return state


def monitor_chassis_ready(public_ip: str, ssh_priv_key_path: Path) -> None:
    """Connects via SSH and waits for the chassis to be ready."""
    ssh = FirewallSSHClient(public_ip, ssh_priv_key_path)
    try:
        ssh.connect()
        for attempt in range(40):
            LOGGER.info(f"Checking chassis readiness (Attempt {attempt + 1}/40)...")
            output = ssh.send_command("show chassis-ready")
            if "yes" in output.lower():
                LOGGER.info("✅ Firewall chassis is ready!")
                system_info = ssh.send_command("show system info")
                LOGGER.info("--- Palo Alto Networks VM-Series System Info ---")
                print(system_info)
                LOGGER.info("--------------------------------------------------")
                return
            LOGGER.info("Firewall not ready yet. Retrying in 30 seconds...")
            time.sleep(30)
        raise TimeoutError("Timed out waiting for firewall chassis to become ready.")
    finally:
        ssh.close()


def destroy_infrastructure(credential, subscription_id: str, state: Dict[str, Any]) -> None:
    """Deletes the Resource Group, which cascade-deletes all resources inside it."""
    resource_client = ResourceManagementClient(credential, subscription_id)
    rg_name = state.get("resource_group")
    prefix = state.get("deployment_prefix", "unknown")

    if not rg_name:
        LOGGER.error("No resource_group found in state file. Cannot destroy.")
        sys.exit(1)

    LOGGER.info(f"💥 Deleting Resource Group '{rg_name}' (cascade-deletes all resources)...")
    try:
        resource_client.resource_groups.begin_delete(rg_name).result()
        LOGGER.info(f"✅ Resource Group '{rg_name}' deleted. All resources destroyed.")
    except ResourceNotFoundError:
        LOGGER.warning(f"Resource Group '{rg_name}' not found — may have already been deleted.")
    except AzureError as e:
        LOGGER.error(f"Failed to delete Resource Group '{rg_name}': {e}")
        raise


def create_managed_image(
    credential,
    subscription_id: str,
    resource_group: str,
    vm_name: str,
    vm_id: str,
    region: str,
    image_name: str,
) -> str:
    """Deallocates, generalizes, and creates a Managed Image from a stopped VM."""
    compute_client = ComputeManagementClient(credential, subscription_id)

    LOGGER.info(f"Deallocating VM '{vm_name}'...")
    compute_client.virtual_machines.begin_deallocate(resource_group, vm_name).result()
    LOGGER.info(f"✅ VM '{vm_name}' deallocated.")

    LOGGER.info(f"Generalizing VM '{vm_name}'...")
    compute_client.virtual_machines.generalize(resource_group, vm_name)
    LOGGER.info(f"✅ VM '{vm_name}' generalized.")

    LOGGER.info(f"Creating Managed Image '{image_name}' from VM...")
    image = compute_client.images.begin_create_or_update(
        resource_group,
        image_name,
        {
            "location": region,
            "source_virtual_machine": {"id": vm_id},
        }
    ).result()
    LOGGER.info(f"✅ Managed Image created: {image.id}")
    return image.id


def print_custom_image_summary(
    image_id: str,
    image_name: str,
    region: str,
    prefix: str,
    auth_code: str,
    allowed_ips: List[str],
    ssh_key_file: str,
    license_type: str,
    auto_destroy: bool,
) -> None:
    """Prints a post-completion summary with next-step suggestions."""
    sep = "=" * 60
    sku = MARKETPLACE_SKUS.get(license_type, license_type)
    allowed_ips_str = ",".join(allowed_ips) if isinstance(allowed_ips, list) else allowed_ips

    print(f"\n{sep}")
    print(f"  Custom Image ID:   {image_id}")
    print(f"  Custom Image Name: {image_name}")
    print(f"  Region:            {region}")
    print(sep)

    if not auto_destroy:
        print("\nNext steps:\n")
        print(f"  1. Destroy temporary infrastructure when ready:")
        print(f"     python azure_create_infra.py destroy --deployment-file {prefix}-state.json\n")

    print(f"  2. Deactivate auth code '{auth_code}' in the Palo Alto Networks support portal")
    print(f"     to free the license for future use:")
    print(f"     https://support.paloaltonetworks.com  →  Products → Software NGFW Credits\n")

    print(f"  3. Test the new image with a fresh deployment:")
    print(f"     python azure_create_infra.py create \\")
    print(f"         --region {region} \\")
    print(f"         --name-tag \"test-{image_name}\" \\")
    print(f"         --custom-image-id \"{image_id}\" \\")
    print(f"         --license-type {license_type} \\")
    print(f"         --allowed-ips \"{allowed_ips_str}\" \\")
    print(f"         --ssh-key-file {ssh_key_file}")
    print(f"\n{sep}\n")


# --- CLI Handlers ---

def handle_create(args: argparse.Namespace) -> None:
    """Handler for the 'create' command."""
    if not args.license_type and not args.custom_image_id:
        LOGGER.error("You must specify either --license-type or --custom-image-id.")
        sys.exit(1)

    ssh_pub_key, ssh_priv_key = get_and_validate_ssh_keys(args.ssh_key_file)

    prefix = args.deployment_prefix or generate_prefix()
    state_file = Path(f"{prefix}-state.json")
    if state_file.exists() and not args.deployment_prefix:
        prefix = generate_prefix()

    if state_file.exists():
        LOGGER.error(
            f"State file {state_file} already exists. "
            "Use 'create-restart' to resume this deployment."
        )
        sys.exit(1)

    LOGGER.info(f"Using deployment prefix: {prefix}")
    full_name_tag = f"{prefix}-{args.name_tag}"

    credential = DefaultAzureCredential()
    subscription_id = get_subscription_id(credential, args.subscription_id)

    custom_data_content = None
    bootstrap_params = [
        getattr(args, 'auth_code', None),
        getattr(args, 'pin_id', None),
        getattr(args, 'pin_value', None),
    ]
    if any(bootstrap_params):
        if not all(bootstrap_params):
            LOGGER.error("--auth-code, --pin-id, and --pin-value must all be specified together.")
            sys.exit(1)
        LOGGER.info("Generating bootstrap custom-data from --auth-code, --pin-id, --pin-value.")
        custom_data_content = build_bootstrap_custom_data(args.auth_code, args.pin_id, args.pin_value)
    elif args.custom_data:
        custom_data_path = Path(args.custom_data).expanduser()
        if custom_data_path.is_file():
            LOGGER.info(f"Reading custom-data from file: {custom_data_path}")
            with custom_data_path.open("r") as f:
                custom_data_content = f.read()
        else:
            LOGGER.info("Using provided string as custom-data.")
            custom_data_content = args.custom_data

    args_dict = {k: v for k, v in vars(args).items() if k != 'func'}
    args_dict['ssh_key_file'] = str(ssh_pub_key)

    state = {
        "deployment_prefix": prefix,
        "subscription_id": subscription_id,
        "region": args.region,
        "invocation_string": ' '.join(sys.argv),
        "invocation_args": args_dict,
    }
    save_state(prefix, state)

    try:
        final_state = create_infrastructure(
            credential=credential,
            subscription_id=subscription_id,
            region=args.region,
            name_tag=full_name_tag,
            prefix=prefix,
            state=state,
            license_type=args.license_type or "byol",
            version=args.version,
            vm_size=args.vm_size,
            vnet_cidr=args.vnet_cidr,
            public_subnet_cidr=args.public_subnet_cidr,
            private_subnet_cidr=args.private_subnet_cidr,
            allowed_ips=args.allowed_ips,
            ssh_pub_key_path=ssh_pub_key,
            custom_data=custom_data_content,
            custom_image_id=args.custom_image_id,
        )
        monitor_chassis_ready(final_state["public_ip"], ssh_priv_key)
        LOGGER.info(f"🎉 Infrastructure '{full_name_tag}' deployed successfully!")
        LOGGER.info(f"Management IP: {final_state['public_ip']}")
        LOGGER.info(f"To destroy: python azure_create_infra.py destroy --deployment-file {prefix}-state.json")
    except (AzureError, RuntimeError, ValueError) as e:
        LOGGER.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)


def handle_destroy(args: argparse.Namespace) -> None:
    """Handler for the 'destroy' command."""
    try:
        state = load_state(args.deployment_file)
        credential = DefaultAzureCredential()
        subscription_id = state.get("subscription_id") or get_subscription_id(credential, None)
        destroy_infrastructure(credential, subscription_id, state)
        state_file = Path(args.deployment_file)
        if state_file.exists():
            state_file.unlink()
            LOGGER.info(f"✅ Deleted state file: {state_file}")
    except (AzureError, RuntimeError, ValueError, FileNotFoundError) as e:
        LOGGER.error(f"An error occurred during destroy: {e}", exc_info=True)
        sys.exit(1)


def handle_set_admin_password(args: argparse.Namespace) -> None:
    """Handler for the 'set-admin-password' command."""
    try:
        state = load_state(args.deployment_file)
        public_ip = state.get("public_ip")
        if not public_ip:
            raise RuntimeError("Public IP not found in state file.")

        ssh_key_file = args.ssh_key_file or state.get('invocation_args', {}).get('ssh_key_file')
        if not ssh_key_file:
            raise ValueError("SSH key file must be specified or be present in the state file.")

        _, ssh_priv_key = get_and_validate_ssh_keys(ssh_key_file)

        new_password = generate_password()
        LOGGER.info(f"Generated new password for admin: {new_password}")

        set_firewall_password(public_ip, ssh_priv_key, new_password)

        state["admin_password"] = new_password
        save_state(state['deployment_prefix'], state)
        LOGGER.info("Password saved to state file.")
        LOGGER.info("✅ Admin password updated successfully.")
        print("\n" + "="*50)
        print(f"  New Admin Password: {new_password}")
        print("="*50 + "\n")

    except (AzureError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred while setting the password: {e}", exc_info=True)
        sys.exit(1)


def handle_upgrade_content(args: argparse.Namespace) -> None:
    """Handler for the 'upgrade-content' command."""
    try:
        state = load_state(args.deployment_file)
        public_ip = state.get("public_ip")
        password = state.get("admin_password")

        if not public_ip:
            raise RuntimeError("Public IP not found in state file.")
        if not password:
            raise RuntimeError("Admin password not found in state file. Run 'set-admin-password' first.")

        serial_number = upgrade_content_api(public_ip, password)

        if serial_number:
            state.setdefault('actions_performed', []).append({
                'command': 'upgrade-content',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'serial_number': serial_number,
            })
            save_state(state['deployment_prefix'], state)
            LOGGER.info("Content upgrade action recorded in state file.")

        LOGGER.info("✅ Content upgrade process completed successfully.")

    except (RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during content upgrade: {e}", exc_info=True)
        sys.exit(1)


def handle_upgrade_panos(args: argparse.Namespace) -> None:
    """Handler for the 'upgrade-panos' command."""
    try:
        state = load_state(args.deployment_file)
        public_ip = state.get("public_ip")
        password = state.get("admin_password")

        if not public_ip:
            raise RuntimeError("Public IP not found in state file.")
        if not password:
            raise RuntimeError("Admin password not found in state file. Run 'set-admin-password' first.")

        target_version = resolve_panos_version(public_ip, password, args.target_version)
        serial_number = upgrade_panos_api(public_ip, password, target_version)

        if serial_number:
            state.setdefault('actions_performed', []).append({
                'command': 'upgrade-panos',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'target_version': target_version,
                'serial_number': serial_number,
            })
            save_state(state['deployment_prefix'], state)
            LOGGER.info("PAN-OS upgrade action recorded in state file.")

        LOGGER.info("✅ PAN-OS upgrade process completed successfully.")

    except (RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during PAN-OS upgrade: {e}", exc_info=True)
        sys.exit(1)


def handle_upgrade_antivirus(args: argparse.Namespace) -> None:
    """Handler for the 'upgrade-antivirus' command."""
    try:
        state = load_state(args.deployment_file)
        public_ip = state.get("public_ip")
        password = state.get("admin_password")

        if not public_ip:
            raise RuntimeError("Public IP not found in state file.")
        if not password:
            raise RuntimeError("Admin password not found in state file. Run 'set-admin-password' first.")

        serial_number = upgrade_antivirus_api(public_ip, password)

        if serial_number:
            state.setdefault('actions_performed', []).append({
                'command': 'upgrade-antivirus',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'serial_number': serial_number,
            })
            save_state(state['deployment_prefix'], state)
            LOGGER.info("Antivirus upgrade action recorded in state file.")

        LOGGER.info("✅ Antivirus upgrade process completed successfully.")

    except (RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during antivirus upgrade: {e}", exc_info=True)
        sys.exit(1)


def handle_create_image(args: argparse.Namespace) -> None:
    """Handler for the 'create-image' command."""
    try:
        state = load_state(args.deployment_file)
        vm_id = state.get("vm_id")
        vm_name = state.get("vm_name")
        resource_group = state.get("resource_group")
        region = state.get("region")
        prefix = state.get("deployment_prefix")

        if not vm_id or not vm_name or not resource_group or not region or not prefix:
            raise RuntimeError("State file is missing required fields (vm_id, vm_name, resource_group, region).")

        credential = DefaultAzureCredential()
        subscription_id = state.get("subscription_id") or get_subscription_id(credential, None)

        image_name = args.image_name
        if not image_name:
            license_type = state.get("invocation_args", {}).get("license_type", "unknown")
            image_name = f"custom-{license_type}-{time.strftime('%Y%m%d%H%M%S')}"
            LOGGER.info(f"No --image-name provided. Generated name: {image_name}")

        image_id = create_managed_image(
            credential=credential,
            subscription_id=subscription_id,
            resource_group=resource_group,
            vm_name=vm_name,
            vm_id=vm_id,
            region=region,
            image_name=image_name,
        )

        state.setdefault('created_images', []).append({
            'image_id': image_id,
            'image_name': image_name,
            'creation_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        })
        save_state(prefix, state)
        LOGGER.info(f"✅ Image information saved to state file.")

    except (AzureError, RuntimeError, ValueError, FileNotFoundError) as e:
        LOGGER.error(f"An error occurred during image creation: {e}", exc_info=True)
        sys.exit(1)


def handle_create_custom_image(args: argparse.Namespace) -> None:
    """Handler for the 'create-custom-image' compound command."""
    ssh_pub_key, ssh_priv_key = get_and_validate_ssh_keys(args.ssh_key_file)

    prefix = generate_prefix()
    full_name_tag = f"{prefix}-{args.name_tag}"

    credential = DefaultAzureCredential()
    subscription_id = get_subscription_id(credential, args.subscription_id)

    args_dict = {k: v for k, v in vars(args).items() if k != 'func'}
    args_dict['ssh_key_file'] = str(ssh_pub_key)

    state = {
        "deployment_prefix": prefix,
        "subscription_id": subscription_id,
        "region": args.region,
        "invocation_string": ' '.join(sys.argv),
        "invocation_args": args_dict,
    }
    save_state(prefix, state)

    try:
        # Step 1: Deploy infrastructure with bootstrap custom_data
        LOGGER.info("=== Step 1: Creating infrastructure ===")
        bootstrap_custom_data = build_bootstrap_custom_data(args.auth_code, args.pin_id, args.pin_value)

        base_version = getattr(args, 'version', None)
        if not base_version:
            parts = args.target_upgrade_version.split(".")
            if len(parts) == 2 or (len(parts) == 3 and parts[2].lower() == "latest"):
                base_version = f"{parts[0]}.{parts[1]}"
                LOGGER.info(f"No --version specified; deriving base image version '{base_version}' from --target-upgrade-version.")

        final_state = create_infrastructure(
            credential=credential,
            subscription_id=subscription_id,
            region=args.region,
            name_tag=full_name_tag,
            prefix=prefix,
            state=state,
            license_type=args.license_type,
            version=base_version,
            vm_size=args.vm_size,
            vnet_cidr=args.vnet_cidr,
            public_subnet_cidr=args.public_subnet_cidr,
            private_subnet_cidr=args.private_subnet_cidr,
            allowed_ips=args.allowed_ips,
            ssh_pub_key_path=ssh_pub_key,
            custom_data=bootstrap_custom_data,
            custom_image_id=None,
        )
        monitor_chassis_ready(final_state["public_ip"], ssh_priv_key)
        state = final_state
        public_ip = state["public_ip"]
        vm_name = state["vm_name"]
        resource_group = state["resource_group"]
        region = state["region"]
        LOGGER.info("✅ Infrastructure created and chassis is ready.")

        # Step 2: Wait for auto-registration (serial assigned)
        LOGGER.info("=== Step 2: Waiting for auto-registration and device certificate ===")
        serial_number = wait_for_serial_ssh(public_ip, ssh_priv_key)
        state.setdefault('actions_performed', []).append({
            'command': 'auto-registration',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'serial_number': serial_number,
        })
        save_state(prefix, state)
        LOGGER.info("✅ Auto-registration complete. Firewall is licensed.")

        # Step 3: Set admin password
        LOGGER.info("=== Step 3: Setting admin password ===")
        new_password = generate_password()
        LOGGER.info(f"Generated new password for admin: {new_password}")
        set_firewall_password(public_ip, ssh_priv_key, new_password)
        state["admin_password"] = new_password
        save_state(prefix, state)
        LOGGER.info("✅ Admin password set and saved.")

        # Resolve target version
        target_upgrade_version = resolve_panos_version(public_ip, new_password, args.target_upgrade_version)

        # Step 4: Upgrade content
        LOGGER.info("=== Step 4: Upgrading content ===")
        serial_number = upgrade_content_api(public_ip, new_password)
        if serial_number:
            state.setdefault('actions_performed', []).append({
                'command': 'upgrade-content',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'serial_number': serial_number,
            })
            save_state(prefix, state)
        LOGGER.info("✅ Content upgrade completed.")

        # Step 5: Upgrade antivirus (optional)
        if args.upgrade_antivirus:
            LOGGER.info("=== Step 5: Upgrading antivirus ===")
            serial_number = upgrade_antivirus_api(public_ip, new_password)
            if serial_number:
                state.setdefault('actions_performed', []).append({
                    'command': 'upgrade-antivirus',
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'serial_number': serial_number,
                })
                save_state(prefix, state)
            LOGGER.info("✅ Antivirus upgrade completed.")
        else:
            LOGGER.info("=== Step 5: Skipping antivirus upgrade (no --upgrade-antivirus flag) ===")

        # Step 6: Upgrade PAN-OS
        LOGGER.info(f"=== Step 6: Upgrading PAN-OS to {target_upgrade_version} ===")
        serial_number = upgrade_panos_api(public_ip, new_password, target_upgrade_version)
        if serial_number:
            state.setdefault('actions_performed', []).append({
                'command': 'upgrade-panos',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'target_version': target_upgrade_version,
                'serial_number': serial_number,
            })
            save_state(prefix, state)
        LOGGER.info("✅ PAN-OS upgrade completed.")

        # Step 7: Wait for SSH post-reboot
        LOGGER.info("=== Step 7: Waiting for SSH connectivity post-reboot ===")
        wait_for_ssh_connectivity(public_ip, ssh_priv_key)
        LOGGER.info("✅ Firewall is reachable via SSH.")

        # Step 8: Private data reset + wait for stopped
        LOGGER.info("=== Step 8: Performing private-data-reset ===")
        compute_client = ComputeManagementClient(credential, subscription_id)
        private_data_reset_and_wait_stopped(
            public_ip, ssh_priv_key, compute_client, resource_group, vm_name
        )
        state.setdefault('actions_performed', []).append({
            'command': 'private-data-reset',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        })
        save_state(prefix, state)
        LOGGER.info("✅ Private data reset complete. VM is stopped.")

        # Step 9: Deallocate, generalize, create Managed Image
        LOGGER.info("=== Step 9: Creating Managed Image ===")
        image_name = f"custom-{args.license_type}-{target_upgrade_version}-{time.strftime('%Y%m%d%H%M%S')}"
        image_id = create_managed_image(
            credential=credential,
            subscription_id=subscription_id,
            resource_group=resource_group,
            vm_name=vm_name,
            vm_id=state["vm_id"],
            region=region,
            image_name=image_name,
        )
        state.setdefault('created_images', []).append({
            'image_id': image_id,
            'image_name': image_name,
            'creation_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        })
        save_state(prefix, state)
        LOGGER.info(f"✅ Managed Image created: {image_id} ({image_name})")

        # Step 10: Destroy infrastructure (optional)
        if args.auto_destroy:
            LOGGER.info("=== Step 10: Destroying temporary infrastructure (--auto-destroy) ===")
            destroy_infrastructure(credential, subscription_id, state)
            state_file = Path(f"{prefix}-state.json")
            if state_file.exists():
                state_file.unlink()
                LOGGER.info(f"✅ Deleted state file: {state_file}")
        else:
            LOGGER.info("=== Step 10: Skipping infrastructure teardown (no --auto-destroy flag) ===")

        LOGGER.info(f"🎉 create-custom-image completed successfully! Image: {image_id}")
        print_custom_image_summary(
            image_id=image_id,
            image_name=image_name,
            region=region,
            prefix=prefix,
            auth_code=args.auth_code,
            allowed_ips=args.allowed_ips,
            ssh_key_file=str(ssh_pub_key),
            license_type=args.license_type,
            auto_destroy=args.auto_destroy,
        )

    except (AzureError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during create-custom-image: {e}", exc_info=True)
        sys.exit(1)


def handle_create_custom_image_restart(args: argparse.Namespace) -> None:
    """Handler for 'create-custom-image-restart'. Resumes an interrupted create-custom-image."""
    try:
        state = load_state(args.deployment_file)
        prefix = state.get("deployment_prefix")
        region = state.get("region")
        vm_name = state.get("vm_name")
        vm_id = state.get("vm_id")
        resource_group = state.get("resource_group")
        public_ip = state.get("public_ip")
        original_args = state.get("invocation_args", {})

        if not vm_id or not region or not prefix or not resource_group:
            raise RuntimeError("State file is missing vm_id, region, resource_group, or deployment_prefix. Cannot restart.")

        credential = DefaultAzureCredential()
        subscription_id = state.get("subscription_id") or get_subscription_id(credential, None)

        ssh_key_file = args.ssh_key_file or original_args.get("ssh_key_file")
        if not ssh_key_file:
            raise ValueError("SSH key file not found in state or CLI args. Use --ssh-key-file.")
        _, ssh_priv_key = get_and_validate_ssh_keys(ssh_key_file)

        target_upgrade_version = original_args.get("target_upgrade_version")
        upgrade_antivirus = original_args.get("upgrade_antivirus", False)
        license_type = original_args.get("license_type", "byol")
        auto_destroy = original_args.get("auto_destroy", False)
        new_password = state.get("admin_password")

        actions_done = {a["command"] for a in state.get("actions_performed", [])}
        image_id = None
        image_name = None
        if state.get("created_images"):
            last = state["created_images"][-1]
            image_id = last.get("image_id")
            image_name = last.get("image_name")

        LOGGER.info(f"Resuming create-custom-image for prefix '{prefix}'. Completed steps: {actions_done or 'none'}")

        # Wait for SSH if private-data-reset not yet done
        if "private-data-reset" not in actions_done and public_ip:
            LOGGER.info("Waiting for firewall to be reachable via SSH before resuming...")
            wait_for_ssh_connectivity(public_ip, ssh_priv_key)
            LOGGER.info("✅ Firewall is reachable.")

        # Step 2: Wait for auto-registration
        if "auto-registration" not in actions_done:
            LOGGER.info("=== Resuming Step 2: Waiting for auto-registration ===")
            serial_number = wait_for_serial_ssh(public_ip, ssh_priv_key)
            state.setdefault("actions_performed", []).append({
                "command": "auto-registration",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "serial_number": serial_number,
            })
            save_state(prefix, state)
            actions_done.add("auto-registration")
            LOGGER.info("✅ Auto-registration complete.")

        # Step 3: Set admin password
        if not new_password:
            LOGGER.info("=== Resuming Step 3: Setting admin password ===")
            new_password = generate_password()
            set_firewall_password(public_ip, ssh_priv_key, new_password)
            state["admin_password"] = new_password
            save_state(prefix, state)
            LOGGER.info("✅ Admin password set and saved.")

        # Step 4: Upgrade content
        if "upgrade-content" not in actions_done:
            LOGGER.info("=== Resuming Step 4: Upgrading content ===")
            serial_number = upgrade_content_api(public_ip, new_password)
            if serial_number:
                state.setdefault("actions_performed", []).append({
                    "command": "upgrade-content",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "serial_number": serial_number,
                })
                save_state(prefix, state)
                actions_done.add("upgrade-content")
            LOGGER.info("✅ Content upgrade completed.")

        # Step 5: Antivirus (optional)
        if upgrade_antivirus and "upgrade-antivirus" not in actions_done:
            LOGGER.info("=== Resuming Step 5: Upgrading antivirus ===")
            serial_number = upgrade_antivirus_api(public_ip, new_password)
            if serial_number:
                state.setdefault("actions_performed", []).append({
                    "command": "upgrade-antivirus",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "serial_number": serial_number,
                })
                save_state(prefix, state)
                actions_done.add("upgrade-antivirus")
            LOGGER.info("✅ Antivirus upgrade completed.")

        # Step 6: Upgrade PAN-OS
        if "upgrade-panos" not in actions_done:
            target_upgrade_version = resolve_panos_version(public_ip, new_password, target_upgrade_version)
            LOGGER.info(f"=== Resuming Step 6: Upgrading PAN-OS to {target_upgrade_version} ===")
            serial_number = upgrade_panos_api(public_ip, new_password, target_upgrade_version)
            if serial_number:
                state.setdefault("actions_performed", []).append({
                    "command": "upgrade-panos",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "target_version": target_upgrade_version,
                    "serial_number": serial_number,
                })
                save_state(prefix, state)
                actions_done.add("upgrade-panos")
            LOGGER.info("✅ PAN-OS upgrade completed.")

        # Step 7 + 8: SSH connectivity + private-data-reset
        if "private-data-reset" not in actions_done:
            LOGGER.info("=== Resuming Step 7: Waiting for SSH connectivity post-reboot ===")
            wait_for_ssh_connectivity(public_ip, ssh_priv_key)
            LOGGER.info("✅ Firewall is reachable via SSH.")

            LOGGER.info("=== Resuming Step 8: Performing private-data-reset ===")
            compute_client = ComputeManagementClient(credential, subscription_id)
            private_data_reset_and_wait_stopped(
                public_ip, ssh_priv_key, compute_client, resource_group, vm_name
            )
            state.setdefault("actions_performed", []).append({
                "command": "private-data-reset",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            save_state(prefix, state)
            actions_done.add("private-data-reset")
            LOGGER.info("✅ Private data reset complete. VM is stopped.")

        # Step 9: Create Managed Image
        if not state.get("created_images"):
            LOGGER.info("=== Resuming Step 9: Creating Managed Image ===")
            image_name = f"custom-{license_type}-{target_upgrade_version}-{time.strftime('%Y%m%d%H%M%S')}"
            image_id = create_managed_image(
                credential=credential,
                subscription_id=subscription_id,
                resource_group=resource_group,
                vm_name=vm_name,
                vm_id=vm_id,
                region=region,
                image_name=image_name,
            )
            state.setdefault("created_images", []).append({
                "image_id": image_id,
                "image_name": image_name,
                "creation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            save_state(prefix, state)
            LOGGER.info(f"✅ Managed Image created: {image_id} ({image_name})")
        else:
            LOGGER.info(f"=== Step 9: Image already created ({image_id}), skipping. ===")

        # Step 10: Destroy (optional)
        if auto_destroy:
            LOGGER.info("=== Resuming Step 10: Destroying temporary infrastructure ===")
            destroy_infrastructure(credential, subscription_id, state)
            state_file = Path(f"{prefix}-state.json")
            if state_file.exists():
                state_file.unlink()
                LOGGER.info(f"✅ Deleted state file: {state_file}")
        else:
            LOGGER.info("=== Step 10: Skipping infrastructure teardown (no --auto-destroy flag) ===")

        LOGGER.info(f"🎉 create-custom-image-restart completed successfully! Image: {image_id}")
        print_custom_image_summary(
            image_id=image_id,
            image_name=image_name,
            region=region,
            prefix=prefix,
            auth_code=original_args.get("auth_code", ""),
            allowed_ips=original_args.get("allowed_ips", []),
            ssh_key_file=original_args.get("ssh_key_file", ""),
            license_type=license_type,
            auto_destroy=auto_destroy,
        )

    except (AzureError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during create-custom-image-restart: {e}", exc_info=True)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Azure Infrastructure CLI for Palo Alto Networks VM-Series",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- Create Command ---
    parser_create = subparsers.add_parser("create", help="Create a new Resource Group and VM-Series VM.")
    parser_create.add_argument("--region", required=True, help="Azure region (e.g., eastus).")
    parser_create.add_argument("--name-tag", required=True, help="Base name for all created resources.")
    parser_create.add_argument("--deployment-prefix", required=False, help="Optional prefix. A 6-char random one is generated if omitted.")
    parser_create.add_argument("--subscription-id", required=False, help="Azure subscription ID. Defaults to current az login subscription.")
    parser_create.add_argument("--license-type", required=False, default="byol",
                               choices=list(MARKETPLACE_SKUS.keys()),
                               help="VM-Series license type (default: byol). Required if --custom-image-id is not provided.")
    parser_create.add_argument("--custom-image-id", required=False, help="ARM resource ID of a custom Managed Image to use instead of Marketplace.")
    parser_create.add_argument("--version", required=False, help="Optional: Marketplace image version (e.g., '11.0.3'). Partial X.Y selects latest patch.")
    parser_create.add_argument("--ssh-key-file", required=False, default="~/.ssh/id_rsa.pub", metavar="PATH", help="Path to SSH public or private key file (default: ~/.ssh/id_rsa.pub).")
    parser_create.add_argument("--allowed-ips", required=True, type=lambda s: [item.strip() for item in s.split(',')], help="Comma-separated IPv4 CIDR blocks for SSH/HTTPS access.")
    parser_create.add_argument("--custom-data", required=False, help="Path to a custom-data file or raw string passed to the VM.")
    parser_create.add_argument("--auth-code", required=False, help="BYOL auth code for basic bootstrapping (requires --pin-id and --pin-value).")
    parser_create.add_argument("--pin-id", required=False, help="VM-Series auto-registration PIN ID for basic bootstrapping.")
    parser_create.add_argument("--pin-value", required=False, help="VM-Series auto-registration PIN value for basic bootstrapping.")
    parser_create.add_argument("--vm-size", default="Standard_D8_v5", help="Azure VM size (default: Standard_D8_v5).")
    parser_create.add_argument("--vnet-cidr", default="10.0.0.0/16", help="CIDR block for the VNet (default: 10.0.0.0/16).")
    parser_create.add_argument("--public-subnet-cidr", default="10.0.1.0/24", help="CIDR for the public subnet (default: 10.0.1.0/24).")
    parser_create.add_argument("--private-subnet-cidr", default="10.0.2.0/24", help="CIDR for the private subnet (default: 10.0.2.0/24).")
    parser_create.set_defaults(func=handle_create)

    # --- Destroy Command ---
    parser_destroy = subparsers.add_parser("destroy", help="Delete the Resource Group and all resources inside it.")
    parser_destroy.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_destroy.set_defaults(func=handle_destroy)

    # --- Set Admin Password Command ---
    parser_set_password = subparsers.add_parser("set-admin-password", help="Set a new random password for the admin user.")
    parser_set_password.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_set_password.add_argument("--ssh-key-file", required=False, metavar="PATH", help="Path to SSH key file. Falls back to state file path if omitted.")
    parser_set_password.set_defaults(func=handle_set_admin_password)

    # --- Upgrade Content Command ---
    parser_upgrade_content = subparsers.add_parser("upgrade-content", help="Download and install the latest content update.")
    parser_upgrade_content.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_upgrade_content.set_defaults(func=handle_upgrade_content)

    # --- Upgrade PAN-OS Command ---
    parser_upgrade_panos = subparsers.add_parser("upgrade-panos", help="Upgrade the PAN-OS software on a firewall.")
    parser_upgrade_panos.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_upgrade_panos.add_argument("--target-version", required=True, help="Target PAN-OS version (e.g., '11.1.2', '11.1', '11.1.latest').")
    parser_upgrade_panos.set_defaults(func=handle_upgrade_panos)

    # --- Upgrade Antivirus Command ---
    parser_upgrade_antivirus = subparsers.add_parser("upgrade-antivirus", help="Download and install the latest antivirus update.")
    parser_upgrade_antivirus.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_upgrade_antivirus.set_defaults(func=handle_upgrade_antivirus)

    # --- Create Image Command ---
    parser_create_image = subparsers.add_parser("create-image", help="Deallocate, generalize, and create a Managed Image from a deployment VM.")
    parser_create_image.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_create_image.add_argument("--image-name", required=False, help="Name for the new Managed Image. Generated if omitted.")
    parser_create_image.set_defaults(func=handle_create_image)

    # --- Create Custom Image Command ---
    parser_cci = subparsers.add_parser("create-custom-image", help="Compound: deploy, upgrade, reset, and snapshot into a custom Managed Image.")
    parser_cci.add_argument("--region", required=True, help="Azure region (e.g., eastus).")
    parser_cci.add_argument("--name-tag", required=True, help="Base name for all created resources.")
    parser_cci.add_argument("--subscription-id", required=False, help="Azure subscription ID. Defaults to current az login subscription.")
    parser_cci.add_argument("--license-type", required=False, default="byol",
                            choices=list(MARKETPLACE_SKUS.keys()),
                            help="VM-Series license type (default: byol).")
    parser_cci.add_argument("--version", required=False, help="Optional: Base Marketplace image version. Partial X.Y auto-derived from --target-upgrade-version if omitted.")
    parser_cci.add_argument("--ssh-key-file", required=False, default="~/.ssh/id_rsa.pub", metavar="PATH", help="Path to SSH public or private key file (default: ~/.ssh/id_rsa.pub).")
    parser_cci.add_argument("--allowed-ips", required=True, type=lambda s: [item.strip() for item in s.split(',')], help="Comma-separated IPv4 CIDR blocks for SSH/HTTPS access.")
    parser_cci.add_argument("--vm-size", default="Standard_D8_v5", help="Azure VM size (default: Standard_D8_v5).")
    parser_cci.add_argument("--vnet-cidr", default="10.0.0.0/16", help="CIDR block for the VNet (default: 10.0.0.0/16).")
    parser_cci.add_argument("--public-subnet-cidr", default="10.0.1.0/24", help="CIDR for the public subnet (default: 10.0.1.0/24).")
    parser_cci.add_argument("--private-subnet-cidr", default="10.0.2.0/24", help="CIDR for the private subnet (default: 10.0.2.0/24).")
    parser_cci.add_argument("--auth-code", required=True, help="BYOL auth code for bootstrap auto-registration.")
    parser_cci.add_argument("--pin-id", required=True, help="VM-Series auto-registration PIN ID.")
    parser_cci.add_argument("--pin-value", required=True, help="VM-Series auto-registration PIN value.")
    parser_cci.add_argument("--target-upgrade-version", required=True, help="Target PAN-OS version (e.g., '11.1.2', '11.1', '11.1.latest').")
    parser_cci.add_argument("--upgrade-antivirus", action="store_true", default=False, help="Also upgrade antivirus after content upgrade.")
    parser_cci.add_argument("--auto-destroy", action="store_true", default=False, help="Destroy temporary infrastructure after image creation.")
    parser_cci.set_defaults(func=handle_create_custom_image)

    # --- Create Custom Image Restart Command ---
    parser_cci_restart = subparsers.add_parser("create-custom-image-restart", help="Resume an interrupted create-custom-image from its state file.")
    parser_cci_restart.add_argument("--deployment-file", required=True, help="Path to the state file from the interrupted run.")
    parser_cci_restart.add_argument("--ssh-key-file", required=False, metavar="PATH", help="Path to SSH key file. Falls back to state file path if omitted.")
    parser_cci_restart.set_defaults(func=handle_create_custom_image_restart)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
