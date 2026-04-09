#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OCI Infrastructure CLI for Palo Alto Networks VM-Series

A Python CLI tool to create, destroy, monitor, or build custom images from a
Palo Alto Networks VM-Series firewall on Oracle Cloud Infrastructure (OCI).

This script provides the following commands:
  1. `create`: Deploys a VCN with 3 subnets, security lists, route tables, and a
     3-NIC VM-Series firewall instance. Creates a state file to track resources.
  2. `destroy`: Ordered teardown of all created resources (instance → subnets →
     route tables → internet gateway → security lists → VCN).
  3. `set-admin-password`: Connects to an existing deployment and sets a new
     random password for the 'admin' user.
  4. `upgrade-content`: Downloads and installs the latest content update via API.
  5. `upgrade-panos`: Upgrades the PAN-OS software via API to a specific version.
  6. `upgrade-antivirus`: Downloads and installs the latest antivirus update via API.
  7. `create-image`: Stops the instance and creates an OCI custom image from it.
  8. `create-custom-image`: Compound command — deploy, license, upgrade, reset, snapshot.
  9. `create-custom-image-restart`: Resume an interrupted create-custom-image workflow.

OCI Networking Model (1 VCN, 3 regional subnets):
--------------------------------------------------
OCI uses a single VCN with three regional subnets for the VM-Series topology:
  - mgmt subnet    (10.0.1.0/24) — NIC0: SSH+HTTPS access, ephemeral public IP
  - untrust subnet (10.0.2.0/24) — NIC1: skip_src_dst=True, ephemeral public IP
  - trust subnet   (10.0.3.0/24) — NIC2: skip_src_dst=True, private only

The primary VNIC (mgmt) is attached at launch. Secondary VNICs (untrust and trust)
are hot-attached after the instance reaches RUNNING state.

Background — Why create-custom-image?
--------------------------------------
PAN does not publish every PAN-OS version to the OCI Marketplace. The solution:
  1. Deploy the latest available Marketplace image version.
  2. Bootstrap with auth code + auto-registration PIN (via base64 user_data).
  3. Upgrade via PAN-OS API to the desired target version.
  4. Perform private-data-reset + shutdown.
  5. Create an OCI custom image from the stopped instance.

Prerequisites:
  - Python 3.12+
  - OCI credentials configured:
      api_key:            ~/.oci/config  (run 'oci setup config')
      instance_principal: no config needed (runs on OCI compute)
      security_token:     ~/.oci/config with security_token_file entry
  - Required Python packages (see requirements.txt)

Example Usage:

# Create a firewall stack using a known image OCID (recommended)
python oci_create_infra.py create \\
    --compartment-id ocid1.compartment.oc1..xxx \\
    --region us-ashburn-1 \\
    --name-tag "pa-fw-test" \\
    --allowed-ips "YOUR_IP/32" \\
    --image-ocid ocid1.image.oc1.iad.xxx \\
    --ssh-key-file ~/.ssh/id_rsa.pub

# Create using Marketplace (accepts terms automatically)
python oci_create_infra.py create \\
    --compartment-id ocid1.compartment.oc1..xxx \\
    --region us-ashburn-1 \\
    --name-tag "pa-fw-test" \\
    --allowed-ips "YOUR_IP/32" \\
    --license-type byol \\
    --ssh-key-file ~/.ssh/id_rsa.pub

# Create a custom OCI image (full lifecycle)
python oci_create_infra.py create-custom-image \\
    --compartment-id ocid1.compartment.oc1..xxx \\
    --region us-ashburn-1 \\
    --name-tag "my-golden-image" \\
    --allowed-ips "YOUR_IP/32" \\
    --license-type byol \\
    --auth-code "YOUR-AUTH-CODE" \\
    --pin-id "YOUR-PIN-ID" \\
    --pin-value "YOUR-PIN-VALUE" \\
    --target-upgrade-version "11.1"

# Destroy all resources
python oci_create_infra.py destroy --deployment-file abc123-state.json
"""

import argparse
import base64
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
    import oci
except ImportError as e:
    LOGGER = logging.getLogger(__name__)
    LOGGER.error("OCI SDK not found.")
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

def load_marketplace_listings() -> Dict[str, Any]:
    """Loads marketplace listing mappings from the external YAML file."""
    config_file = Path(__file__).parent / "marketplace_listings.yaml"
    if not config_file.is_file():
        config_file = Path("marketplace_listings.yaml")
    if not config_file.is_file():
        LOGGER.error("Configuration file 'marketplace_listings.yaml' not found.")
        sys.exit(1)
    with config_file.open("r") as f:
        return yaml.safe_load(f)

MARKETPLACE_LISTINGS = load_marketplace_listings()


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


# --- OCI Auth ---

def get_oci_config(auth_method: str, config_file: str, profile: str) -> Tuple[Dict, Any]:
    """Returns (config_dict, signer) for the specified auth method.

    - api_key:            config dict + no signer (SDK uses config dict directly)
    - instance_principal: empty config + InstancePrincipalsSecurityTokenSigner
    - security_token:     config dict + SecurityTokenSigner (token from config)
    """
    if auth_method == "api_key":
        try:
            config = oci.config.from_file(file_location=config_file, profile_name=profile)
            oci.config.validate_config(config)
            return config, None
        except Exception as e:
            LOGGER.error(f"Failed to load OCI api_key config from '{config_file}' (profile: {profile}): {e}")
            LOGGER.error("Run 'oci setup config' to create ~/.oci/config.")
            sys.exit(1)

    elif auth_method == "instance_principal":
        try:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            return {}, signer
        except Exception as e:
            LOGGER.error(f"Failed to initialize Instance Principal auth: {e}")
            LOGGER.error("Ensure the instance has a dynamic group policy granting OCI access.")
            sys.exit(1)

    elif auth_method == "security_token":
        try:
            config = oci.config.from_file(file_location=config_file, profile_name=profile)
            token_file_path = config.get("security_token_file")
            if not token_file_path:
                LOGGER.error("Config profile does not have a 'security_token_file' field.")
                sys.exit(1)
            token_path = Path(token_file_path).expanduser()
            if not token_path.is_file():
                LOGGER.error(f"Security token file not found: {token_path}")
                sys.exit(1)
            with token_path.open("r") as f:
                token = f.read().strip()
            private_key = oci.signer.load_private_key_from_file(
                config.get("key_file"),
                config.get("pass_phrase"),
            )
            signer = oci.auth.signers.SecurityTokenSigner(token=token, private_key=private_key)
            return config, signer
        except Exception as e:
            LOGGER.error(f"Failed to initialize security_token auth: {e}")
            sys.exit(1)

    else:
        LOGGER.error(f"Unknown auth method '{auth_method}'. Use api_key, instance_principal, or security_token.")
        sys.exit(1)


def make_oci_clients(config: Dict, signer: Any, region: str) -> Dict[str, Any]:
    """Creates and returns all required OCI service clients."""
    if signer:
        base_config = {"region": region}
        def _client(cls):
            return cls(base_config, signer=signer)
    else:
        base_config = dict(config)
        base_config["region"] = region
        def _client(cls):
            return cls(base_config)

    clients = {
        "compute": _client(oci.core.ComputeClient),
        "network": _client(oci.core.VirtualNetworkClient),
        "identity": _client(oci.identity.IdentityClient),
    }

    # Marketplace client is optional (may not be needed if --image-ocid is provided)
    try:
        clients["marketplace"] = _client(oci.marketplace.MarketplaceClient)
    except Exception:
        clients["marketplace"] = None

    return clients


def get_availability_domain(identity_client: Any, compartment_id: str, requested_ad: Optional[str] = None) -> str:
    """Returns an availability domain name for the given compartment.

    If requested_ad is provided, validates it exists. Otherwise returns the first AD.
    """
    try:
        ads = identity_client.list_availability_domains(compartment_id=compartment_id).data
    except Exception as e:
        raise RuntimeError(f"Failed to list availability domains: {e}")

    if not ads:
        raise RuntimeError("No availability domains found in compartment.")

    if requested_ad:
        ad_names = [ad.name for ad in ads]
        if requested_ad not in ad_names:
            raise ValueError(
                f"Availability domain '{requested_ad}' not found. "
                f"Available: {', '.join(ad_names)}"
            )
        return requested_ad

    ad_name = ads[0].name
    LOGGER.info(f"Using availability domain: {ad_name}")
    return ad_name


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


# --- OCI Polling Helpers ---

def wait_for_instance_state(
    compute_client: Any,
    instance_id: str,
    target_state: str,
    max_wait: int = 600,
) -> None:
    """Polls an OCI instance until it reaches the target lifecycle_state."""
    LOGGER.info(f"Waiting for instance {instance_id} to reach '{target_state}'...")
    start = time.time()
    while time.time() - start < max_wait:
        instance = compute_client.get_instance(instance_id).data
        state = instance.lifecycle_state
        LOGGER.info(f"  Instance state: {state}")
        if state == target_state:
            LOGGER.info(f"✅ Instance reached '{target_state}'.")
            return
        if state == "TERMINATED" and target_state != "TERMINATED":
            raise RuntimeError(f"Instance unexpectedly reached TERMINATED state.")
        time.sleep(15)
    raise TimeoutError(f"Instance did not reach '{target_state}' within {max_wait}s.")


def wait_for_vnic_attachment_state(
    compute_client: Any,
    attachment_id: str,
    target_state: str,
    max_wait: int = 180,
) -> None:
    """Polls a VNIC attachment until it reaches the target lifecycle_state."""
    LOGGER.info(f"Waiting for VNIC attachment {attachment_id} to reach '{target_state}'...")
    start = time.time()
    while time.time() - start < max_wait:
        try:
            attachment = compute_client.get_vnic_attachment(attachment_id).data
            state = attachment.lifecycle_state
            if state == target_state:
                LOGGER.info(f"✅ VNIC attachment reached '{target_state}'.")
                return
            if state == "DETACHED" and target_state != "DETACHED":
                raise RuntimeError("VNIC attachment unexpectedly detached.")
            time.sleep(10)
        except oci.exceptions.ServiceError as e:
            if e.status == 404 and target_state == "DETACHED":
                LOGGER.info("✅ VNIC attachment no longer exists (already detached).")
                return
            raise
    raise TimeoutError(f"VNIC attachment did not reach '{target_state}' within {max_wait}s.")


def wait_for_image_state(
    compute_client: Any,
    image_id: str,
    target_state: str,
    max_wait: int = 1800,
) -> None:
    """Polls an OCI image until it reaches the target lifecycle_state."""
    LOGGER.info(f"Waiting for image {image_id} to reach '{target_state}'...")
    start = time.time()
    while time.time() - start < max_wait:
        image = compute_client.get_image(image_id).data
        state = image.lifecycle_state
        LOGGER.info(f"  Image state: {state}")
        if state == target_state:
            LOGGER.info(f"✅ Image reached '{target_state}'.")
            return
        if state == "DELETED":
            raise RuntimeError("Image unexpectedly deleted.")
        time.sleep(30)
    raise TimeoutError(f"Image did not reach '{target_state}' within {max_wait}s.")


def _wait_for_network_resource(get_fn, resource_name: str, target_state: str = "AVAILABLE", max_wait: int = 120) -> Any:
    """Polls a networking resource (VCN, subnet, etc.) until it reaches the target state."""
    start = time.time()
    while time.time() - start < max_wait:
        resource = get_fn()
        if resource.lifecycle_state == target_state:
            return resource
        time.sleep(5)
    raise TimeoutError(f"{resource_name} did not reach '{target_state}' within {max_wait}s.")


# --- OCI Marketplace / App Catalog ---

def accept_marketplace_subscription(
    marketplace_client: Any,
    compute_client: Any,
    compartment_id: str,
    license_type: str,
) -> str:
    """Finds the VM-Series Marketplace listing, accepts terms, and returns the image OCID."""
    listing_config = MARKETPLACE_LISTINGS.get(license_type)
    if not listing_config:
        raise ValueError(f"Unknown license type '{license_type}'. Check marketplace_listings.yaml.")

    listing_name = listing_config["name"]
    pricing_type = listing_config["pricing_type"]

    LOGGER.info(f"Searching OCI Marketplace for '{listing_name}' (pricing: {pricing_type})...")

    # Step 1: Find the listing
    try:
        response = marketplace_client.list_listings(
            compartment_id=compartment_id,
            name=listing_name,
        )
        listings = response.data
    except Exception as e:
        raise RuntimeError(
            f"Failed to query OCI Marketplace: {e}\n"
            "If using instance_principal or security_token auth, ensure the "
            "policy allows 'marketplace-catalog' access. Alternatively, use "
            "--image-ocid to bypass Marketplace lookup."
        )

    if not listings:
        raise RuntimeError(
            f"No Marketplace listing found matching '{listing_name}'.\n"
            "Run 'python oci_marketplace_explorer.py list-listings' to discover available listings.\n"
            "Or use --image-ocid to bypass Marketplace lookup."
        )

    # Find matching listing by pricing type
    matching = [l for l in listings if getattr(l, 'pricing_type', None) == pricing_type or pricing_type in str(getattr(l, 'pricing_types', ''))]
    if not matching:
        LOGGER.warning(f"Could not filter by pricing_type='{pricing_type}', using first result.")
        matching = listings

    listing = matching[0]
    listing_id = listing.id
    LOGGER.info(f"Found listing: {listing.name} (id: {listing_id})")

    # Step 2: Get the latest package
    try:
        packages_response = marketplace_client.list_packages(
            listing_id=listing_id,
            compartment_id=compartment_id,
        )
        packages = packages_response.data
    except Exception as e:
        raise RuntimeError(f"Failed to list packages for listing '{listing_id}': {e}")

    if not packages:
        raise RuntimeError(f"No packages found for listing '{listing_id}'.")

    package = packages[0]
    LOGGER.info(f"Using package version: {package.version}")

    app_catalog_listing_id = package.app_catalog_listing_id
    app_catalog_resource_version = package.app_catalog_listing_resource_version
    image_ocid = package.app_catalog_listing_resource_id

    if not app_catalog_listing_id:
        raise RuntimeError(
            "Package does not have app_catalog_listing_id. "
            "Use --image-ocid to specify the image OCID directly."
        )

    # Step 3: Get the agreement
    LOGGER.info(f"Getting App Catalog agreement for listing '{app_catalog_listing_id}'...")
    try:
        agreement_response = compute_client.get_app_catalog_listing_agreements(
            listing_id=app_catalog_listing_id,
            resource_version=app_catalog_resource_version,
        )
        agreement = agreement_response.data
    except Exception as e:
        raise RuntimeError(f"Failed to get App Catalog agreement: {e}")

    # Step 4: Create subscription (accept terms)
    LOGGER.info("Accepting Marketplace terms and creating App Catalog subscription...")
    try:
        compute_client.create_app_catalog_subscription(
            create_app_catalog_subscription_details=oci.core.models.CreateAppCatalogSubscriptionDetails(
                compartment_id=compartment_id,
                listing_id=app_catalog_listing_id,
                listing_resource_version=app_catalog_resource_version,
                oracle_terms_of_use_link=agreement.oracle_terms_of_use_link,
                eula_link=agreement.eula_link,
                time_retrieved=agreement.time_retrieved,
                signature=agreement.signature,
            )
        )
        LOGGER.info("✅ App Catalog subscription created (terms accepted).")
    except oci.exceptions.ServiceError as e:
        if e.status == 409:
            LOGGER.info("App Catalog subscription already exists (terms already accepted).")
        else:
            raise RuntimeError(f"Failed to create App Catalog subscription: {e}")

    LOGGER.info(f"✅ Image OCID from Marketplace: {image_ocid}")
    return image_ocid


# --- OCI Infrastructure Management ---

def _make_egress_all() -> Any:
    """Returns an OCI EgressSecurityRule allowing all outbound traffic."""
    return oci.core.models.EgressSecurityRule(
        protocol="all",
        destination="0.0.0.0/0",
        destination_type="CIDR_BLOCK",
        is_stateless=False,
    )


def create_infrastructure(
    compartment_id: str,
    region: str,
    availability_domain: str,
    name_tag: str,
    prefix: str,
    state: Dict[str, Any],
    clients: Dict[str, Any],
    license_type: str,
    shape: str,
    ocpu_count: float,
    memory_gb: float,
    vcn_cidr: str,
    mgmt_cidr: str,
    untrust_cidr: str,
    trust_cidr: str,
    allowed_ips: List[str],
    ssh_pub_key_path: Path,
    bootstrap_user_data: Optional[str] = None,
    image_ocid: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates or resumes the full OCI stack for the VM-Series firewall."""
    compute_client = clients["compute"]
    network_client = clients["network"]
    marketplace_client = clients.get("marketplace")

    LOGGER.info(f"🚀 Starting/resuming infrastructure creation for '{name_tag}'...")

    # --- VCN ---
    if not state.get("vcn_id"):
        vcn_name = f"{name_tag}-vcn"
        vcn_dns_label = f"pavcn{prefix}"  # unique per deployment
        LOGGER.info(f"Creating VCN '{vcn_name}' ({vcn_cidr})...")
        vcn = network_client.create_vcn(
            oci.core.models.CreateVcnDetails(
                compartment_id=compartment_id,
                cidr_block=vcn_cidr,
                display_name=vcn_name,
                dns_label=vcn_dns_label,
            )
        ).data
        _wait_for_network_resource(
            lambda: network_client.get_vcn(vcn.id).data,
            "VCN",
        )
        state["vcn_id"] = vcn.id
        state["default_route_table_id"] = vcn.default_route_table_id
        state["default_dhcp_options_id"] = vcn.default_dhcp_options_id
        save_state(prefix, state)
        LOGGER.info(f"✅ VCN created: {vcn.id}")
    else:
        LOGGER.info(f"✅ VCN exists: {state['vcn_id']}")
        # Ensure default_route_table_id is in state (for older state files)
        if not state.get("default_route_table_id"):
            vcn = network_client.get_vcn(state["vcn_id"]).data
            state["default_route_table_id"] = vcn.default_route_table_id
            state["default_dhcp_options_id"] = vcn.default_dhcp_options_id
            save_state(prefix, state)

    vcn_id = state["vcn_id"]
    default_rt_id = state["default_route_table_id"]

    # --- Internet Gateway ---
    if not state.get("internet_gateway_id"):
        ig_name = f"{name_tag}-ig"
        LOGGER.info(f"Creating Internet Gateway '{ig_name}'...")
        ig = network_client.create_internet_gateway(
            oci.core.models.CreateInternetGatewayDetails(
                compartment_id=compartment_id,
                vcn_id=vcn_id,
                is_enabled=True,
                display_name=ig_name,
            )
        ).data
        _wait_for_network_resource(
            lambda ig_id=ig.id: network_client.get_internet_gateway(ig_id).data,
            "Internet Gateway",
        )
        state["internet_gateway_id"] = ig.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Internet Gateway created: {ig.id}")
    else:
        LOGGER.info(f"✅ Internet Gateway exists: {state['internet_gateway_id']}")

    ig_id = state["internet_gateway_id"]

    # --- Update Default Route Table (add 0.0.0.0/0 → IG) ---
    if not state.get("default_route_table_updated"):
        LOGGER.info("Adding default route (0.0.0.0/0 → IG) to VCN route table...")
        network_client.update_route_table(
            rt_id=default_rt_id,
            update_route_table_details=oci.core.models.UpdateRouteTableDetails(
                route_rules=[
                    oci.core.models.RouteRule(
                        destination="0.0.0.0/0",
                        destination_type="CIDR_BLOCK",
                        network_entity_id=ig_id,
                    )
                ]
            ),
        )
        state["default_route_table_updated"] = True
        save_state(prefix, state)
        LOGGER.info("✅ Default route table updated.")
    else:
        LOGGER.info("✅ Default route table already updated.")

    # --- Trust Private Route Table (no routes — private/internal only) ---
    if not state.get("trust_route_table_id"):
        trust_rt_name = f"{name_tag}-trust-rt"
        LOGGER.info(f"Creating trust private route table '{trust_rt_name}'...")
        trust_rt = network_client.create_route_table(
            oci.core.models.CreateRouteTableDetails(
                compartment_id=compartment_id,
                vcn_id=vcn_id,
                display_name=trust_rt_name,
                route_rules=[],
            )
        ).data
        _wait_for_network_resource(
            lambda rt_id=trust_rt.id: network_client.get_route_table(rt_id).data,
            "Trust Route Table",
        )
        state["trust_route_table_id"] = trust_rt.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Trust route table created: {trust_rt.id}")
    else:
        LOGGER.info(f"✅ Trust route table exists: {state['trust_route_table_id']}")

    trust_rt_id = state["trust_route_table_id"]

    # --- Mgmt Security List ---
    if not state.get("mgmt_security_list_id"):
        mgmt_sl_name = f"{name_tag}-mgmt-sl"
        LOGGER.info(f"Creating mgmt security list '{mgmt_sl_name}'...")
        ingress_rules = []
        for cidr in allowed_ips:
            for port in [22, 443]:
                ingress_rules.append(oci.core.models.IngressSecurityRule(
                    protocol="6",  # TCP
                    source=cidr,
                    source_type="CIDR_BLOCK",
                    tcp_options=oci.core.models.TcpOptions(
                        destination_port_range=oci.core.models.PortRange(min=port, max=port)
                    ),
                    is_stateless=False,
                ))
            ingress_rules.append(oci.core.models.IngressSecurityRule(
                protocol="1",  # ICMP
                source=cidr,
                source_type="CIDR_BLOCK",
                is_stateless=False,
            ))
        mgmt_sl = network_client.create_security_list(
            oci.core.models.CreateSecurityListDetails(
                compartment_id=compartment_id,
                vcn_id=vcn_id,
                display_name=mgmt_sl_name,
                ingress_security_rules=ingress_rules,
                egress_security_rules=[_make_egress_all()],
            )
        ).data
        _wait_for_network_resource(
            lambda sl_id=mgmt_sl.id: network_client.get_security_list(sl_id).data,
            "Mgmt Security List",
        )
        state["mgmt_security_list_id"] = mgmt_sl.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Mgmt security list created: {mgmt_sl.id}")
    else:
        LOGGER.info(f"✅ Mgmt security list exists: {state['mgmt_security_list_id']}")

    # --- Untrust Security List (no ingress, egress all) ---
    if not state.get("untrust_security_list_id"):
        untrust_sl_name = f"{name_tag}-untrust-sl"
        LOGGER.info(f"Creating untrust security list '{untrust_sl_name}'...")
        untrust_sl = network_client.create_security_list(
            oci.core.models.CreateSecurityListDetails(
                compartment_id=compartment_id,
                vcn_id=vcn_id,
                display_name=untrust_sl_name,
                ingress_security_rules=[],
                egress_security_rules=[_make_egress_all()],
            )
        ).data
        _wait_for_network_resource(
            lambda sl_id=untrust_sl.id: network_client.get_security_list(sl_id).data,
            "Untrust Security List",
        )
        state["untrust_security_list_id"] = untrust_sl.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Untrust security list created: {untrust_sl.id}")
    else:
        LOGGER.info(f"✅ Untrust security list exists: {state['untrust_security_list_id']}")

    # --- Trust Security List (RFC1918 ingress, egress all) ---
    if not state.get("trust_security_list_id"):
        trust_sl_name = f"{name_tag}-trust-sl"
        LOGGER.info(f"Creating trust security list '{trust_sl_name}'...")
        rfc1918_ingress = []
        for rfc_cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
            rfc1918_ingress.append(oci.core.models.IngressSecurityRule(
                protocol="all",
                source=rfc_cidr,
                source_type="CIDR_BLOCK",
                is_stateless=False,
            ))
        trust_sl = network_client.create_security_list(
            oci.core.models.CreateSecurityListDetails(
                compartment_id=compartment_id,
                vcn_id=vcn_id,
                display_name=trust_sl_name,
                ingress_security_rules=rfc1918_ingress,
                egress_security_rules=[_make_egress_all()],
            )
        ).data
        _wait_for_network_resource(
            lambda sl_id=trust_sl.id: network_client.get_security_list(sl_id).data,
            "Trust Security List",
        )
        state["trust_security_list_id"] = trust_sl.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Trust security list created: {trust_sl.id}")
    else:
        LOGGER.info(f"✅ Trust security list exists: {state['trust_security_list_id']}")

    # --- Mgmt Subnet ---
    if not state.get("mgmt_subnet_id"):
        mgmt_subnet_name = f"{name_tag}-mgmt-subnet"
        LOGGER.info(f"Creating mgmt subnet '{mgmt_subnet_name}' ({mgmt_cidr})...")
        mgmt_subnet = network_client.create_subnet(
            oci.core.models.CreateSubnetDetails(
                compartment_id=compartment_id,
                vcn_id=vcn_id,
                cidr_block=mgmt_cidr,
                display_name=mgmt_subnet_name,
                dns_label="mgmt",
                route_table_id=default_rt_id,
                security_list_ids=[state["mgmt_security_list_id"]],
                dhcp_options_id=state.get("default_dhcp_options_id"),
            )
        ).data
        _wait_for_network_resource(
            lambda sid=mgmt_subnet.id: network_client.get_subnet(sid).data,
            "Mgmt Subnet",
        )
        state["mgmt_subnet_id"] = mgmt_subnet.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Mgmt subnet created: {mgmt_subnet.id}")
    else:
        LOGGER.info(f"✅ Mgmt subnet exists: {state['mgmt_subnet_id']}")

    # --- Untrust Subnet ---
    if not state.get("untrust_subnet_id"):
        untrust_subnet_name = f"{name_tag}-untrust-subnet"
        LOGGER.info(f"Creating untrust subnet '{untrust_subnet_name}' ({untrust_cidr})...")
        untrust_subnet = network_client.create_subnet(
            oci.core.models.CreateSubnetDetails(
                compartment_id=compartment_id,
                vcn_id=vcn_id,
                cidr_block=untrust_cidr,
                display_name=untrust_subnet_name,
                dns_label="untrust",
                route_table_id=default_rt_id,
                security_list_ids=[state["untrust_security_list_id"]],
                dhcp_options_id=state.get("default_dhcp_options_id"),
            )
        ).data
        _wait_for_network_resource(
            lambda sid=untrust_subnet.id: network_client.get_subnet(sid).data,
            "Untrust Subnet",
        )
        state["untrust_subnet_id"] = untrust_subnet.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Untrust subnet created: {untrust_subnet.id}")
    else:
        LOGGER.info(f"✅ Untrust subnet exists: {state['untrust_subnet_id']}")

    # --- Trust Subnet (private, no public IPs) ---
    if not state.get("trust_subnet_id"):
        trust_subnet_name = f"{name_tag}-trust-subnet"
        LOGGER.info(f"Creating trust subnet '{trust_subnet_name}' ({trust_cidr})...")
        trust_subnet = network_client.create_subnet(
            oci.core.models.CreateSubnetDetails(
                compartment_id=compartment_id,
                vcn_id=vcn_id,
                cidr_block=trust_cidr,
                display_name=trust_subnet_name,
                dns_label="trust",
                route_table_id=trust_rt_id,
                security_list_ids=[state["trust_security_list_id"]],
                dhcp_options_id=state.get("default_dhcp_options_id"),
                prohibit_public_ip_on_vnic=True,
            )
        ).data
        _wait_for_network_resource(
            lambda sid=trust_subnet.id: network_client.get_subnet(sid).data,
            "Trust Subnet",
        )
        state["trust_subnet_id"] = trust_subnet.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Trust subnet created: {trust_subnet.id}")
    else:
        LOGGER.info(f"✅ Trust subnet exists: {state['trust_subnet_id']}")

    # --- Resolve Image OCID ---
    if not image_ocid:
        if not state.get("image_ocid"):
            if not marketplace_client:
                raise RuntimeError(
                    "Marketplace client unavailable. Use --image-ocid to specify the image OCID directly."
                )
            LOGGER.info(f"Resolving image OCID via OCI Marketplace for license type '{license_type}'...")
            resolved_ocid = accept_marketplace_subscription(
                marketplace_client, compute_client, compartment_id, license_type
            )
            state["image_ocid"] = resolved_ocid
            save_state(prefix, state)
        image_ocid = state["image_ocid"]
    else:
        state["image_ocid"] = image_ocid
        save_state(prefix, state)

    LOGGER.info(f"Using image OCID: {image_ocid}")

    # --- Launch Instance ---
    instance_name = f"{name_tag}-fw"
    if not state.get("instance_id"):
        LOGGER.info(f"Launching instance '{instance_name}' (shape: {shape}, OCPUs: {ocpu_count}, Memory: {memory_gb}GB)...")

        with open(ssh_pub_key_path, "r") as f:
            ssh_pub_key_data = f.read().strip()

        metadata = {"ssh_authorized_keys": ssh_pub_key_data}
        if bootstrap_user_data:
            metadata["user_data"] = bootstrap_user_data

        launch_details = oci.core.models.LaunchInstanceDetails(
            compartment_id=compartment_id,
            availability_domain=availability_domain,
            display_name=instance_name,
            shape=shape,
            shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                ocpus=ocpu_count,
                memory_in_gbs=memory_gb,
            ),
            create_vnic_details=oci.core.models.CreateVnicDetails(
                subnet_id=state["mgmt_subnet_id"],
                assign_public_ip=True,
                display_name=f"{name_tag}-mgmt-vnic",
                hostname_label=f"fw{prefix}",
            ),
            source_details=oci.core.models.InstanceSourceViaImageDetails(
                image_id=image_ocid,
            ),
            metadata=metadata,
            freeform_tags={"deployment-prefix": prefix, "name-tag": name_tag},
        )

        instance = compute_client.launch_instance(launch_details).data
        state["instance_id"] = instance.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Instance launched: {instance.id}")
    else:
        LOGGER.info(f"✅ Instance exists: {state['instance_id']}")

    instance_id = state["instance_id"]

    # --- Wait for Instance RUNNING ---
    wait_for_instance_state(compute_client, instance_id, "RUNNING")

    # --- Get Primary VNIC (mgmt) public IP ---
    if not state.get("mgmt_vnic_id") or not state.get("public_ip"):
        LOGGER.info("Retrieving primary VNIC details...")
        attachments = compute_client.list_vnic_attachments(
            compartment_id=compartment_id,
            instance_id=instance_id,
        ).data
        primary = next(
            (a for a in attachments if a.nic_index == 0 and a.lifecycle_state == "ATTACHED"),
            None,
        )
        if not primary:
            raise RuntimeError("Could not find primary VNIC attachment (nic_index=0).")
        vnic = network_client.get_vnic(primary.vnic_id).data
        state["mgmt_vnic_id"] = vnic.id
        state["mgmt_vnic_attachment_id"] = primary.id
        state["public_ip"] = vnic.public_ip
        save_state(prefix, state)
        LOGGER.info(f"✅ Management public IP: {vnic.public_ip}")
    else:
        LOGGER.info(f"✅ Management public IP: {state['public_ip']}")

    # --- Attach Untrust VNIC (nic_index=1, skip_source_dest_check, public IP) ---
    if not state.get("untrust_vnic_attachment_id"):
        LOGGER.info("Attaching untrust VNIC (NIC1, skip_source_dest_check=True)...")
        untrust_attachment = compute_client.attach_vnic(
            oci.core.models.AttachVnicDetails(
                instance_id=instance_id,
                create_vnic_details=oci.core.models.CreateVnicDetails(
                    subnet_id=state["untrust_subnet_id"],
                    assign_public_ip=True,
                    skip_source_dest_check=True,
                    display_name=f"{name_tag}-untrust-vnic",
                ),
                nic_index=1,
                display_name=f"{name_tag}-untrust-attachment",
            )
        ).data
        state["untrust_vnic_attachment_id"] = untrust_attachment.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Untrust VNIC attachment initiated: {untrust_attachment.id}")
    else:
        LOGGER.info(f"✅ Untrust VNIC attachment exists: {state['untrust_vnic_attachment_id']}")

    # Wait for untrust VNIC ATTACHED
    wait_for_vnic_attachment_state(compute_client, state["untrust_vnic_attachment_id"], "ATTACHED")

    # Get untrust VNIC details and public IP
    if not state.get("untrust_vnic_id") or not state.get("untrust_public_ip"):
        attachment = compute_client.get_vnic_attachment(state["untrust_vnic_attachment_id"]).data
        vnic = network_client.get_vnic(attachment.vnic_id).data
        # Wait for public IP assignment if not yet available
        for _ in range(12):
            if vnic.public_ip:
                break
            time.sleep(5)
            vnic = network_client.get_vnic(vnic.id).data
        state["untrust_vnic_id"] = vnic.id
        state["untrust_public_ip"] = vnic.public_ip
        save_state(prefix, state)
        LOGGER.info(f"✅ Untrust VNIC attached. Public IP: {vnic.public_ip}")
    else:
        LOGGER.info(f"✅ Untrust VNIC: {state['untrust_vnic_id']} (IP: {state.get('untrust_public_ip')})")

    # --- Attach Trust VNIC (nic_index=2, skip_source_dest_check, no public IP) ---
    if not state.get("trust_vnic_attachment_id"):
        LOGGER.info("Attaching trust VNIC (NIC2, skip_source_dest_check=True, private)...")
        trust_attachment = compute_client.attach_vnic(
            oci.core.models.AttachVnicDetails(
                instance_id=instance_id,
                create_vnic_details=oci.core.models.CreateVnicDetails(
                    subnet_id=state["trust_subnet_id"],
                    assign_public_ip=False,
                    skip_source_dest_check=True,
                    display_name=f"{name_tag}-trust-vnic",
                ),
                nic_index=2,
                display_name=f"{name_tag}-trust-attachment",
            )
        ).data
        state["trust_vnic_attachment_id"] = trust_attachment.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Trust VNIC attachment initiated: {trust_attachment.id}")
    else:
        LOGGER.info(f"✅ Trust VNIC attachment exists: {state['trust_vnic_attachment_id']}")

    # Wait for trust VNIC ATTACHED
    wait_for_vnic_attachment_state(compute_client, state["trust_vnic_attachment_id"], "ATTACHED")

    if not state.get("trust_vnic_id"):
        attachment = compute_client.get_vnic_attachment(state["trust_vnic_attachment_id"]).data
        state["trust_vnic_id"] = attachment.vnic_id
        save_state(prefix, state)
        LOGGER.info(f"✅ Trust VNIC attached: {attachment.vnic_id}")
    else:
        LOGGER.info(f"✅ Trust VNIC: {state['trust_vnic_id']}")

    return state


def destroy_infrastructure(state: Dict[str, Any], clients: Dict[str, Any]) -> None:
    """Ordered teardown: instance → subnets → route tables → IG → security lists → VCN."""
    compute_client = clients["compute"]
    network_client = clients["network"]

    def _safe_delete(label: str, delete_fn):
        try:
            LOGGER.info(f"Deleting {label}...")
            delete_fn()
            LOGGER.info(f"✅ Deleted {label}.")
        except oci.exceptions.ServiceError as e:
            if e.status == 404:
                LOGGER.warning(f"{label} not found — may already be deleted.")
            elif e.status == 409:
                LOGGER.warning(f"{label} still has dependencies or conflict: {e.message}")
            else:
                LOGGER.error(f"Failed to delete {label}: {e}")
        except Exception as e:
            LOGGER.error(f"Failed to delete {label}: {e}")

    # 1. Terminate instance
    if state.get("instance_id"):
        LOGGER.info(f"Terminating instance '{state['instance_id']}'...")
        try:
            compute_client.terminate_instance(
                instance_id=state["instance_id"],
                preserve_boot_volume=False,
            )
            wait_for_instance_state(compute_client, state["instance_id"], "TERMINATED", max_wait=900)
            LOGGER.info("✅ Instance terminated.")
            # Wait briefly for VNIC detachment cleanup
            time.sleep(10)
        except oci.exceptions.ServiceError as e:
            if e.status == 404:
                LOGGER.warning("Instance not found — may already be terminated.")
            else:
                LOGGER.error(f"Failed to terminate instance: {e}")

    # 2. Delete subnets (wait for active VNICs to clear after instance termination)
    for key, label in [
        ("trust_subnet_id", "trust subnet"),
        ("untrust_subnet_id", "untrust subnet"),
        ("mgmt_subnet_id", "mgmt subnet"),
    ]:
        if state.get(key):
            subnet_id = state[key]
            # Brief retry loop for subnet deletion (VNICs may take a moment to clear)
            for attempt in range(6):
                try:
                    network_client.delete_subnet(subnet_id)
                    LOGGER.info(f"✅ Deleted {label}: {subnet_id}")
                    break
                except oci.exceptions.ServiceError as e:
                    if e.status == 404:
                        LOGGER.warning(f"{label} not found — may already be deleted.")
                        break
                    elif e.status == 409 and attempt < 5:
                        LOGGER.warning(f"{label} still has active VNICs. Waiting 15s (attempt {attempt+1}/6)...")
                        time.sleep(15)
                    else:
                        LOGGER.error(f"Failed to delete {label}: {e}")
                        break

    # 3. Clear default route table routes (needed to delete IG)
    if state.get("default_route_table_id"):
        LOGGER.info("Clearing default route table routes...")
        try:
            network_client.update_route_table(
                rt_id=state["default_route_table_id"],
                update_route_table_details=oci.core.models.UpdateRouteTableDetails(route_rules=[]),
            )
            LOGGER.info("✅ Default route table cleared.")
        except oci.exceptions.ServiceError as e:
            if e.status != 404:
                LOGGER.warning(f"Could not clear default route table: {e}")

    # 4. Delete trust private route table
    if state.get("trust_route_table_id"):
        _safe_delete(
            f"trust route table '{state['trust_route_table_id']}'",
            lambda: network_client.delete_route_table(state["trust_route_table_id"]),
        )

    # 5. Delete Internet Gateway
    if state.get("internet_gateway_id"):
        _safe_delete(
            f"Internet Gateway '{state['internet_gateway_id']}'",
            lambda: network_client.delete_internet_gateway(state["internet_gateway_id"]),
        )

    # 6. Delete security lists
    for key, label in [
        ("mgmt_security_list_id", "mgmt security list"),
        ("untrust_security_list_id", "untrust security list"),
        ("trust_security_list_id", "trust security list"),
    ]:
        if state.get(key):
            sl_id = state[key]
            _safe_delete(
                f"{label} '{sl_id}'",
                lambda sid=sl_id: network_client.delete_security_list(sid),
            )

    # 7. Delete VCN
    if state.get("vcn_id"):
        # Brief retry in case child resources are still cleaning up
        for attempt in range(6):
            try:
                network_client.delete_vcn(state["vcn_id"])
                LOGGER.info(f"✅ Deleted VCN: {state['vcn_id']}")
                break
            except oci.exceptions.ServiceError as e:
                if e.status == 404:
                    LOGGER.warning("VCN not found — may already be deleted.")
                    break
                elif e.status == 409 and attempt < 5:
                    LOGGER.warning(f"VCN still has dependencies. Waiting 15s (attempt {attempt+1}/6)...")
                    time.sleep(15)
                else:
                    LOGGER.error(f"Failed to delete VCN: {e}")
                    break

    LOGGER.info("✅ All resources destroyed.")


def create_oci_image(
    compute_client: Any,
    compartment_id: str,
    instance_id: str,
    image_name: str,
) -> str:
    """Stops the instance and creates an OCI custom image from it. Returns the image OCID."""
    # Stop the instance
    LOGGER.info(f"Stopping instance '{instance_id}' (SOFTSTOP)...")
    compute_client.instance_action(instance_id=instance_id, action="SOFTSTOP")
    wait_for_instance_state(compute_client, instance_id, "STOPPED", max_wait=600)
    LOGGER.info(f"✅ Instance stopped.")

    # Create image from instance
    LOGGER.info(f"Creating OCI image '{image_name}' from instance...")
    image = compute_client.create_image(
        oci.core.models.CreateImageDetails(
            compartment_id=compartment_id,
            instance_id=instance_id,
            display_name=image_name,
            freeform_tags={"source-instance": instance_id},
        )
    ).data

    LOGGER.info(f"Image creation initiated (OCID: {image.id}). Waiting for AVAILABLE state...")
    wait_for_image_state(compute_client, image.id, "AVAILABLE", max_wait=1800)
    LOGGER.info(f"✅ OCI image created: {image.id} ({image_name})")
    return image.id


def private_data_reset_and_wait_stopped(
    public_ip: str,
    ssh_priv_key_path: Path,
    compute_client: Any,
    instance_id: str,
) -> None:
    """Issues private-data-reset via SSH, then waits for the instance to reach STOPPED state."""
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

    LOGGER.info("Waiting for instance to reach STOPPED state after private-data-reset...")
    wait_for_instance_state(compute_client, instance_id, "STOPPED", max_wait=600)
    LOGGER.info("✅ Instance has reached STOPPED state.")


def print_custom_image_summary(
    image_id: str,
    image_name: str,
    compartment_id: str,
    region: str,
    prefix: str,
    auth_code: str,
    allowed_ips: List[str],
    ssh_key_file: str,
    license_type: str,
    auto_destroy: bool,
) -> None:
    """Prints a post-completion summary with next-step suggestions."""
    sep = "=" * 65
    allowed_ips_str = ",".join(allowed_ips) if isinstance(allowed_ips, list) else allowed_ips

    print(f"\n{sep}")
    print(f"  Custom Image Name:  {image_name}")
    print(f"  Custom Image OCID:  {image_id}")
    print(f"  Compartment:        {compartment_id}")
    print(f"  Region:             {region}")
    print(sep)

    if not auto_destroy:
        print("\nNext steps:\n")
        print(f"  1. Destroy temporary infrastructure when ready:")
        print(f"     python oci_create_infra.py destroy --deployment-file {prefix}-state.json\n")

    print(f"  2. Deactivate auth code '{auth_code}' in the Palo Alto Networks support portal")
    print(f"     to free the license for future use:")
    print(f"     https://support.paloaltonetworks.com  →  Products → Software NGFW Credits\n")

    print(f"  3. Test the new image with a fresh deployment:")
    print(f"     python oci_create_infra.py create \\")
    print(f"         --compartment-id {compartment_id} \\")
    print(f"         --region {region} \\")
    print(f"         --name-tag \"test-{image_name}\" \\")
    print(f"         --image-ocid \"{image_id}\" \\")
    print(f"         --license-type {license_type} \\")
    print(f"         --allowed-ips \"{allowed_ips_str}\" \\")
    print(f"         --ssh-key-file {ssh_key_file}")
    print(f"\n{sep}\n")


# --- CLI Handlers ---

def _get_clients_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    """Builds OCI clients from CLI arguments."""
    config, signer = get_oci_config(
        auth_method=getattr(args, 'auth_method', 'api_key'),
        config_file=getattr(args, 'oci_config_file', '~/.oci/config'),
        profile=getattr(args, 'profile', 'DEFAULT'),
    )
    return make_oci_clients(config, signer, args.region)


def _get_clients_from_state(state: Dict[str, Any], args: argparse.Namespace) -> Dict[str, Any]:
    """Builds OCI clients using region from state + auth args."""
    region = state.get("region") or args.region
    if not region:
        LOGGER.error("No region found in state file or CLI args.")
        sys.exit(1)
    config, signer = get_oci_config(
        auth_method=getattr(args, 'auth_method', 'api_key'),
        config_file=getattr(args, 'oci_config_file', '~/.oci/config'),
        profile=getattr(args, 'profile', 'DEFAULT'),
    )
    return make_oci_clients(config, signer, region)


def handle_create(args: argparse.Namespace) -> None:
    """Handler for the 'create' command."""
    if not args.license_type and not args.image_ocid:
        LOGGER.error("You must specify either --license-type or --image-ocid.")
        sys.exit(1)

    ssh_pub_key, ssh_priv_key = get_and_validate_ssh_keys(args.ssh_key_file)
    clients = _get_clients_from_args(args)
    identity_client = clients["identity"]

    prefix = args.deployment_prefix or generate_prefix()
    state_file = Path(f"{prefix}-state.json")

    if state_file.exists():
        LOGGER.error(
            f"State file {state_file} already exists. "
            "Use a different prefix or remove the existing state file."
        )
        sys.exit(1)

    # Resolve availability domain
    availability_domain = get_availability_domain(
        identity_client, args.compartment_id, args.availability_domain
    )

    full_name_tag = f"{prefix}-{args.name_tag}"
    LOGGER.info(f"Using deployment prefix: {prefix}")

    # Build bootstrap user_data
    bootstrap_user_data = None
    bootstrap_params = [
        getattr(args, 'auth_code', None),
        getattr(args, 'pin_id', None),
        getattr(args, 'pin_value', None),
    ]
    if any(bootstrap_params):
        if not all(bootstrap_params):
            LOGGER.error("--auth-code, --pin-id, and --pin-value must all be specified together.")
            sys.exit(1)
        content = (
            f"authcodes={args.auth_code}\n"
            f"vm-series-auto-registration-pin-id={args.pin_id}\n"
            f"vm-series-auto-registration-pin-value={args.pin_value}\n"
        )
        bootstrap_user_data = base64.b64encode(content.encode()).decode()
        LOGGER.info("Bootstrap user_data generated from --auth-code, --pin-id, --pin-value.")

    args_dict = {k: v for k, v in vars(args).items() if k != 'func'}
    args_dict['ssh_key_file'] = str(ssh_pub_key)

    state = {
        "deployment_prefix": prefix,
        "compartment_id": args.compartment_id,
        "region": args.region,
        "availability_domain": availability_domain,
        "invocation_string": ' '.join(sys.argv),
        "invocation_args": args_dict,
    }
    save_state(prefix, state)

    try:
        final_state = create_infrastructure(
            compartment_id=args.compartment_id,
            region=args.region,
            availability_domain=availability_domain,
            name_tag=full_name_tag,
            prefix=prefix,
            state=state,
            clients=clients,
            license_type=args.license_type or "byol",
            shape=args.shape,
            ocpu_count=args.ocpu_count,
            memory_gb=args.memory_gb,
            vcn_cidr=args.vcn_cidr,
            mgmt_cidr=args.mgmt_cidr,
            untrust_cidr=args.untrust_cidr,
            trust_cidr=args.trust_cidr,
            allowed_ips=args.allowed_ips,
            ssh_pub_key_path=ssh_pub_key,
            bootstrap_user_data=bootstrap_user_data,
            image_ocid=args.image_ocid,
        )
        monitor_chassis_ready(final_state["public_ip"], ssh_priv_key)
        LOGGER.info(f"🎉 Infrastructure '{full_name_tag}' deployed successfully!")
        LOGGER.info(f"Management IP: {final_state['public_ip']}")
        LOGGER.info(f"To destroy: python oci_create_infra.py destroy --deployment-file {prefix}-state.json")
    except (RuntimeError, ValueError) as e:
        LOGGER.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)


def handle_destroy(args: argparse.Namespace) -> None:
    """Handler for the 'destroy' command."""
    try:
        state = load_state(args.deployment_file)
        clients = _get_clients_from_state(state, args)
        destroy_infrastructure(state, clients)
        state_file = Path(args.deployment_file)
        if state_file.exists():
            state_file.unlink()
            LOGGER.info(f"✅ Deleted state file: {state_file}")
    except (RuntimeError, ValueError, FileNotFoundError) as e:
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

    except (RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
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
        instance_id = state.get("instance_id")
        compartment_id = state.get("compartment_id")
        prefix = state.get("deployment_prefix")

        if not instance_id or not compartment_id or not prefix:
            raise RuntimeError("State file is missing required fields (instance_id, compartment_id).")

        clients = _get_clients_from_state(state, args)
        compute_client = clients["compute"]

        image_name = args.image_name
        if not image_name:
            license_type = state.get("invocation_args", {}).get("license_type", "unknown")
            image_name = f"custom-{license_type}-{time.strftime('%Y%m%d%H%M%S')}"
            LOGGER.info(f"No --image-name provided. Generated name: {image_name}")

        image_id = create_oci_image(
            compute_client=compute_client,
            compartment_id=compartment_id,
            instance_id=instance_id,
            image_name=image_name,
        )

        state.setdefault('created_images', []).append({
            'image_id': image_id,
            'image_name': image_name,
            'creation_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        })
        save_state(prefix, state)
        LOGGER.info(f"✅ Image information saved to state file.")

    except (RuntimeError, ValueError, FileNotFoundError) as e:
        LOGGER.error(f"An error occurred during image creation: {e}", exc_info=True)
        sys.exit(1)


def handle_create_custom_image(args: argparse.Namespace) -> None:
    """Handler for the 'create-custom-image' compound command."""
    ssh_pub_key, ssh_priv_key = get_and_validate_ssh_keys(args.ssh_key_file)
    clients = _get_clients_from_args(args)
    identity_client = clients["identity"]
    compute_client = clients["compute"]

    prefix = generate_prefix()
    full_name_tag = f"{prefix}-{args.name_tag}"

    availability_domain = get_availability_domain(
        identity_client, args.compartment_id, args.availability_domain
    )

    args_dict = {k: v for k, v in vars(args).items() if k != 'func'}
    args_dict['ssh_key_file'] = str(ssh_pub_key)

    state = {
        "deployment_prefix": prefix,
        "compartment_id": args.compartment_id,
        "region": args.region,
        "availability_domain": availability_domain,
        "invocation_string": ' '.join(sys.argv),
        "invocation_args": args_dict,
    }
    save_state(prefix, state)

    try:
        # Step 1: Build bootstrap user_data
        content = (
            f"authcodes={args.auth_code}\n"
            f"vm-series-auto-registration-pin-id={args.pin_id}\n"
            f"vm-series-auto-registration-pin-value={args.pin_value}\n"
        )
        bootstrap_user_data = base64.b64encode(content.encode()).decode()

        # Step 1: Deploy infrastructure
        LOGGER.info("=== Step 1: Creating infrastructure ===")
        final_state = create_infrastructure(
            compartment_id=args.compartment_id,
            region=args.region,
            availability_domain=availability_domain,
            name_tag=full_name_tag,
            prefix=prefix,
            state=state,
            clients=clients,
            license_type=args.license_type,
            shape=args.shape,
            ocpu_count=args.ocpu_count,
            memory_gb=args.memory_gb,
            vcn_cidr=args.vcn_cidr,
            mgmt_cidr=args.mgmt_cidr,
            untrust_cidr=args.untrust_cidr,
            trust_cidr=args.trust_cidr,
            allowed_ips=args.allowed_ips,
            ssh_pub_key_path=ssh_pub_key,
            bootstrap_user_data=bootstrap_user_data,
            image_ocid=None,
        )
        monitor_chassis_ready(final_state["public_ip"], ssh_priv_key)
        state = final_state
        public_ip = state["public_ip"]
        instance_id = state["instance_id"]
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
        private_data_reset_and_wait_stopped(public_ip, ssh_priv_key, compute_client, instance_id)
        state.setdefault('actions_performed', []).append({
            'command': 'private-data-reset',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        })
        save_state(prefix, state)
        LOGGER.info("✅ Private data reset complete. Instance is stopped.")

        # Step 9: Create OCI image
        LOGGER.info("=== Step 9: Creating OCI custom image ===")
        image_name = f"custom-{args.license_type}-{re.sub(r'[^a-z0-9-]', '-', target_upgrade_version.lower())}-{time.strftime('%Y%m%d%H%M%S')}"
        image_id = create_oci_image(
            compute_client=compute_client,
            compartment_id=args.compartment_id,
            instance_id=instance_id,
            image_name=image_name,
        )
        state.setdefault('created_images', []).append({
            'image_id': image_id,
            'image_name': image_name,
            'creation_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        })
        save_state(prefix, state)
        LOGGER.info(f"✅ OCI image created: {image_id} ({image_name})")

        # Step 10: Destroy infrastructure (optional)
        if args.auto_destroy:
            LOGGER.info("=== Step 10: Destroying temporary infrastructure (--auto-destroy) ===")
            destroy_infrastructure(state, clients)
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
            compartment_id=args.compartment_id,
            region=args.region,
            prefix=prefix,
            auth_code=args.auth_code,
            allowed_ips=args.allowed_ips,
            ssh_key_file=str(ssh_pub_key),
            license_type=args.license_type,
            auto_destroy=args.auto_destroy,
        )

    except (RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during create-custom-image: {e}", exc_info=True)
        sys.exit(1)


def handle_create_custom_image_restart(args: argparse.Namespace) -> None:
    """Handler for 'create-custom-image-restart'. Resumes an interrupted create-custom-image."""
    try:
        state = load_state(args.deployment_file)
        prefix = state.get("deployment_prefix")
        region = state.get("region")
        compartment_id = state.get("compartment_id")
        instance_id = state.get("instance_id")
        public_ip = state.get("public_ip")
        original_args = state.get("invocation_args", {})

        if not compartment_id or not region or not prefix:
            raise RuntimeError("State file is missing compartment_id, region, or deployment_prefix. Cannot restart.")

        clients = _get_clients_from_state(state, args)
        compute_client = clients["compute"]

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
            private_data_reset_and_wait_stopped(public_ip, ssh_priv_key, compute_client, instance_id)
            state.setdefault("actions_performed", []).append({
                "command": "private-data-reset",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            save_state(prefix, state)
            actions_done.add("private-data-reset")
            LOGGER.info("✅ Private data reset complete. Instance is stopped.")

        # Step 9: Create OCI image
        if not state.get("created_images"):
            LOGGER.info("=== Resuming Step 9: Creating OCI custom image ===")
            image_name = f"custom-{license_type}-{re.sub(r'[^a-z0-9-]', '-', (target_upgrade_version or 'unknown').lower())}-{time.strftime('%Y%m%d%H%M%S')}"
            image_id = create_oci_image(
                compute_client=compute_client,
                compartment_id=compartment_id,
                instance_id=instance_id,
                image_name=image_name,
            )
            state.setdefault("created_images", []).append({
                "image_id": image_id,
                "image_name": image_name,
                "creation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            save_state(prefix, state)
            LOGGER.info(f"✅ OCI image created: {image_id} ({image_name})")
        else:
            LOGGER.info(f"=== Step 9: Image already created ({image_id}), skipping. ===")

        # Step 10: Destroy (optional)
        if auto_destroy:
            LOGGER.info("=== Resuming Step 10: Destroying temporary infrastructure ===")
            destroy_infrastructure(state, clients)
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
            compartment_id=compartment_id,
            region=region,
            prefix=prefix,
            auth_code=original_args.get("auth_code", ""),
            allowed_ips=original_args.get("allowed_ips", []),
            ssh_key_file=original_args.get("ssh_key_file", ""),
            license_type=license_type,
            auto_destroy=auto_destroy,
        )

    except (RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during create-custom-image-restart: {e}", exc_info=True)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OCI Infrastructure CLI for Palo Alto Networks VM-Series",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    license_choices = list(MARKETPLACE_LISTINGS.keys())

    # Shared auth arguments (added to subcommands that need OCI API access)
    def _add_auth_args(p):
        p.add_argument("--auth-method", default="api_key",
                       choices=["api_key", "instance_principal", "security_token"],
                       help="OCI authentication method (default: api_key).")
        p.add_argument("--oci-config-file", default="~/.oci/config", metavar="PATH",
                       help="Path to OCI config file (default: ~/.oci/config). Used by api_key and security_token.")
        p.add_argument("--profile", default="DEFAULT",
                       help="OCI config profile name (default: DEFAULT). Used by api_key and security_token.")

    # --- Create Command ---
    parser_create = subparsers.add_parser("create", help="Create a VCN and a 3-NIC VM-Series instance.")
    parser_create.add_argument("--compartment-id", required=True, help="OCI compartment OCID.")
    parser_create.add_argument("--region", required=True, help="OCI region (e.g., us-ashburn-1).")
    parser_create.add_argument("--availability-domain", required=False,
                               help="Availability domain name (e.g., Uocm:IAD-AD-1). Default: first AD in region.")
    parser_create.add_argument("--name-tag", required=True, help="Base name for all created resources.")
    parser_create.add_argument("--deployment-prefix", required=False,
                               help="Optional prefix. A 6-char random one is generated if omitted.")
    parser_create.add_argument("--license-type", required=False, default=None,
                               choices=license_choices,
                               help="VM-Series license type. Required if --image-ocid is not provided.")
    parser_create.add_argument("--image-ocid", required=False,
                               help="OCID of a custom or Marketplace image to use (recommended). Bypasses Marketplace lookup.")
    parser_create.add_argument("--ssh-key-file", required=False, default="~/.ssh/id_rsa.pub", metavar="PATH",
                               help="Path to SSH public or private key file (default: ~/.ssh/id_rsa.pub).")
    parser_create.add_argument("--allowed-ips", required=True,
                               type=lambda s: [item.strip() for item in s.split(',')],
                               help="Comma-separated IPv4 CIDR blocks for SSH/HTTPS access to mgmt interface.")
    parser_create.add_argument("--auth-code", required=False,
                               help="BYOL auth code for bootstrap (requires --pin-id and --pin-value).")
    parser_create.add_argument("--pin-id", required=False,
                               help="VM-Series auto-registration PIN ID for bootstrap.")
    parser_create.add_argument("--pin-value", required=False,
                               help="VM-Series auto-registration PIN value for bootstrap.")
    parser_create.add_argument("--shape", default="VM.Standard3.Flex",
                               help="OCI compute shape (default: VM.Standard3.Flex).")
    parser_create.add_argument("--ocpu-count", type=float, default=4.0,
                               help="Number of OCPUs for flexible shapes (default: 4).")
    parser_create.add_argument("--memory-gb", type=float, default=16.0,
                               help="Memory in GB for flexible shapes (default: 16).")
    parser_create.add_argument("--vcn-cidr", default="10.0.0.0/16",
                               help="CIDR block for the VCN (default: 10.0.0.0/16).")
    parser_create.add_argument("--mgmt-cidr", default="10.0.1.0/24",
                               help="CIDR for the mgmt subnet (default: 10.0.1.0/24).")
    parser_create.add_argument("--untrust-cidr", default="10.0.2.0/24",
                               help="CIDR for the untrust subnet (default: 10.0.2.0/24).")
    parser_create.add_argument("--trust-cidr", default="10.0.3.0/24",
                               help="CIDR for the trust subnet (default: 10.0.3.0/24).")
    _add_auth_args(parser_create)
    parser_create.set_defaults(func=handle_create)

    # --- Destroy Command ---
    parser_destroy = subparsers.add_parser("destroy", help="Delete all resources created by 'create' (ordered teardown).")
    parser_destroy.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_destroy.add_argument("--region", required=False, default=None,
                                help="OCI region override (default: read from state file).")
    _add_auth_args(parser_destroy)
    parser_destroy.set_defaults(func=handle_destroy)

    # --- Set Admin Password Command ---
    parser_set_password = subparsers.add_parser("set-admin-password", help="Set a new random password for the admin user.")
    parser_set_password.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_set_password.add_argument("--ssh-key-file", required=False, metavar="PATH",
                                     help="Path to SSH key file. Falls back to state file path if omitted.")
    parser_set_password.set_defaults(func=handle_set_admin_password)

    # --- Upgrade Content Command ---
    parser_upgrade_content = subparsers.add_parser("upgrade-content", help="Download and install the latest content update.")
    parser_upgrade_content.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_upgrade_content.set_defaults(func=handle_upgrade_content)

    # --- Upgrade PAN-OS Command ---
    parser_upgrade_panos = subparsers.add_parser("upgrade-panos", help="Upgrade the PAN-OS software on a firewall.")
    parser_upgrade_panos.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_upgrade_panos.add_argument("--target-version", required=True,
                                      help="Target PAN-OS version (e.g., '11.1.2', '11.1', '11.1.latest').")
    parser_upgrade_panos.set_defaults(func=handle_upgrade_panos)

    # --- Upgrade Antivirus Command ---
    parser_upgrade_antivirus = subparsers.add_parser("upgrade-antivirus", help="Download and install the latest antivirus update.")
    parser_upgrade_antivirus.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_upgrade_antivirus.set_defaults(func=handle_upgrade_antivirus)

    # --- Create Image Command ---
    parser_create_image = subparsers.add_parser("create-image", help="Stop the instance and create an OCI custom image from it.")
    parser_create_image.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_create_image.add_argument("--image-name", required=False,
                                     help="Display name for the new OCI image. Generated if omitted.")
    parser_create_image.add_argument("--region", required=False, default=None,
                                     help="OCI region override (default: read from state file).")
    _add_auth_args(parser_create_image)
    parser_create_image.set_defaults(func=handle_create_image)

    # --- Create Custom Image Command ---
    parser_cci = subparsers.add_parser("create-custom-image",
                                       help="Compound: deploy, upgrade, reset, and snapshot into a custom OCI image.")
    parser_cci.add_argument("--compartment-id", required=True, help="OCI compartment OCID.")
    parser_cci.add_argument("--region", required=True, help="OCI region (e.g., us-ashburn-1).")
    parser_cci.add_argument("--availability-domain", required=False,
                            help="Availability domain name. Default: first AD in region.")
    parser_cci.add_argument("--name-tag", required=True, help="Base name for all created resources.")
    parser_cci.add_argument("--license-type", required=False, default="byol",
                            choices=license_choices,
                            help="VM-Series license type (default: byol).")
    parser_cci.add_argument("--ssh-key-file", required=False, default="~/.ssh/id_rsa.pub", metavar="PATH",
                            help="Path to SSH public or private key file (default: ~/.ssh/id_rsa.pub).")
    parser_cci.add_argument("--allowed-ips", required=True,
                            type=lambda s: [item.strip() for item in s.split(',')],
                            help="Comma-separated IPv4 CIDR blocks for SSH/HTTPS access.")
    parser_cci.add_argument("--shape", default="VM.Standard3.Flex",
                            help="OCI compute shape (default: VM.Standard3.Flex).")
    parser_cci.add_argument("--ocpu-count", type=float, default=4.0,
                            help="Number of OCPUs for flexible shapes (default: 4).")
    parser_cci.add_argument("--memory-gb", type=float, default=16.0,
                            help="Memory in GB for flexible shapes (default: 16).")
    parser_cci.add_argument("--vcn-cidr", default="10.0.0.0/16",
                            help="CIDR block for the VCN (default: 10.0.0.0/16).")
    parser_cci.add_argument("--mgmt-cidr", default="10.0.1.0/24",
                            help="CIDR for the mgmt subnet (default: 10.0.1.0/24).")
    parser_cci.add_argument("--untrust-cidr", default="10.0.2.0/24",
                            help="CIDR for the untrust subnet (default: 10.0.2.0/24).")
    parser_cci.add_argument("--trust-cidr", default="10.0.3.0/24",
                            help="CIDR for the trust subnet (default: 10.0.3.0/24).")
    parser_cci.add_argument("--auth-code", required=True, help="BYOL auth code for bootstrap auto-registration.")
    parser_cci.add_argument("--pin-id", required=True, help="VM-Series auto-registration PIN ID.")
    parser_cci.add_argument("--pin-value", required=True, help="VM-Series auto-registration PIN value.")
    parser_cci.add_argument("--target-upgrade-version", required=True,
                            help="Target PAN-OS version (e.g., '11.1.2', '11.1', '11.1.latest').")
    parser_cci.add_argument("--upgrade-antivirus", action="store_true", default=False,
                            help="Also upgrade antivirus after content upgrade.")
    parser_cci.add_argument("--auto-destroy", action="store_true", default=False,
                            help="Destroy temporary infrastructure after image creation.")
    _add_auth_args(parser_cci)
    parser_cci.set_defaults(func=handle_create_custom_image)

    # --- Create Custom Image Restart Command ---
    parser_cci_restart = subparsers.add_parser("create-custom-image-restart",
                                               help="Resume an interrupted create-custom-image from its state file.")
    parser_cci_restart.add_argument("--deployment-file", required=True,
                                    help="Path to the state file from the interrupted run.")
    parser_cci_restart.add_argument("--ssh-key-file", required=False, metavar="PATH",
                                    help="Path to SSH key file. Falls back to state file path if omitted.")
    parser_cci_restart.add_argument("--region", required=False, default=None,
                                    help="OCI region override (default: read from state file).")
    _add_auth_args(parser_cci_restart)
    parser_cci_restart.set_defaults(func=handle_create_custom_image_restart)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
