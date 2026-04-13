#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GCP Infrastructure CLI for Palo Alto Networks VM-Series

A Python CLI tool to create, destroy, monitor, or build custom images from a
Palo Alto Networks VM-Series firewall on Google Cloud Platform.

This script provides the following commands:
  1. `create`: Deploys 3 VPC networks, subnets, firewall rules, static IPs, and a
     3-NIC VM-Series firewall instance. Creates a state file to track resources.
  2. `destroy`: Ordered teardown of all created resources (instance → IPs → firewall
     rules → subnets → networks), then removes the state file.
  3. `set-admin-password`: Connects to an existing deployment and sets a new
     random password for the 'admin' user.
  4. `upgrade-content`: Downloads and installs the latest content update via API.
  5. `upgrade-panos`: Upgrades the PAN-OS software via API to a specific version.
  6. `upgrade-antivirus`: Downloads and installs the latest antivirus update via API.
  7. `create-image`: Stops the instance and creates a GCP image from its boot disk.
  8. `create-custom-image`: Compound command — deploy, license, upgrade, reset, snapshot.
  9. `create-custom-image-restart`: Resume an interrupted create-custom-image workflow.

GCP Networking Model (3 separate VPCs):
----------------------------------------
GCP requires each NIC to be in a different VPC network. The standard VM-Series
topology uses:
  - mgmt-vpc  (10.0.0.0/24) — NIC0: SSH+HTTPS access, static external IP
  - untrust-vpc (10.0.1.0/24) — NIC1: static external IP, permissive egress
  - trust-vpc   (10.0.2.0/24) — NIC2: no external IP, internal only

Background — Why create-custom-image?
--------------------------------------
PAN does not publish every PAN-OS version to the GCP Marketplace. The solution:
  1. Deploy the latest available Marketplace image version.
  2. Bootstrap with auth code + auto-registration PIN (via instance metadata).
  3. Upgrade via PAN-OS API to the desired target version.
  4. Perform private-data-reset + shutdown.
  5. Create a GCP image from the stopped instance's boot disk.

Prerequisites:
  - Python 3.12+
  - GCP credentials configured (run 'gcloud auth application-default login')
  - GCP project with Compute Engine API enabled
  - Required Python packages (see requirements.txt)

Example Usage:

# Create a firewall stack (generates a state file like 'abc123-state.json')
python gcp_create_infra.py create \\
    --project-id my-gcp-project \\
    --region us-east1 \\
    --name-tag "pa-fw-test" \\
    --allowed-ips "YOUR_IP/32" \\
    --license-type byol

# Create a custom GCP image (full lifecycle)
python gcp_create_infra.py create-custom-image \\
    --project-id my-gcp-project \\
    --region us-east1 \\
    --name-tag "my-golden-image" \\
    --allowed-ips "YOUR_IP/32" \\
    --auth-code "YOUR-AUTH-CODE" \\
    --pin-id "YOUR-PIN-ID" \\
    --pin-value "YOUR-PIN-VALUE" \\
    --target-upgrade-version "11.1"
"""

import argparse
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
    import google.auth
    from google.auth.transport.requests import Request
    from google.cloud import compute_v1
except ImportError as e:
    LOGGER = logging.getLogger(__name__)
    LOGGER.error("Google Cloud SDK libraries not found.")
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

def load_marketplace_images() -> Dict[str, Any]:
    """Loads marketplace image mappings from the external YAML file."""
    config_file = Path(__file__).parent / "marketplace_images.yaml"
    if not config_file.is_file():
        config_file = Path("marketplace_images.yaml")
    if not config_file.is_file():
        LOGGER.error(f"Configuration file 'marketplace_images.yaml' not found.")
        sys.exit(1)
    with config_file.open("r") as f:
        return yaml.safe_load(f)

MARKETPLACE_IMAGES = load_marketplace_images()


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


# --- GCP Auth ---

def get_gcp_credentials():
    """Returns GCP Application Default Credentials."""
    try:
        credentials, project = google.auth.default()
        # Refresh credentials if needed
        if not credentials.valid:
            credentials.refresh(Request())
        return credentials
    except google.auth.exceptions.DefaultCredentialsError:
        LOGGER.error(
            "No GCP credentials found. Please run: "
            "gcloud auth application-default login"
        )
        sys.exit(1)


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


def private_data_reset_and_wait_stopped(
    public_ip: str,
    ssh_priv_key_path: Path,
    instances_client: compute_v1.InstancesClient,
    project_id: str,
    zone: str,
    instance_name: str,
):
    """Issues private-data-reset via SSH, then waits for the instance to reach TERMINATED state."""
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

    LOGGER.info(f"Waiting for instance '{instance_name}' to reach TERMINATED state...")
    max_wait = 600  # 10 minutes
    start = time.time()
    while time.time() - start < max_wait:
        try:
            instance = instances_client.get(project=project_id, zone=zone, instance=instance_name)
            status = instance.status
            LOGGER.info(f"  Current instance status: {status}")
            if status == "TERMINATED":
                LOGGER.info(f"✅ Instance '{instance_name}' has reached TERMINATED state.")
                return
        except Exception as e:
            LOGGER.warning(f"Could not query instance state: {e}")
        time.sleep(30)
    raise TimeoutError(f"Instance '{instance_name}' did not stop within {max_wait // 60} minutes.")


# --- GCP Resource Management ---

def _wait_for_operation(operation_client: compute_v1.ZoneOperationsClient, project: str, zone: str, operation_name: str) -> None:
    """Polls a zonal operation until it completes."""
    while True:
        op = operation_client.get(project=project, zone=zone, operation=operation_name)
        if op.status == compute_v1.Operation.Status.DONE:
            if op.error:
                errors = [f"{e.code}: {e.message}" for e in op.error.errors]
                raise RuntimeError(f"GCP operation failed: {'; '.join(errors)}")
            return
        time.sleep(5)


def _wait_for_global_operation(operation_client: compute_v1.GlobalOperationsClient, project: str, operation_name: str) -> None:
    """Polls a global operation until it completes."""
    while True:
        op = operation_client.get(project=project, operation=operation_name)
        if op.status == compute_v1.Operation.Status.DONE:
            if op.error:
                errors = [f"{e.code}: {e.message}" for e in op.error.errors]
                raise RuntimeError(f"GCP operation failed: {'; '.join(errors)}")
            return
        time.sleep(5)


def _wait_for_region_operation(operation_client: compute_v1.RegionOperationsClient, project: str, region: str, operation_name: str) -> None:
    """Polls a regional operation until it completes."""
    while True:
        op = operation_client.get(project=project, region=region, operation=operation_name)
        if op.status == compute_v1.Operation.Status.DONE:
            if op.error:
                errors = [f"{e.code}: {e.message}" for e in op.error.errors]
                raise RuntimeError(f"GCP operation failed: {'; '.join(errors)}")
            return
        time.sleep(5)


def get_latest_marketplace_image(project_id: str, license_type: str) -> str:
    """Returns the self_link of the latest VM-Series marketplace image for the given license type."""
    image_config = MARKETPLACE_IMAGES.get(license_type)
    if not image_config:
        raise ValueError(f"Unknown license type '{license_type}'. Check marketplace_images.yaml.")

    image_project = image_config["project"]
    image_family = image_config["family"]
    # Use the family value as a name prefix (everything before the last "-segment")
    name_prefix = image_family.rsplit("-", 1)[0]  # e.g. "vmseries-flex-byol-1215" -> "vmseries-flex-byol"

    images_client = compute_v1.ImagesClient()
    LOGGER.info(f"Querying images in project '{image_project}' with name prefix '{name_prefix}'...")
    try:
        all_images = list(images_client.list(project=image_project))
        # Exclude special-purpose variants (tf=Terraform, mp=Marketplace, mptf=both)
        _EXCLUDED = ("-tf-", "-mp-", "-mptf-")
        matching = [
            img for img in all_images
            if img.name.startswith(name_prefix) and not any(x in img.name for x in _EXCLUDED)
        ]
        if not matching:
            raise RuntimeError(f"No images found matching prefix '{name_prefix}' in project '{image_project}'.")
        # Sort by parsed PAN-OS version. Image names encode versions as
        # {major}{minor}{patch} with no separators, e.g.:
        #   vmseries-flex-byol-1215  = 12.1.5
        #   vmseries-flex-byol-10112 = 10.1.12  (10 < 12, so this is older)
        # 2-digit majors are 10-20; 1-digit majors are 1-9.
        def _pan_version_key(image_name: str):
            ver = image_name.rsplit('-', 1)[-1]  # last segment, e.g. '1215' or '1114h6'
            m = re.match(r'^(\d+?)(?:h(\d+))?$', ver)
            if not m:
                return (0, 0, 0, 0)
            numeric, hotfix = m.group(1), int(m.group(2) or 0)
            if len(numeric) >= 4 and 10 <= int(numeric[:2]) <= 20:
                major, rest = int(numeric[:2]), numeric[2:]
            else:
                major, rest = int(numeric[0]), numeric[1:]
            minor = int(rest[0]) if rest else 0
            patch = int(rest[1:]) if len(rest) > 1 else 0
            return (major, minor, patch, hotfix)
        matching.sort(key=lambda img: _pan_version_key(img.name), reverse=True)
        latest = matching[0]
        LOGGER.info(f"✅ Found latest image: {latest.name} (self_link: {latest.self_link})")
        return latest.self_link
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(
            f"Failed to list images with prefix '{name_prefix}' in project '{image_project}': {e}\n"
            "Run 'python gcp_marketplace_explorer.py list-images' to discover available images."
        )


def create_infrastructure(
    project_id: str,
    region: str,
    zone: str,
    name_tag: str,
    prefix: str,
    state: Dict[str, Any],
    license_type: str,
    machine_type: str,
    mgmt_cidr: str,
    untrust_cidr: str,
    trust_cidr: str,
    allowed_ips: List[str],
    ssh_pub_key_path: Path,
    bootstrap_metadata: Optional[Dict[str, str]] = None,
    custom_image_self_link: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates or resumes the full GCP stack for the VM-Series firewall."""
    networks_client = compute_v1.NetworksClient()
    subnetworks_client = compute_v1.SubnetworksClient()
    firewalls_client = compute_v1.FirewallsClient()
    addresses_client = compute_v1.AddressesClient()
    instances_client = compute_v1.InstancesClient()
    zone_ops_client = compute_v1.ZoneOperationsClient()
    global_ops_client = compute_v1.GlobalOperationsClient()
    region_ops_client = compute_v1.RegionOperationsClient()

    LOGGER.info(f"🚀 Starting/resuming infrastructure creation for '{name_tag}'...")

    # --- Mgmt VPC Network ---
    mgmt_net_name = f"{name_tag}-mgmt-net"
    if not state.get("mgmt_network_name"):
        LOGGER.info(f"Creating mgmt VPC network '{mgmt_net_name}'...")
        op = networks_client.insert(
            project=project_id,
            network_resource=compute_v1.Network(
                name=mgmt_net_name,
                auto_create_subnetworks=False,
            )
        )
        _wait_for_global_operation(global_ops_client, project_id, op.name)
        state["mgmt_network_name"] = mgmt_net_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Mgmt VPC network created: {mgmt_net_name}")
    else:
        LOGGER.info(f"✅ Mgmt VPC network exists: {state['mgmt_network_name']}")

    # --- Untrust VPC Network ---
    untrust_net_name = f"{name_tag}-untrust-net"
    if not state.get("untrust_network_name"):
        LOGGER.info(f"Creating untrust VPC network '{untrust_net_name}'...")
        op = networks_client.insert(
            project=project_id,
            network_resource=compute_v1.Network(
                name=untrust_net_name,
                auto_create_subnetworks=False,
            )
        )
        _wait_for_global_operation(global_ops_client, project_id, op.name)
        state["untrust_network_name"] = untrust_net_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Untrust VPC network created: {untrust_net_name}")
    else:
        LOGGER.info(f"✅ Untrust VPC network exists: {state['untrust_network_name']}")

    # --- Trust VPC Network ---
    trust_net_name = f"{name_tag}-trust-net"
    if not state.get("trust_network_name"):
        LOGGER.info(f"Creating trust VPC network '{trust_net_name}'...")
        op = networks_client.insert(
            project=project_id,
            network_resource=compute_v1.Network(
                name=trust_net_name,
                auto_create_subnetworks=False,
            )
        )
        _wait_for_global_operation(global_ops_client, project_id, op.name)
        state["trust_network_name"] = trust_net_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Trust VPC network created: {trust_net_name}")
    else:
        LOGGER.info(f"✅ Trust VPC network exists: {state['trust_network_name']}")

    # --- Mgmt Subnet ---
    mgmt_subnet_name = f"{name_tag}-mgmt-subnet"
    if not state.get("mgmt_subnet_name"):
        LOGGER.info(f"Creating mgmt subnet '{mgmt_subnet_name}' ({mgmt_cidr})...")
        op = subnetworks_client.insert(
            project=project_id,
            region=region,
            subnetwork_resource=compute_v1.Subnetwork(
                name=mgmt_subnet_name,
                network=f"projects/{project_id}/global/networks/{mgmt_net_name}",
                ip_cidr_range=mgmt_cidr,
                region=region,
            )
        )
        _wait_for_region_operation(region_ops_client, project_id, region, op.name)
        state["mgmt_subnet_name"] = mgmt_subnet_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Mgmt subnet created: {mgmt_subnet_name}")
    else:
        LOGGER.info(f"✅ Mgmt subnet exists: {state['mgmt_subnet_name']}")

    # --- Untrust Subnet ---
    untrust_subnet_name = f"{name_tag}-untrust-subnet"
    if not state.get("untrust_subnet_name"):
        LOGGER.info(f"Creating untrust subnet '{untrust_subnet_name}' ({untrust_cidr})...")
        op = subnetworks_client.insert(
            project=project_id,
            region=region,
            subnetwork_resource=compute_v1.Subnetwork(
                name=untrust_subnet_name,
                network=f"projects/{project_id}/global/networks/{untrust_net_name}",
                ip_cidr_range=untrust_cidr,
                region=region,
            )
        )
        _wait_for_region_operation(region_ops_client, project_id, region, op.name)
        state["untrust_subnet_name"] = untrust_subnet_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Untrust subnet created: {untrust_subnet_name}")
    else:
        LOGGER.info(f"✅ Untrust subnet exists: {state['untrust_subnet_name']}")

    # --- Trust Subnet ---
    trust_subnet_name = f"{name_tag}-trust-subnet"
    if not state.get("trust_subnet_name"):
        LOGGER.info(f"Creating trust subnet '{trust_subnet_name}' ({trust_cidr})...")
        op = subnetworks_client.insert(
            project=project_id,
            region=region,
            subnetwork_resource=compute_v1.Subnetwork(
                name=trust_subnet_name,
                network=f"projects/{project_id}/global/networks/{trust_net_name}",
                ip_cidr_range=trust_cidr,
                region=region,
            )
        )
        _wait_for_region_operation(region_ops_client, project_id, region, op.name)
        state["trust_subnet_name"] = trust_subnet_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Trust subnet created: {trust_subnet_name}")
    else:
        LOGGER.info(f"✅ Trust subnet exists: {state['trust_subnet_name']}")

    # --- Mgmt Firewall Rule (SSH + HTTPS from allowed IPs) ---
    mgmt_fw_rule_name = f"{name_tag}-mgmt-allow"
    if not state.get("mgmt_firewall_rule_name"):
        LOGGER.info(f"Creating mgmt firewall rule '{mgmt_fw_rule_name}'...")
        op = firewalls_client.insert(
            project=project_id,
            firewall_resource=compute_v1.Firewall(
                name=mgmt_fw_rule_name,
                network=f"projects/{project_id}/global/networks/{mgmt_net_name}",
                direction="INGRESS",
                allowed=[compute_v1.Allowed(I_p_protocol="tcp", ports=["22", "443"])],
                source_ranges=allowed_ips,
                description="Allow SSH and HTTPS to VM-Series management interface",
            )
        )
        _wait_for_global_operation(global_ops_client, project_id, op.name)
        state["mgmt_firewall_rule_name"] = mgmt_fw_rule_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Mgmt firewall rule created: {mgmt_fw_rule_name}")
    else:
        LOGGER.info(f"✅ Mgmt firewall rule exists: {state['mgmt_firewall_rule_name']}")

    # --- Untrust Firewall Rule (allow all ingress) ---
    untrust_fw_rule_name = f"{name_tag}-untrust-allow"
    if not state.get("untrust_firewall_rule_name"):
        LOGGER.info(f"Creating untrust firewall rule '{untrust_fw_rule_name}'...")
        op = firewalls_client.insert(
            project=project_id,
            firewall_resource=compute_v1.Firewall(
                name=untrust_fw_rule_name,
                network=f"projects/{project_id}/global/networks/{untrust_net_name}",
                direction="INGRESS",
                allowed=[compute_v1.Allowed(I_p_protocol="all")],
                source_ranges=["0.0.0.0/0"],
                description="Allow all ingress to VM-Series untrust interface",
            )
        )
        _wait_for_global_operation(global_ops_client, project_id, op.name)
        state["untrust_firewall_rule_name"] = untrust_fw_rule_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Untrust firewall rule created: {untrust_fw_rule_name}")
    else:
        LOGGER.info(f"✅ Untrust firewall rule exists: {state['untrust_firewall_rule_name']}")

    # --- Trust Firewall Rule (allow all ingress from RFC1918) ---
    trust_fw_rule_name = f"{name_tag}-trust-allow"
    if not state.get("trust_firewall_rule_name"):
        LOGGER.info(f"Creating trust firewall rule '{trust_fw_rule_name}'...")
        op = firewalls_client.insert(
            project=project_id,
            firewall_resource=compute_v1.Firewall(
                name=trust_fw_rule_name,
                network=f"projects/{project_id}/global/networks/{trust_net_name}",
                direction="INGRESS",
                allowed=[compute_v1.Allowed(I_p_protocol="all")],
                source_ranges=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                description="Allow RFC1918 ingress to VM-Series trust interface",
            )
        )
        _wait_for_global_operation(global_ops_client, project_id, op.name)
        state["trust_firewall_rule_name"] = trust_fw_rule_name
        save_state(prefix, state)
        LOGGER.info(f"✅ Trust firewall rule created: {trust_fw_rule_name}")
    else:
        LOGGER.info(f"✅ Trust firewall rule exists: {state['trust_firewall_rule_name']}")

    # --- Mgmt Static IP ---
    mgmt_ip_name = f"{name_tag}-mgmt-ip"
    if not state.get("mgmt_ip_name"):
        LOGGER.info(f"Creating mgmt static external IP '{mgmt_ip_name}'...")
        op = addresses_client.insert(
            project=project_id,
            region=region,
            address_resource=compute_v1.Address(
                name=mgmt_ip_name,
                region=region,
                address_type="EXTERNAL",
                network_tier="PREMIUM",
            )
        )
        _wait_for_region_operation(region_ops_client, project_id, region, op.name)
        addr = addresses_client.get(project=project_id, region=region, address=mgmt_ip_name)
        state["mgmt_ip_name"] = mgmt_ip_name
        state["public_ip"] = addr.address
        save_state(prefix, state)
        LOGGER.info(f"✅ Mgmt static IP created: {addr.address}")
    else:
        if not state.get("public_ip"):
            addr = addresses_client.get(project=project_id, region=region, address=mgmt_ip_name)
            state["public_ip"] = addr.address
            save_state(prefix, state)
        LOGGER.info(f"✅ Mgmt static IP exists: {state.get('public_ip')}")

    # --- Untrust Static IP ---
    untrust_ip_name = f"{name_tag}-untrust-ip"
    if not state.get("untrust_ip_name"):
        LOGGER.info(f"Creating untrust static external IP '{untrust_ip_name}'...")
        op = addresses_client.insert(
            project=project_id,
            region=region,
            address_resource=compute_v1.Address(
                name=untrust_ip_name,
                region=region,
                address_type="EXTERNAL",
                network_tier="PREMIUM",
            )
        )
        _wait_for_region_operation(region_ops_client, project_id, region, op.name)
        addr = addresses_client.get(project=project_id, region=region, address=untrust_ip_name)
        state["untrust_ip_name"] = untrust_ip_name
        state["untrust_public_ip"] = addr.address
        save_state(prefix, state)
        LOGGER.info(f"✅ Untrust static IP created: {addr.address}")
    else:
        LOGGER.info(f"✅ Untrust static IP exists: {state.get('untrust_public_ip')}")

    # --- VM Instance ---
    instance_name = f"{name_tag}-vm"
    if not state.get("instance_name"):
        LOGGER.info(f"Launching instance '{instance_name}' ({machine_type}) in {zone}...")

        with open(ssh_pub_key_path, "r") as f:
            ssh_pub_key_data = f.read().strip()

        # Resolve source image
        if custom_image_self_link:
            source_image = custom_image_self_link
            LOGGER.info(f"Using custom image: {source_image}")
        else:
            source_image = get_latest_marketplace_image(project_id, license_type)

        # Build instance metadata for bootstrap
        metadata_items = [
            compute_v1.Items(key="ssh-keys", value=f"admin:{ssh_pub_key_data}"),
            compute_v1.Items(key="mgmt-interface-swap", value="enable"),
            compute_v1.Items(key="type", value="dhcp-client"),
            compute_v1.Items(key="op-command-modes", value="mgmt-interface-swap"),
        ]
        if bootstrap_metadata:
            for k, v in bootstrap_metadata.items():
                metadata_items.append(compute_v1.Items(key=k, value=v))

        instance_resource = compute_v1.Instance(
            name=instance_name,
            machine_type=f"zones/{zone}/machineTypes/{machine_type}",
            disks=[
                compute_v1.AttachedDisk(
                    boot=True,
                    auto_delete=True,
                    initialize_params=compute_v1.AttachedDiskInitializeParams(
                        source_image=source_image,
                        disk_type=f"zones/{zone}/diskTypes/pd-ssd",
                    ),
                )
            ],
            network_interfaces=[
                # NIC0: mgmt (with external IP)
                compute_v1.NetworkInterface(
                    subnetwork=f"projects/{project_id}/regions/{region}/subnetworks/{mgmt_subnet_name}",
                    access_configs=[
                        compute_v1.AccessConfig(
                            name="mgmt-external",
                            type_="ONE_TO_ONE_NAT",
                            nat_i_p=state["public_ip"],
                            network_tier="PREMIUM",
                        )
                    ],
                ),
                # NIC1: untrust (with external IP)
                compute_v1.NetworkInterface(
                    subnetwork=f"projects/{project_id}/regions/{region}/subnetworks/{untrust_subnet_name}",
                    access_configs=[
                        compute_v1.AccessConfig(
                            name="untrust-external",
                            type_="ONE_TO_ONE_NAT",
                            nat_i_p=state["untrust_public_ip"],
                            network_tier="PREMIUM",
                        )
                    ],
                ),
                # NIC2: trust (no external IP)
                compute_v1.NetworkInterface(
                    subnetwork=f"projects/{project_id}/regions/{region}/subnetworks/{trust_subnet_name}",
                ),
            ],
            metadata=compute_v1.Metadata(items=metadata_items),
            labels={"deployment": prefix, "name-tag": name_tag.replace("-", "_")},
            tags=compute_v1.Tags(items=[prefix]),
        )

        op = instances_client.insert(project=project_id, zone=zone, instance_resource=instance_resource)
        _wait_for_operation(zone_ops_client, project_id, zone, op.name)

        state["instance_name"] = instance_name
        state["zone"] = zone
        save_state(prefix, state)
        LOGGER.info(f"✅ Instance created: {instance_name}")
        LOGGER.info(f"✅ Management public IP: {state['public_ip']}")
    else:
        LOGGER.info(f"✅ Instance exists: {state['instance_name']}")

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


def destroy_infrastructure(project_id: str, state: Dict[str, Any]) -> None:
    """Ordered teardown: instance → IPs → firewall rules → subnets → networks."""
    region = state.get("region")
    zone = state.get("zone")
    prefix = state.get("deployment_prefix", "unknown")

    instances_client = compute_v1.InstancesClient()
    addresses_client = compute_v1.AddressesClient()
    firewalls_client = compute_v1.FirewallsClient()
    subnetworks_client = compute_v1.SubnetworksClient()
    networks_client = compute_v1.NetworksClient()
    zone_ops_client = compute_v1.ZoneOperationsClient()
    global_ops_client = compute_v1.GlobalOperationsClient()
    region_ops_client = compute_v1.RegionOperationsClient()

    def _delete_resource(label: str, delete_fn, wait_fn, **kwargs):
        try:
            LOGGER.info(f"Deleting {label}...")
            op = delete_fn(**kwargs)
            wait_fn(op.name)
            LOGGER.info(f"✅ Deleted {label}.")
        except Exception as e:
            if "was not found" in str(e) or "404" in str(e):
                LOGGER.warning(f"{label} not found — may already be deleted.")
            else:
                LOGGER.error(f"Failed to delete {label}: {e}")

    # 1. Delete instance
    if state.get("instance_name") and zone:
        _delete_resource(
            f"instance '{state['instance_name']}'",
            lambda **kw: instances_client.delete(project=project_id, zone=zone, instance=state["instance_name"]),
            lambda op_name: _wait_for_operation(zone_ops_client, project_id, zone, op_name),
        )

    # 2. Release static IPs
    if state.get("mgmt_ip_name") and region:
        _delete_resource(
            f"mgmt IP '{state['mgmt_ip_name']}'",
            lambda **kw: addresses_client.delete(project=project_id, region=region, address=state["mgmt_ip_name"]),
            lambda op_name: _wait_for_region_operation(region_ops_client, project_id, region, op_name),
        )
    if state.get("untrust_ip_name") and region:
        _delete_resource(
            f"untrust IP '{state['untrust_ip_name']}'",
            lambda **kw: addresses_client.delete(project=project_id, region=region, address=state["untrust_ip_name"]),
            lambda op_name: _wait_for_region_operation(region_ops_client, project_id, region, op_name),
        )

    # 3. Delete firewall rules
    for key in ["mgmt_firewall_rule_name", "untrust_firewall_rule_name", "trust_firewall_rule_name"]:
        if state.get(key):
            _delete_resource(
                f"firewall rule '{state[key]}'",
                lambda rule=state[key], **kw: firewalls_client.delete(project=project_id, firewall=rule),
                lambda op_name: _wait_for_global_operation(global_ops_client, project_id, op_name),
            )

    # 4. Delete subnets
    for key, net_key in [
        ("mgmt_subnet_name", "mgmt_network_name"),
        ("untrust_subnet_name", "untrust_network_name"),
        ("trust_subnet_name", "trust_network_name"),
    ]:
        if state.get(key) and region:
            _delete_resource(
                f"subnet '{state[key]}'",
                lambda subnet=state[key], **kw: subnetworks_client.delete(project=project_id, region=region, subnetwork=subnet),
                lambda op_name: _wait_for_region_operation(region_ops_client, project_id, region, op_name),
            )

    # 5. Delete VPC networks
    for key in ["mgmt_network_name", "untrust_network_name", "trust_network_name"]:
        if state.get(key):
            _delete_resource(
                f"VPC network '{state[key]}'",
                lambda net=state[key], **kw: networks_client.delete(project=project_id, network=net),
                lambda op_name: _wait_for_global_operation(global_ops_client, project_id, op_name),
            )

    LOGGER.info("✅ All resources destroyed.")


def create_gcp_image(
    project_id: str,
    zone: str,
    instance_name: str,
    image_name: str,
) -> str:
    """Stops the instance and creates a GCP image from its boot disk."""
    instances_client = compute_v1.InstancesClient()
    images_client = compute_v1.ImagesClient()
    zone_ops_client = compute_v1.ZoneOperationsClient()
    global_ops_client = compute_v1.GlobalOperationsClient()

    # Stop the instance
    LOGGER.info(f"Stopping instance '{instance_name}'...")
    op = instances_client.stop(project=project_id, zone=zone, instance=instance_name)
    _wait_for_operation(zone_ops_client, project_id, zone, op.name)
    LOGGER.info(f"✅ Instance '{instance_name}' stopped.")

    # Wait until TERMINATED
    LOGGER.info("Waiting for instance to reach TERMINATED state...")
    for _ in range(60):
        instance = instances_client.get(project=project_id, zone=zone, instance=instance_name)
        if instance.status == "TERMINATED":
            break
        time.sleep(10)
    else:
        raise TimeoutError(f"Instance '{instance_name}' did not reach TERMINATED state.")

    # Get boot disk self_link
    boot_disk = next((d for d in instance.disks if d.boot), None)
    if not boot_disk:
        raise RuntimeError(f"No boot disk found on instance '{instance_name}'.")
    disk_source = boot_disk.source
    LOGGER.info(f"Boot disk source: {disk_source}")

    # Create image from disk
    LOGGER.info(f"Creating GCP image '{image_name}' from boot disk...")
    op = images_client.insert(
        project=project_id,
        image_resource=compute_v1.Image(
            name=image_name,
            source_disk=disk_source,
            labels={"source-instance": instance_name.replace("-", "_")},
        )
    )
    _wait_for_global_operation(global_ops_client, project_id, op.name)
    image = images_client.get(project=project_id, image=image_name)
    LOGGER.info(f"✅ GCP image created: {image.self_link}")
    return image.self_link


def print_custom_image_summary(
    image_self_link: str,
    image_name: str,
    project_id: str,
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
    allowed_ips_str = ",".join(allowed_ips) if isinstance(allowed_ips, list) else allowed_ips

    print(f"\n{sep}")
    print(f"  Custom Image Name:      {image_name}")
    print(f"  Custom Image Self-Link: {image_self_link}")
    print(f"  Project:                {project_id}")
    print(f"  Region:                 {region}")
    print(sep)

    if not auto_destroy:
        print("\nNext steps:\n")
        print(f"  1. Destroy temporary infrastructure when ready:")
        print(f"     python gcp_create_infra.py destroy --deployment-file {prefix}-state.json\n")

    print(f"  2. Deactivate auth code '{auth_code}' in the Palo Alto Networks support portal")
    print(f"     to free the license for future use:")
    print(f"     https://support.paloaltonetworks.com  →  Products → Software NGFW Credits\n")

    print(f"  3. Test the new image with a fresh deployment:")
    print(f"     python gcp_create_infra.py create \\")
    print(f"         --project-id {project_id} \\")
    print(f"         --region {region} \\")
    print(f"         --name-tag \"test-{image_name}\" \\")
    print(f"         --custom-image-self-link \"{image_self_link}\" \\")
    print(f"         --license-type {license_type} \\")
    print(f"         --allowed-ips \"{allowed_ips_str}\" \\")
    print(f"         --ssh-key-file {ssh_key_file}")
    print(f"\n{sep}\n")


# --- CLI Handlers ---

def handle_create(args: argparse.Namespace) -> None:
    """Handler for the 'create' command."""
    if not args.license_type and not args.custom_image_self_link:
        LOGGER.error("You must specify either --license-type or --custom-image-self-link.")
        sys.exit(1)

    ssh_pub_key, ssh_priv_key = get_and_validate_ssh_keys(args.ssh_key_file)

    prefix = args.deployment_prefix or generate_prefix()
    state_file = Path(f"{prefix}-state.json")

    if state_file.exists():
        LOGGER.error(
            f"State file {state_file} already exists. "
            "Use a different prefix or remove the existing state file."
        )
        sys.exit(1)

    zone = args.zone or f"{args.region}-b"
    LOGGER.info(f"Using deployment prefix: {prefix}")
    full_name_tag = f"{prefix}-{args.name_tag}"

    bootstrap_metadata = None
    bootstrap_params = [
        getattr(args, 'auth_code', None),
        getattr(args, 'pin_id', None),
        getattr(args, 'pin_value', None),
    ]
    if any(bootstrap_params):
        if not all(bootstrap_params):
            LOGGER.error("--auth-code, --pin-id, and --pin-value must all be specified together.")
            sys.exit(1)
        LOGGER.info("Generating bootstrap metadata from --auth-code, --pin-id, --pin-value.")
        bootstrap_metadata = {
            "authcodes": args.auth_code,
            "vm-series-auto-registration-pin-id": args.pin_id,
            "vm-series-auto-registration-pin-value": args.pin_value,
        }

    args_dict = {k: v for k, v in vars(args).items() if k != 'func'}
    args_dict['ssh_key_file'] = str(ssh_pub_key)

    state = {
        "deployment_prefix": prefix,
        "project_id": args.project_id,
        "region": args.region,
        "zone": zone,
        "invocation_string": ' '.join(sys.argv),
        "invocation_args": args_dict,
    }
    save_state(prefix, state)

    try:
        final_state = create_infrastructure(
            project_id=args.project_id,
            region=args.region,
            zone=zone,
            name_tag=full_name_tag,
            prefix=prefix,
            state=state,
            license_type=args.license_type or "byol",
            machine_type=args.machine_type,
            mgmt_cidr=args.mgmt_cidr,
            untrust_cidr=args.untrust_cidr,
            trust_cidr=args.trust_cidr,
            allowed_ips=args.allowed_ips,
            ssh_pub_key_path=ssh_pub_key,
            bootstrap_metadata=bootstrap_metadata,
            custom_image_self_link=args.custom_image_self_link,
        )
        monitor_chassis_ready(final_state["public_ip"], ssh_priv_key)
        LOGGER.info(f"🎉 Infrastructure '{full_name_tag}' deployed successfully!")
        LOGGER.info(f"Management IP: {final_state['public_ip']}")
        LOGGER.info(f"To destroy: python gcp_create_infra.py destroy --deployment-file {prefix}-state.json")
    except (RuntimeError, ValueError) as e:
        LOGGER.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)


def handle_destroy(args: argparse.Namespace) -> None:
    """Handler for the 'destroy' command."""
    try:
        state = load_state(args.deployment_file)
        project_id = state.get("project_id")
        if not project_id:
            LOGGER.error("No project_id found in state file. Cannot destroy.")
            sys.exit(1)
        destroy_infrastructure(project_id, state)
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
        instance_name = state.get("instance_name")
        zone = state.get("zone")
        project_id = state.get("project_id")
        prefix = state.get("deployment_prefix")

        if not instance_name or not zone or not project_id or not prefix:
            raise RuntimeError("State file is missing required fields (instance_name, zone, project_id).")

        image_name = args.image_name
        if not image_name:
            license_type = state.get("invocation_args", {}).get("license_type", "unknown")
            image_name = f"custom-{license_type}-{time.strftime('%Y%m%d%H%M%S')}"
            LOGGER.info(f"No --image-name provided. Generated name: {image_name}")

        image_self_link = create_gcp_image(
            project_id=project_id,
            zone=zone,
            instance_name=instance_name,
            image_name=image_name,
        )

        state.setdefault('created_images', []).append({
            'image_self_link': image_self_link,
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

    prefix = generate_prefix()
    full_name_tag = f"{prefix}-{args.name_tag}"
    zone = args.zone or f"{args.region}-b"

    args_dict = {k: v for k, v in vars(args).items() if k != 'func'}
    args_dict['ssh_key_file'] = str(ssh_pub_key)

    state = {
        "deployment_prefix": prefix,
        "project_id": args.project_id,
        "region": args.region,
        "zone": zone,
        "invocation_string": ' '.join(sys.argv),
        "invocation_args": args_dict,
    }
    save_state(prefix, state)

    try:
        # Step 1: Deploy infrastructure with bootstrap metadata
        LOGGER.info("=== Step 1: Creating infrastructure ===")
        bootstrap_metadata = {
            "authcodes": args.auth_code,
            "vm-series-auto-registration-pin-id": args.pin_id,
            "vm-series-auto-registration-pin-value": args.pin_value,
        }

        final_state = create_infrastructure(
            project_id=args.project_id,
            region=args.region,
            zone=zone,
            name_tag=full_name_tag,
            prefix=prefix,
            state=state,
            license_type=args.license_type,
            machine_type=args.machine_type,
            mgmt_cidr=args.mgmt_cidr,
            untrust_cidr=args.untrust_cidr,
            trust_cidr=args.trust_cidr,
            allowed_ips=args.allowed_ips,
            ssh_pub_key_path=ssh_pub_key,
            bootstrap_metadata=bootstrap_metadata,
            custom_image_self_link=None,
        )
        monitor_chassis_ready(final_state["public_ip"], ssh_priv_key)
        state = final_state
        public_ip = state["public_ip"]
        instance_name = state["instance_name"]
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
        instances_client = compute_v1.InstancesClient()
        private_data_reset_and_wait_stopped(
            public_ip, ssh_priv_key, instances_client, args.project_id, zone, instance_name
        )
        state.setdefault('actions_performed', []).append({
            'command': 'private-data-reset',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        })
        save_state(prefix, state)
        LOGGER.info("✅ Private data reset complete. Instance is stopped.")

        # Step 9: Create GCP image
        LOGGER.info("=== Step 9: Creating GCP image ===")
        image_name = f"custom-{args.license_type}-{target_upgrade_version}-{time.strftime('%Y%m%d%H%M%S')}"
        # GCP image names must be lowercase alphanumeric + hyphens
        image_name = re.sub(r'[^a-z0-9\-]', '-', image_name.lower()).strip('-')
        image_self_link = create_gcp_image(
            project_id=args.project_id,
            zone=zone,
            instance_name=instance_name,
            image_name=image_name,
        )
        state.setdefault('created_images', []).append({
            'image_self_link': image_self_link,
            'image_name': image_name,
            'creation_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        })
        save_state(prefix, state)
        LOGGER.info(f"✅ GCP image created: {image_self_link} ({image_name})")

        # Step 10: Destroy infrastructure (optional)
        if args.auto_destroy:
            LOGGER.info("=== Step 10: Destroying temporary infrastructure (--auto-destroy) ===")
            destroy_infrastructure(args.project_id, state)
            state_file = Path(f"{prefix}-state.json")
            if state_file.exists():
                state_file.unlink()
                LOGGER.info(f"✅ Deleted state file: {state_file}")
        else:
            LOGGER.info("=== Step 10: Skipping infrastructure teardown (no --auto-destroy flag) ===")

        LOGGER.info(f"🎉 create-custom-image completed successfully! Image: {image_self_link}")
        print_custom_image_summary(
            image_self_link=image_self_link,
            image_name=image_name,
            project_id=args.project_id,
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
        zone = state.get("zone")
        project_id = state.get("project_id")
        instance_name = state.get("instance_name")
        public_ip = state.get("public_ip")
        original_args = state.get("invocation_args", {})

        if not project_id or not region or not prefix:
            raise RuntimeError("State file is missing project_id, region, or deployment_prefix. Cannot restart.")

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
        image_self_link = None
        image_name = None
        if state.get("created_images"):
            last = state["created_images"][-1]
            image_self_link = last.get("image_self_link")
            image_name = last.get("image_name")

        LOGGER.info(f"Resuming create-custom-image for prefix '{prefix}'. Completed steps: {actions_done or 'none'}")

        # Step 1: Complete infrastructure creation if VM was never successfully created
        if not instance_name:
            LOGGER.info("=== Resuming Step 1: VM creation incomplete — re-running infrastructure creation ===")
            iargs = original_args
            ssh_pub_key, _ = get_and_validate_ssh_keys(ssh_key_file)
            bootstrap_metadata = {
                "authcodes": iargs.get("auth_code", ""),
                "vm-series-auto-registration-pin-id": iargs.get("pin_id", ""),
                "vm-series-auto-registration-pin-value": iargs.get("pin_value", ""),
            }
            full_name_tag = f"{prefix}-{iargs.get('name_tag', 'pa-fw')}"
            state = create_infrastructure(
                project_id=project_id,
                region=region,
                zone=zone,
                name_tag=full_name_tag,
                prefix=prefix,
                state=state,
                license_type=license_type,
                machine_type=iargs.get("machine_type", "n2-standard-4"),
                mgmt_cidr=iargs.get("mgmt_cidr", "10.0.0.0/24"),
                untrust_cidr=iargs.get("untrust_cidr", "10.0.1.0/24"),
                trust_cidr=iargs.get("trust_cidr", "10.0.2.0/24"),
                allowed_ips=iargs.get("allowed_ips", ""),
                ssh_pub_key_path=ssh_pub_key,
                bootstrap_metadata=bootstrap_metadata,
                custom_image_self_link=None,
            )
            monitor_chassis_ready(state["public_ip"], ssh_priv_key)
            instance_name = state["instance_name"]
            public_ip = state["public_ip"]
            LOGGER.info("✅ Infrastructure created and chassis is ready.")

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
            instances_client = compute_v1.InstancesClient()
            private_data_reset_and_wait_stopped(
                public_ip, ssh_priv_key, instances_client, project_id, zone, instance_name
            )
            state.setdefault("actions_performed", []).append({
                "command": "private-data-reset",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            save_state(prefix, state)
            actions_done.add("private-data-reset")
            LOGGER.info("✅ Private data reset complete. Instance is stopped.")

        # Step 9: Create GCP image
        if not state.get("created_images"):
            LOGGER.info("=== Resuming Step 9: Creating GCP image ===")
            image_name = f"custom-{license_type}-{target_upgrade_version}-{time.strftime('%Y%m%d%H%M%S')}"
            image_name = re.sub(r'[^a-z0-9\-]', '-', image_name.lower()).strip('-')
            image_self_link = create_gcp_image(
                project_id=project_id,
                zone=zone,
                instance_name=instance_name,
                image_name=image_name,
            )
            state.setdefault("created_images", []).append({
                "image_self_link": image_self_link,
                "image_name": image_name,
                "creation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            save_state(prefix, state)
            LOGGER.info(f"✅ GCP image created: {image_self_link} ({image_name})")
        else:
            LOGGER.info(f"=== Step 9: Image already created ({image_self_link}), skipping. ===")

        # Step 10: Destroy (optional)
        if auto_destroy:
            LOGGER.info("=== Resuming Step 10: Destroying temporary infrastructure ===")
            destroy_infrastructure(project_id, state)
            state_file = Path(f"{prefix}-state.json")
            if state_file.exists():
                state_file.unlink()
                LOGGER.info(f"✅ Deleted state file: {state_file}")
        else:
            LOGGER.info("=== Step 10: Skipping infrastructure teardown (no --auto-destroy flag) ===")

        LOGGER.info(f"🎉 create-custom-image-restart completed successfully! Image: {image_self_link}")
        print_custom_image_summary(
            image_self_link=image_self_link,
            image_name=image_name,
            project_id=project_id,
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
        description="GCP Infrastructure CLI for Palo Alto Networks VM-Series",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Shared license-type choices
    license_choices = list(MARKETPLACE_IMAGES.keys())

    # --- Create Command ---
    parser_create = subparsers.add_parser("create", help="Create 3 VPC networks and a VM-Series instance.")
    parser_create.add_argument("--project-id", required=True, help="GCP project ID.")
    parser_create.add_argument("--region", required=True, help="GCP region (e.g., us-east1).")
    parser_create.add_argument("--zone", required=False, help="GCP zone (default: {region}-b).")
    parser_create.add_argument("--name-tag", required=True, help="Base name for all created resources.")
    parser_create.add_argument("--deployment-prefix", required=False, help="Optional prefix. A 6-char random one is generated if omitted.")
    parser_create.add_argument("--license-type", required=False, default="byol",
                               choices=license_choices,
                               help="VM-Series license type (default: byol). Required if --custom-image-self-link is not provided.")
    parser_create.add_argument("--custom-image-self-link", required=False, help="GCP image self_link of a custom image to use instead of Marketplace.")
    parser_create.add_argument("--ssh-key-file", required=False, default="~/.ssh/id_rsa.pub", metavar="PATH", help="Path to SSH public or private key file (default: ~/.ssh/id_rsa.pub).")
    parser_create.add_argument("--allowed-ips", required=True, type=lambda s: [item.strip() for item in s.split(',')], help="Comma-separated IPv4 CIDR blocks for SSH/HTTPS access to the mgmt interface.")
    parser_create.add_argument("--auth-code", required=False, help="BYOL auth code for basic bootstrapping (requires --pin-id and --pin-value).")
    parser_create.add_argument("--pin-id", required=False, help="VM-Series auto-registration PIN ID for basic bootstrapping.")
    parser_create.add_argument("--pin-value", required=False, help="VM-Series auto-registration PIN value for basic bootstrapping.")
    parser_create.add_argument("--machine-type", default="n2-standard-4", help="GCP machine type (default: n2-standard-4).")
    parser_create.add_argument("--mgmt-cidr", default="10.0.0.0/24", help="CIDR for the mgmt subnet (default: 10.0.0.0/24).")
    parser_create.add_argument("--untrust-cidr", default="10.0.1.0/24", help="CIDR for the untrust subnet (default: 10.0.1.0/24).")
    parser_create.add_argument("--trust-cidr", default="10.0.2.0/24", help="CIDR for the trust subnet (default: 10.0.2.0/24).")
    parser_create.set_defaults(func=handle_create)

    # --- Destroy Command ---
    parser_destroy = subparsers.add_parser("destroy", help="Delete all resources created by 'create' (ordered teardown).")
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
    parser_create_image = subparsers.add_parser("create-image", help="Stop the instance and create a GCP image from its boot disk.")
    parser_create_image.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_create_image.add_argument("--image-name", required=False, help="Name for the new GCP image. Generated if omitted.")
    parser_create_image.set_defaults(func=handle_create_image)

    # --- Create Custom Image Command ---
    parser_cci = subparsers.add_parser("create-custom-image", help="Compound: deploy, upgrade, reset, and snapshot into a custom GCP image.")
    parser_cci.add_argument("--project-id", required=True, help="GCP project ID.")
    parser_cci.add_argument("--region", required=True, help="GCP region (e.g., us-east1).")
    parser_cci.add_argument("--zone", required=False, help="GCP zone (default: {region}-b).")
    parser_cci.add_argument("--name-tag", required=True, help="Base name for all created resources.")
    parser_cci.add_argument("--license-type", required=False, default="byol",
                            choices=license_choices,
                            help="VM-Series license type (default: byol).")
    parser_cci.add_argument("--ssh-key-file", required=False, default="~/.ssh/id_rsa.pub", metavar="PATH", help="Path to SSH public or private key file (default: ~/.ssh/id_rsa.pub).")
    parser_cci.add_argument("--allowed-ips", required=True, type=lambda s: [item.strip() for item in s.split(',')], help="Comma-separated IPv4 CIDR blocks for SSH/HTTPS access.")
    parser_cci.add_argument("--machine-type", default="n2-standard-4", help="GCP machine type (default: n2-standard-4).")
    parser_cci.add_argument("--mgmt-cidr", default="10.0.0.0/24", help="CIDR for the mgmt subnet (default: 10.0.0.0/24).")
    parser_cci.add_argument("--untrust-cidr", default="10.0.1.0/24", help="CIDR for the untrust subnet (default: 10.0.1.0/24).")
    parser_cci.add_argument("--trust-cidr", default="10.0.2.0/24", help="CIDR for the trust subnet (default: 10.0.2.0/24).")
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
