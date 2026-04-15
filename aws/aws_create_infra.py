#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS Infrastructure CLI for Palo Alto Networks VM-Series 🚀

A modern Python CLI tool to create, destroy, monitor, or build custom AMIs from a
Palo Alto Networks VM-Series firewall.

This script provides eleven main commands:
  1. `create`: Deploys a VPC with public and private subnets, an internet gateway,
     a security group, and a 3-ENI VM-Series firewall instance. It then
     monitors the instance and runs 'show system info'. This command creates
     a state file to track resources.
  2. `destroy`: Tears down an entire deployment using its deployment state file.
  3. `create-restart`: Resumes an interrupted 'create' operation using a
     deployment state file.
  4. `set-admin-password`: Connects to an existing deployment and sets a new
     random password for the 'admin' user.
  5. `license-firewall`: Applies a BYOL auth code to an existing deployment.
  6. `upgrade-content`: Downloads and installs the latest content update on a
     licensed firewall using the XML API.
  7. `upgrade-panos`: Upgrades the PAN-OS software on a firewall to a specific
     version using the XML API.
  8. `private-data-reset`: Factory resets a firewall and shuts it down via SSH.
  9. `upgrade-antivirus`: Downloads and installs the latest antivirus update.
  10. `create-ami`: Creates an AMI from the instance in a deployment.
  11. `upgrade-vmseries-plugin`: Downloads and installs a specific VM-Series plugin version.
  12. `create-custom-ami`: Compound command that deploys, licenses, upgrades, resets,
      and snapshots a firewall into a custom AMI in one automated flow.

Prerequisites:
  - Python 3.7+
  - An AWS account with credentials configured and subscribed to the
    Palo Alto Networks VM-Series product in the AWS Marketplace.
  - Required Python packages: `boto3`, `paramiko`, `ipaddress`, `pan-os-python`, `pyyaml`
    (install with: pip install -r requirements.txt)

Tip: Finding Available Versions
-------------------------------
To find available VM-Series versions and their corresponding AMI IDs for a specific
product code and region, you can use the AWS CLI. This is useful when you want to
use the `--version` or `--target-upgrade-version` parameters.

Example for the BYOL license in us-east-2:

aws ec2 describe-images \
    --region us-east-2 \
    --filters "Name=product-code,Values=6njl1pau431dv1qxipg63mvah" "Name=owner-alias,Values=aws-marketplace" "Name=name,Values=*PA-VM-AWS*" \
    --query "reverse(sort_by(Images, &CreationDate))[*].{Version: Name, AMI_ID: ImageId, CreationDate: CreationDate}" \
    --output table

Example Usage:

# Create a full firewall stack (generates a state file like 'abc123-state.json')
python aws_create_infra.py create --region us-west-2 --name-tag "pa-fw-multinic" \
    --license-type byol --ssh-key-file ~/.ssh/id_rsa.pub \
    --allowed-ips "YOUR_PUBLIC_IP/32,ANOTHER_IP/32"

# Create an AMI from the deployed instance
python aws_create_infra.py create-ami --deployment-file "abc123-state.json" --ami-name "my-custom-panos-ami"
"""

import argparse
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
import boto3
import paramiko
import yaml
from botocore.exceptions import ClientError, WaiterError


# Import pan-os-python, handle if not installed with a more detailed error
try:
    from panos import firewall
except ImportError as e:
    LOGGER = logging.getLogger(__name__)
    LOGGER.error("A required library is missing or could not be imported.")
    LOGGER.error(f"Specific error: {e}")
    LOGGER.error("Please ensure 'pan-os-python' and all its dependencies are installed correctly (`pip install pan-os-python==1.12.3`).")
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

def load_product_codes() -> Dict[str, str]:
    """Loads product codes from the external YAML file."""
    config_file = Path("product_codes.yaml")
    if not config_file.is_file():
        LOGGER.error(f"Configuration file '{config_file}' not found.")
        sys.exit(1)
    with config_file.open("r") as f:
        return yaml.safe_load(f)

PRODUCT_CODES = load_product_codes()


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

# --- SSH Interaction Class ---

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
                self.client.connect(hostname=self.public_ip, username=self.user, key_filename=str(self.ssh_priv_key_path), timeout=15)
                LOGGER.info("✅ SSH connection successful with key authentication.")

                LOGGER.info("Opening interactive shell...")
                self.shell = self.client.invoke_shell()
                self.wait_for_prompt(timeout=90) # Wait longer for initial prompt
                
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
                # Wait a moment to see if more data arrives after the prompt.
                # This handles cases where the full command output arrives after the prompt.
                time.sleep(1) 
                if not self.shell.recv_ready():
                    # If no new data has arrived, we are finished.
                    return output
            
            time.sleep(0.2)
    
    def send_command(self, command, prompt_chars=['>', '#'], timeout=60):
        """Sends a command and returns the output once a prompt reappears."""
        self.shell.send(command + '\n')
        full_output = self.wait_for_prompt(prompt_chars, timeout)
        # Clean up the output by removing the sent command and the final prompt
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


# --- AWS Resource Management ---


def get_ami_id_with_details(region: str, license_type: str, version: Optional[str] = None) -> Tuple[str, str, int]:
    """
    Finds the latest or specific VM-Series AMI and returns its ID, root device name,
    and default root volume size.
    """
    if version:
        LOGGER.info(f"Finding AMI for license '{license_type}' and version '{version}' in {region}...")
    else:
        LOGGER.info(f"Finding latest AMI for license type '{license_type}' in {region}...")

    if license_type not in PRODUCT_CODES:
        raise ValueError(f"Invalid license type specified: {license_type}")

    ec2_client = boto3.client("ec2", region_name=region)
    filters = [
        {"Name": "product-code", "Values": [PRODUCT_CODES[license_type]]},
        {"Name": "state", "Values": ["available"]},
        {"Name": "virtualization-type", "Values": ["hvm"]},
    ]

    if version:
        name_filter = f"PA-VM-AWS-{version}*"
        LOGGER.info(f"Applying name filter: '{name_filter}'")
        filters.append({"Name": "name", "Values": [name_filter]})
        
    try:
        response = ec2_client.describe_images(Owners=["aws-marketplace"], Filters=filters)
        images = sorted(response["Images"], key=lambda x: x["CreationDate"], reverse=True)
        
        if not images:
            error_msg = f"No VM-Series AMI found for license '{license_type}'"
            if version:
                error_msg += f" and version '{version}'"
            error_msg += ". Please check the version number or ensure you are subscribed to the product in the AWS Marketplace for this region."
            raise RuntimeError(error_msg)
        
        selected_image = images[0]
        ami_id = selected_image["ImageId"]
        
        # --- MODIFIED: Extract root device name and size ---
        root_device_name = selected_image.get("RootDeviceName", "/dev/sda1") # Default
        root_volume_size = 80 # Default size in GiB for PAN-OS
        
        if "BlockDeviceMappings" in selected_image:
            for bdm in selected_image["BlockDeviceMappings"]:
                if bdm.get("DeviceName") == root_device_name:
                    # Use the size from the AMI, but ensure it's at least the default
                    ami_size = bdm.get("Ebs", {}).get("VolumeSize", 80)
                    root_volume_size = max(ami_size, root_volume_size)
                    break
        # --- END MODIFIED ---

        LOGGER.info(f"✅ Found AMI: {ami_id} (Name: {selected_image['Name']})")
        LOGGER.info(f"  Root Device: {root_device_name}, Default Size: {root_volume_size} GiB")
        return ami_id, root_device_name, root_volume_size # Return tuple
    except ClientError as e:
        if "AuthFailure" in str(e):
             LOGGER.error("AWS authentication failed. Please check your credentials.")
        raise

def create_infrastructure(
    region: str,
    name_tag: str,
    prefix: str,
    state: Dict[str, Any],
    license_type: str,
    version: Optional[str],
    instance_type: str,
    vpc_cidr: str,
    public_subnet_cidr: str,
    private_subnet_cidr: str,
    allowed_ips: List[str],
    ssh_pub_key_path: Path,
    user_data: Optional[str] = None,
    ami_id_override: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates or resumes the full AWS stack for the VM-Series firewall."""
    ec2_client = boto3.client("ec2", region_name=region)
    ec2_resource = boto3.resource("ec2", region_name=region)
    iam_client = boto3.client("iam", region_name=region)
    
    LOGGER.info(f"🚀 Starting/resuming infrastructure creation for '{name_tag}'...")
    
    base_tags = [{"Key": "ManagedBy", "Value": "aws_infra_tool.py"}, {"Key": "DeploymentPrefix", "Value": prefix}]
    
    # ... (VPC, IGW, Subnets, Route Table, SG, EIP from previous step remain the same)
    # VPC
    if not state.get("vpc_id"):
        LOGGER.info(f"Creating VPC with CIDR {vpc_cidr}...")
        vpc_tags = base_tags + [{"Key": "Name", "Value": name_tag}]
        vpc = ec2_resource.create_vpc(CidrBlock=vpc_cidr, TagSpecifications=[{"ResourceType": "vpc", "Tags": vpc_tags}])
        vpc.wait_until_available()
        state["vpc_id"] = vpc.id
        save_state(prefix, state)
        LOGGER.info(f"✅ VPC created: {vpc.id}")
    else:
        vpc = ec2_resource.Vpc(state["vpc_id"])
        LOGGER.info(f"✅ VPC exists: {vpc.id}")

    # Internet Gateway
    if not state.get("igw_id"):
        LOGGER.info("Creating Internet Gateway...")
        igw_tags = base_tags + [{"Key": "Name", "Value": name_tag}]
        igw = ec2_resource.create_internet_gateway(TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": igw_tags}])
        vpc.attach_internet_gateway(InternetGatewayId=igw.id)
        state["igw_id"] = igw.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Internet Gateway created and attached: {igw.id}")
    else:
        igw = ec2_resource.InternetGateway(state["igw_id"])
        LOGGER.info(f"✅ Internet Gateway exists: {igw.id}")

    # Public Subnet
    if not state.get("public_subnet_id"):
        LOGGER.info("Creating Public Subnet...")
        public_subnet_tags = base_tags + [{"Key": "Name", "Value": f"{name_tag}-public"}]
        public_subnet = vpc.create_subnet(CidrBlock=public_subnet_cidr, TagSpecifications=[{"ResourceType": "subnet", "Tags": public_subnet_tags}])
        ec2_client.modify_subnet_attribute(SubnetId=public_subnet.id, MapPublicIpOnLaunch={"Value": True})
        state["public_subnet_id"] = public_subnet.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Public Subnet created: {public_subnet.id}")
    else:
        public_subnet = ec2_resource.Subnet(state["public_subnet_id"])
        LOGGER.info(f"✅ Public Subnet exists: {public_subnet.id}")
    
    # Private Subnet
    if not state.get("private_subnet_id"):
        LOGGER.info("Creating Private Subnet...")
        private_subnet_tags = base_tags + [{"Key": "Name", "Value": f"{name_tag}-private"}]
        private_subnet = vpc.create_subnet(CidrBlock=private_subnet_cidr, TagSpecifications=[{"ResourceType": "subnet", "Tags": private_subnet_tags}])
        state["private_subnet_id"] = private_subnet.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Private Subnet created: {private_subnet.id}")
    else:
        private_subnet = ec2_resource.Subnet(state["private_subnet_id"])
        LOGGER.info(f"✅ Private Subnet exists: {private_subnet.id}")

    # Route Table
    if not state.get("route_table_id"):
        LOGGER.info("Creating Route Table...")
        rt_tags = base_tags + [{"Key": "Name", "Value": name_tag}]
        route_table = vpc.create_route_table(TagSpecifications=[{"ResourceType": "route-table", "Tags": rt_tags}])
        route_table.create_route(DestinationCidrBlock="0.0.0.0/0", GatewayId=igw.id)
        route_table.associate_with_subnet(SubnetId=public_subnet.id)
        state["route_table_id"] = route_table.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Route table created and associated: {route_table.id}")
    else:
        LOGGER.info(f"✅ Route Table exists: {state['route_table_id']}")

    # Security Group
    if not state.get("sg_id"):
        LOGGER.info("Creating Security Group...")
        sg_tags = base_tags + [{"Key": "Name", "Value": f"{name_tag}-sg"}]
        sg = vpc.create_security_group(GroupName=f"{name_tag}-sg", Description="Allows SSH and HTTPS access from specified IPs for management.", TagSpecifications=[{"ResourceType": "security-group", "Tags": sg_tags}])
        sg.authorize_ingress(IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": ip} for ip in allowed_ips]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": ip} for ip in allowed_ips]}
        ])
        state["sg_id"] = sg.id
        save_state(prefix, state)
        LOGGER.info(f"✅ Security Group created: {sg.id}")
    else:
        sg = ec2_resource.SecurityGroup(state["sg_id"])
        LOGGER.info(f"✅ Security Group exists: {sg.id}")
    
    # EIP
    if not state.get("eip_alloc_id"):
        LOGGER.info("Allocating EIP...")
        eip_tags = base_tags + [{"Key": "Name", "Value": f"{name_tag}-eip"}]
        eip = ec2_client.allocate_address(Domain='vpc', TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": eip_tags}])
        state["eip_alloc_id"] = eip["AllocationId"]
        state["eip_public_ip"] = eip["PublicIp"]
        save_state(prefix, state)
        LOGGER.info(f"✅ EIP allocated: {eip['PublicIp']}")
    else:
        LOGGER.info(f"✅ EIP exists: {state['eip_public_ip']}")

    # IAM Role, Policy, and Instance Profile
    if not state.get("instance_profile_name"):
        LOGGER.info("Creating IAM Role and Instance Profile...")
        role_name = f"{name_tag}-role"
        profile_name = f"{name_tag}-instance-profile"
        policy_name = "CloudWatchLogsAccess"
        
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
        }
        logs_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Action": ["logs:PutLogEvents", "logs:CreateLogStream", "logs:CreateLogGroup"], "Effect": "Allow", "Resource": "*", "Sid": "CloudWatchLogsAccess"}]
        }
        
        try:
            iam_client.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
            iam_client.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(logs_policy))
            iam_client.create_instance_profile(InstanceProfileName=profile_name)
            iam_client.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
            
            state["role_name"] = role_name
            state["instance_profile_name"] = profile_name
            save_state(prefix, state)
            LOGGER.info(f"✅ IAM Role and Instance Profile created: {profile_name}")
            # Wait for IAM propagation
            LOGGER.info("Waiting 15 seconds for IAM changes to propagate...")
            time.sleep(15)
        except iam_client.exceptions.EntityAlreadyExistsException:
            LOGGER.warning("IAM Role or Instance Profile may already exist. Assuming it's configured correctly.")
            state["role_name"] = role_name
            state["instance_profile_name"] = profile_name
            save_state(prefix, state)
    else:
        LOGGER.info(f"✅ IAM Instance Profile exists: {state['instance_profile_name']}")

    # Key Pair
    if not state.get("key_name"):
        key_name = f"{name_tag}-key"
        key_tags = base_tags + [{"Key": "Name", "Value": key_name}]
        with open(ssh_pub_key_path, "r") as key_file:
            public_key_material = key_file.read()
        try:
            ec2_client.import_key_pair(KeyName=key_name, PublicKeyMaterial=public_key_material, TagSpecifications=[{"ResourceType": "key-pair", "Tags": key_tags}])
            state["key_name"] = key_name
            save_state(prefix, state)
            LOGGER.info(f"✅ Key Pair imported: {key_name}")
        except ClientError as e:
            if "InvalidKeyPair.Duplicate" in str(e):
                state["key_name"] = key_name
                save_state(prefix, state)
                LOGGER.warning(f"Key Pair '{key_name}' already exists. Reusing it.")
            else:
                raise
    else:
        key_name = state["key_name"]
        LOGGER.info(f"✅ Key Pair exists: {key_name}")
    
    # Instance and ENIs
    if not state.get("instance_id"):
        if ami_id_override:
            ami_id = ami_id_override
            LOGGER.info(f"Using provided custom AMI ID: {ami_id}")
            # We must guess the root device name and size for custom AMIs
            root_device_name = "/dev/sda1" 
            root_volume_size = 80 
            LOGGER.warning(f"Using custom AMI. Assuming root device '{root_device_name}' and size {root_volume_size} GiB for gp3 volume.")
        else:
            # --- MODIFIED: Call new function ---
            ami_id, root_device_name, root_volume_size = get_ami_id_with_details(region, license_type, version)
        
        public_network = ipaddress.ip_network(public_subnet_cidr)
        private_network = ipaddress.ip_network(private_subnet_cidr)
        public_hosts = list(public_network.hosts())
        eth0_private_ip, eth1_private_ip = str(public_hosts[3]), str(public_hosts[4])
        eth2_private_ip = str(list(private_network.hosts())[3])

        # --- MODIFIED: Updated log message ---
        LOGGER.info(f"Launching VM-Series instance ({instance_type}) with gp3 root volume...")
        instance_tags = base_tags + [{"Key": "Name", "Value": name_tag}]
        
        instance_params = {
            "ImageId": ami_id, "InstanceType": instance_type, "MinCount": 1, "MaxCount": 1, "KeyName": key_name,
            "IamInstanceProfile": {"Name": state["instance_profile_name"]},
            # --- MODIFIED: Add BlockDeviceMappings for gp3 ---
            "BlockDeviceMappings": [
                {
                    "DeviceName": root_device_name,
                    "Ebs": {
                        "VolumeType": "gp3",
                        "VolumeSize": root_volume_size,
                        "DeleteOnTermination": True,
                        "Iops": 3000,       # Default for gp3, can be customized
                        "Throughput": 125  # Default for gp3, can be customized
                    }
                }
            ],
            # --- END MODIFIED ---
            "NetworkInterfaces": [{"DeviceIndex": 0, "SubnetId": public_subnet.id, "Groups": [sg.id], "PrivateIpAddress": eth0_private_ip}],
            "TagSpecifications": [{"ResourceType": "instance", "Tags": instance_tags}]
        }
        if user_data:
            instance_params["UserData"] = user_data

        instance = ec2_resource.create_instances(**instance_params)[0]
        state["instance_id"] = instance.id
        save_state(prefix, state)
        
        LOGGER.info(f"Waiting for instance {instance.id} to enter 'running' state...")
        instance.wait_until_running()
        instance.reload()
        state["management_public_ip"] = instance.public_ip_address
        save_state(prefix, state)
        LOGGER.info(f"✅ Instance is running: {instance.id} at {instance.public_ip_address}")

        LOGGER.info("Configuring network interfaces...")
        primary_eni_id = instance.network_interfaces_attribute[0]['NetworkInterfaceId']
        state["eth0_eni_id"] = primary_eni_id
        save_state(prefix, state)
        LOGGER.info("✅ Confirmed Source/Dest check is enabled on eth0 (management).")

        untrust_eni_tags = base_tags + [{"Key": "Name", "Value": f"{name_tag}-untrust-eni"}]
        untrust_eni = ec2_resource.create_network_interface(
            SubnetId=public_subnet.id, Description='VM-Series Untrust Interface (eth1)', Groups=[sg.id],
            PrivateIpAddress=eth1_private_ip, TagSpecifications=[{"ResourceType": "network-interface", "Tags": untrust_eni_tags}])
        untrust_eni.attach(InstanceId=instance.id, DeviceIndex=1)
        ec2_client.associate_address(AllocationId=state["eip_alloc_id"], NetworkInterfaceId=untrust_eni.id)
        state["eth1_eni_id"] = untrust_eni.id
        save_state(prefix, state)
        LOGGER.info("✅ Created, attached, and configured eth1 (untrust) with EIP.")

        trust_eni_tags = base_tags + [{"Key": "Name", "Value": f"{name_tag}-trust-eni"}]
        trust_eni = ec2_resource.create_network_interface(
            SubnetId=private_subnet.id, Description='VM-Series Trust Interface (eth2)', Groups=[sg.id],
            PrivateIpAddress=eth2_private_ip, TagSpecifications=[{"ResourceType": "network-interface", "Tags": trust_eni_tags}])
        trust_eni.attach(InstanceId=instance.id, DeviceIndex=2)
        ec2_client.modify_network_interface_attribute(NetworkInterfaceId=trust_eni.id, SourceDestCheck={'Value': False})
        state["eth2_eni_id"] = trust_eni.id
        save_state(prefix, state)
        LOGGER.info("✅ Created, attached, and configured eth2 (trust).")
    else:
        LOGGER.info(f"✅ Instance and ENIs exist: {state['instance_id']}")

    return state


def monitor_and_run_command(public_ip: str, ssh_priv_key_path: Path, region: str, instance_id: str) -> None:
    # ... (code from previous step)
    ssh = FirewallSSHClient(public_ip, ssh_priv_key_path)
    try:
        ssh.connect()
        # Wait for the firewall to be fully ready
        for attempt in range(40):
            LOGGER.info(f"Checking chassis readiness (Attempt {attempt + 1}/40)...")
            output = ssh.send_command("show chassis-ready")
            if "yes" in output.lower():
                LOGGER.info("✅ Firewall chassis is ready!")
                system_info = ssh.send_command("show system info")
                LOGGER.info("--- 💻 Palo Alto Networks VM-Series System Info ---")
                print(system_info)
                LOGGER.info("--------------------------------------------------")
                
                # Extract software version and tag the instance
                match = re.search(r"sw-version:\s+(\S+)", system_info)
                if match:
                    panos_version = match.group(1)
                    LOGGER.info(f"Found PAN-OS version: {panos_version}")
                    try:
                        ec2_client = boto3.client("ec2", region_name=region)
                        ec2_client.create_tags(
                            Resources=[instance_id],
                            Tags=[{'Key': 'sw-version', 'Value': panos_version}]
                        )
                        LOGGER.info(f"✅ Instance {instance_id} tagged with sw-version: {panos_version}")
                    except ClientError as e:
                        LOGGER.warning(f"Could not tag instance {instance_id}: {e}")
                else:
                    LOGGER.warning("Could not determine PAN-OS version from 'show system info'.")
                return
            else:
                LOGGER.info(f"Firewall not ready yet. Retrying in 30 seconds...")
                time.sleep(30)
        raise TimeoutError("Timed out waiting for firewall chassis to become ready.")
    finally:
        ssh.close()

def license_firewall(public_ip: str, ssh_priv_key_path: Path, auth_code: str, region: str, instance_id: str) -> Optional[str]:
    """Connects to a firewall, applies a license, and verifies."""
    ssh = FirewallSSHClient(public_ip, ssh_priv_key_path)
    serial_number = None
    try:
        ssh.connect()
        
        LOGGER.info("Checking for existing license...")
        info = ssh.send_command("show system info")
        match = re.search(r"^serial:\s+(\S+)", info, re.MULTILINE)
        if match and match.group(1) != "unknown":
            serial_number = match.group(1)
            LOGGER.info(f"Firewall is already licensed with serial: {serial_number}. Tagging instance and skipping license fetch.")
        else:
            LOGGER.info("Firewall not licensed. Applying license with auth code...")
            try:
                ssh.shell.send(f"request license fetch auth-code {auth_code}\n")
                time.sleep(10)
            except Exception as e:
                 LOGGER.info(f"SSH session disconnected as expected after license fetch command: {e}")

            ssh.reboot_and_reconnect(initial_wait=10)
            
            LOGGER.info("Verifying serial number appears after licensing...")
            info = ssh.send_command("show system info")
            
            match = re.search(r"^serial:\s+(\S+)", info, re.MULTILINE)
            if match:
                serial_number = match.group(1)

            if not (serial_number and serial_number != "unknown"):
                LOGGER.error(f"Could not find a valid serial number after licensing. Full output:\n{info}")
                raise RuntimeError("Firewall did not get a valid serial number after licensing.")
        
        if serial_number:
            LOGGER.info(f"✅ Serial number found: {serial_number}. Licensing successful.")
            LOGGER.info(f"Tagging instance {instance_id} with serial number...")
            try:
                ec2_client = boto3.client("ec2", region_name=region)
                ec2_client.create_tags(
                    Resources=[instance_id],
                    Tags=[{'Key': 'pan-os-serial', 'Value': serial_number}]
                )
                LOGGER.info(f"✅ Instance tagged with pan-os-serial: {serial_number}")
            except ClientError as e:
                LOGGER.warning(f"Could not tag instance {instance_id}: {e}")
        return serial_number

    finally:
        ssh.close()
    return serial_number

def upgrade_content_api(public_ip: str, password: str) -> Optional[str]:
    """Connects to a firewall via API, downloads and installs the latest content."""
    try:
        fw = firewall.Firewall(public_ip, "admin", password)
    except Exception as e:
        raise RuntimeError(f"Failed to connect to firewall API: {e}")

    # Step 1: Verify firewall is licensed
    LOGGER.info("Verifying firewall is licensed before starting content upgrade...")
    system_info = fw.op("show system info")
    serial = system_info.findtext("./result/system/serial")
    if not serial or serial == "unknown":
        raise RuntimeError("Firewall is not licensed. Cannot perform content upgrade.")
    LOGGER.info(f"✅ Firewall is licensed with serial: {serial}")

    # Step 2: Download and install latest content using the correct class
    updater = fw.content
    LOGGER.info("Requesting download and install of latest content...")
    # This combines both download and install into a single, monitored action
    updater.download_and_install_latest(sync=True)
    LOGGER.info("✅ Content download and installation complete.")
    return serial

def resolve_panos_version(public_ip: str, password: str, version_spec: str) -> str:
    """Resolves 'X.Y' or 'X.Y.latest' to the latest available patch version. Full 'X.Y.Z' passes through unchanged."""
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


def upgrade_panos_api(public_ip: str, password: str, target_version: str, region: str, instance_id: str) -> Optional[str]:
    """Connects to a firewall via API and upgrades the PAN-OS software."""
    try:
        fw = firewall.Firewall(public_ip, "admin", password)
    except Exception as e:
        raise RuntimeError(f"Failed to connect to firewall API: {e}")

    # Step 1: Verify firewall is licensed
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
        LOGGER.info(f"Current version: {fw.version}")
    except Exception as e:
        if "no element found" in str(e) or "ParseError" in str(e):
            LOGGER.info("Device is rebooting after upgrade — XML API unavailable as expected. Continuing.")
        else:
            raise

    # Tag the instance with the new software version
    try:
        ec2_client = boto3.client("ec2", region_name=region)
        ec2_client.create_tags(
            Resources=[instance_id],
            Tags=[{'Key': 'sw-version', 'Value': target_version}]
        )
        LOGGER.info(f"✅ Instance {instance_id} tagged with sw-version: {target_version}")
    except ClientError as e:
        LOGGER.warning(f"Could not tag instance {instance_id} with new version: {e}")

    return serial

def upgrade_antivirus_api(public_ip: str, password: str) -> Optional[str]:
    """Connects to a firewall via API, downloads and installs the latest antivirus update."""
    try:
        fw = firewall.Firewall(public_ip, "admin", password)
    except Exception as e:
        raise RuntimeError(f"Failed to connect to firewall API: {e}")

    # Step 1: Verify firewall is licensed
    LOGGER.info("Verifying firewall is licensed before starting antivirus upgrade...")
    system_info = fw.op("show system info")
    serial = system_info.findtext("./result/system/serial")
    if not serial or serial == "unknown":
        raise RuntimeError("Firewall is not licensed. Cannot perform antivirus upgrade.")
    LOGGER.info(f"✅ Firewall is licensed with serial: {serial}")

    # Step 2: Check for latest antivirus update
    LOGGER.info("Checking for latest antivirus update...")
    check_response = fw.op(cmd="<request><anti-virus><upgrade><check/></upgrade></anti-virus></request>", cmd_xml=True)
    
    # Step 3: Parse the response to find the latest version and its status
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
    
    # Step 4: Download if not already downloaded
    if latest_version_info['downloaded'] != 'yes':
        LOGGER.info("Requesting download of latest antivirus update...")
        response = fw.op(cmd="<request><anti-virus><upgrade><download><latest/></latest></download></upgrade></anti-virus></request>", cmd_xml=True)
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

    # Step 5: Install latest antivirus update
    LOGGER.info(f"Requesting installation of version {latest_version_info['version']}...")
    install_cmd = f"<request><anti-virus><upgrade><install><version>{latest_version_info['version']}</version></install></upgrade></anti-virus></request>"
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


def upgrade_vmseries_plugin_api(public_ip: str, password: str, plugin_version: str) -> None:
    """Connects to a firewall via API, downloads and installs a specific VM-Series plugin version."""
    try:
        fw = firewall.Firewall(public_ip, "admin", password)
    except Exception as e:
        raise RuntimeError(f"Failed to connect to firewall API: {e}")

    # Step 1: Verify firewall is licensed
    LOGGER.info("Verifying firewall is licensed before starting VM-Series plugin upgrade...")
    system_info = fw.op("show system info")
    serial = system_info.findtext("./result/system/serial")
    if not serial or serial == "unknown":
        raise RuntimeError("Firewall is not licensed. Cannot perform plugin upgrade.")
    LOGGER.info(f"✅ Firewall is licensed with serial: {serial}")

    # Step 2: Check if this version is already installed
    LOGGER.info(f"Checking if VM-Series plugin version {plugin_version} is already installed...")
    installed_response = fw.op(cmd="<show><plugins><installed></installed></plugins></show>", cmd_xml=True)
    for entry in installed_response.findall(".//entry"):
        if entry.get("name") == "vm_series":
            current_version = entry.findtext("version")
            if current_version == plugin_version:
                LOGGER.info(f"✅ VM-Series plugin version {plugin_version} is already installed. Skipping.")
                return
            else:
                LOGGER.info(f"Current VM-Series plugin version is {current_version}. Will upgrade to {plugin_version}.")

    # Step 3: Download the plugin
    plugin_file = f"vm_series-{plugin_version}.tgz"
    LOGGER.info(f"Requesting download of VM-Series plugin: {plugin_file}...")
    download_cmd = f"<request><plugins><download><file>{plugin_file}</file></download></plugins></request>"
    response = fw.op(cmd=download_cmd, cmd_xml=True)
    job_id = response.findtext('./result/job')
    if not job_id:
        raise RuntimeError("Could not find job ID for plugin download task.")

    LOGGER.info(f"Download job started with ID: {job_id}. Monitoring progress...")
    while True:
        job_info = fw.op(cmd=f"<show><jobs><id>{job_id}</id></show>", cmd_xml=True)
        status = job_info.findtext('.//status')
        if status == "FIN":
            result = job_info.findtext('.//result')
            if result != "OK":
                raise RuntimeError(f"Plugin download job finished with unexpected result: {result}")
            LOGGER.info("✅ VM-Series plugin download complete.")
            break
        progress = job_info.findtext('.//progress')
        LOGGER.info(f"Download in progress - Status: {status}, Progress: {progress}%...")
        time.sleep(10)

    # Step 4: Install the plugin
    install_name = f"vm_series-{plugin_version}"
    LOGGER.info(f"Requesting installation of VM-Series plugin: {install_name}...")
    install_cmd = f"<request><plugins><install>{install_name}</install></plugins></request>"
    response = fw.op(cmd=install_cmd, cmd_xml=True)
    job_id = response.findtext('./result/job')
    if not job_id:
        raise RuntimeError("Could not find job ID for plugin install task.")

    LOGGER.info(f"Installation job started with ID: {job_id}. Monitoring progress...")
    while True:
        job_info = fw.op(cmd=f"<show><jobs><id>{job_id}</id></show>", cmd_xml=True)
        status = job_info.findtext('.//status')
        if status == "FIN":
            result = job_info.findtext('.//result')
            if result != "OK":
                raise RuntimeError(f"Plugin install job finished with unexpected result: {result}")
            LOGGER.info("✅ VM-Series plugin installation complete.")
            break
        progress = job_info.findtext('.//progress')
        LOGGER.info(f"Installation in progress - Status: {status}, Progress: {progress}%...")
        time.sleep(10)

    # Step 5: Verify installation
    LOGGER.info(f"Verifying VM-Series plugin version {plugin_version} is now installed...")
    installed_response = fw.op(cmd="<show><plugins><installed></installed></plugins></show>", cmd_xml=True)
    for entry in installed_response.findall(".//entry"):
        if entry.get("name") == "vm_series":
            installed_version = entry.findtext("version")
            if installed_version == plugin_version:
                LOGGER.info(f"✅ VM-Series plugin version {plugin_version} verified as installed.")
                return
    raise RuntimeError(f"VM-Series plugin version {plugin_version} not found after installation. Please verify manually.")


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


def build_bootstrap_user_data(auth_code: str, pin_id: str, pin_value: str) -> str:
    """Builds the instance metadata user-data string for basic VM-Series bootstrapping."""
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


def private_data_reset_ssh(public_ip: str, ssh_priv_key_path: Path, region: str, instance_id: str):
    """Connects to a firewall via SSH, issues a private-data-reset, and monitors shutdown."""
    ssh = FirewallSSHClient(public_ip, ssh_priv_key_path)
    try:
        ssh.connect()
        LOGGER.info("Sending private-data-reset command to the firewall...")
        ssh.shell.send("request system private-data-reset shutdown\n")
        
        # Wait for the confirmation prompt
        ssh.wait_for_prompt(prompt_chars=['(y or n)'], timeout=30)
        LOGGER.info("Confirmation prompt received. Sending 'y' to confirm.")
        
        # Send 'y' and expect the connection to hang/close
        ssh.shell.send("y\n")
        
        LOGGER.info("Reset command confirmed. The firewall will now shut down. The SSH connection may hang.")
        # We don't wait for a prompt here as the system is going down.

    except Exception as e:
        LOGGER.info(f"SSH session closed as expected after reset command: {e}")
    finally:
        ssh.close()
        
    LOGGER.info(f"Monitoring EC2 instance {instance_id} for 'stopped' state...")
    try:
        ec2_client = boto3.client("ec2", region_name=region)
        waiter = ec2_client.get_waiter('instance_stopped')
        waiter.wait(InstanceIds=[instance_id])
        LOGGER.info(f"✅ Instance {instance_id} has reached the 'stopped' state.")
    except ClientError as e:
        LOGGER.error(f"An error occurred while waiting for the instance to stop: {e}")
        raise

def create_ami_from_instance(region, instance_id, ami_name):
    """
    Creates an AMI from an EC2 instance and waits for it to become available,
    with an extended timeout.
    """
    ec2_client = boto3.client('ec2', region_name=region)

    try:
        print(f"[INFO] Creating AMI '{ami_name}'...")
        # Get the current time for the timestamp tag
        creation_timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        response = ec2_client.create_image(
            InstanceId=instance_id,
            Name=ami_name,
            Description=f"Custom AMI created from instance {instance_id}",
            NoReboot=True,  # Assumes you don't want to reboot if the instance is running
            TagSpecifications=[{
                'ResourceType': 'image',
                'Tags': [
                    {'Key': 'Name', 'Value': ami_name},
                    {'Key': 'CreationTimestamp', 'Value': creation_timestamp},
                    {'Key': 'SourceInstanceId', 'Value': instance_id}
                ]
            }]
        )
        ami_id = response['ImageId']
        print(f"[INFO] AMI creation initiated. New AMI ID: {ami_id}")

        print(f"[INFO] Waiting for AMI {ami_id} to become available...")
        waiter = ec2_client.get_waiter('image_available')

        # This configuration waits for up to 30 minutes.
        waiter.wait(
            ImageIds=[ami_id],
            WaiterConfig={
                'Delay': 30,     # Poll for status every 30 seconds
                'MaxAttempts': 60 # Try a total of 60 times
            }
        )

        print(f"[INFO] Successfully created AMI: {ami_id}")
        return ami_id

    except WaiterError:
        # This error block will now only be hit after 30 minutes of waiting
        print(f"[ERROR] An error occurred while waiting for the AMI to become available: Waiter ImageAvailable failed: Max attempts exceeded", file=sys.stderr)
        print(f"[ERROR] Please check the status of AMI '{ami_id}' in the AWS EC2 Console for failure details.", file=sys.stderr)
        raise # Re-raise the exception to stop the script
    except ClientError as e:
        print(f"[ERROR] An AWS client error occurred: {e}", file=sys.stderr)
        raise
    

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

def destroy_infrastructure(region: str, state: Dict[str, Any]):
    """Tears down all resources based on the state file."""
    ec2_resource = boto3.resource("ec2", region_name=region)
    ec2_client = boto3.client("ec2", region_name=region)
    iam_client = boto3.client("iam", region_name=region)

    prefix = state.get("deployment_prefix", "unknown")
    LOGGER.info(f"💥 Starting teardown for deployment '{prefix}' in {region}...")

    # --- Terminate Instances ---
    if state.get("instance_id"):
        try:
            instance = ec2_resource.Instance(state["instance_id"])
            instance.terminate()
            LOGGER.info(f"Terminating instance: {state['instance_id']}")
            waiter = ec2_client.get_waiter('instance_terminated')
            waiter.wait(InstanceIds=[state["instance_id"]])
            LOGGER.info("✅ Instance terminated.")
        except ClientError as e:
            LOGGER.warning(f"Could not terminate instance (may be already gone): {e}")

    # --- Disassociate and Release EIPs ---
    if state.get("eip_alloc_id"):
        try:
            LOGGER.info(f"Releasing EIP with Allocation ID {state['eip_alloc_id']}...")
            ec2_client.release_address(AllocationId=state['eip_alloc_id'])
            LOGGER.info("✅ EIP released.")
        except ClientError as e:
            LOGGER.warning(f"Could not release EIP (may be already gone): {e}")

    LOGGER.info("Waiting 15 seconds for network resources to update...")
    time.sleep(15)
    
    # --- Detach and Delete ENIs ---
    for eni_key in ["eth0_eni_id", "eth1_eni_id", "eth2_eni_id"]:
        if state.get(eni_key):
            try:
                eni = ec2_resource.NetworkInterface(state[eni_key])
                if eni.attachment: eni.detach(Force=True)
                eni.delete()
                LOGGER.info(f"✅ Deleted ENI: {state[eni_key]}")
            except ClientError as e:
                 LOGGER.warning(f"Could not delete ENI {state[eni_key]} (may be already gone): {e}")

    # --- Detach and Delete Internet Gateways ---
    if state.get("igw_id") and state.get("vpc_id"):
        try:
            igw = ec2_resource.InternetGateway(state["igw_id"])
            vpc = ec2_resource.Vpc(state["vpc_id"])
            igw.detach_from_vpc(VpcId=vpc.id)
            igw.delete()
            LOGGER.info(f"✅ Internet Gateway deleted: {state['igw_id']}")
        except ClientError as e:
            LOGGER.warning(f"Could not delete Internet Gateway: {e}")

    # --- Delete Subnets ---
    for subnet_key in ["public_subnet_id", "private_subnet_id"]:
        if state.get(subnet_key):
            try:
                subnet = ec2_resource.Subnet(state[subnet_key])
                subnet.delete()
                LOGGER.info(f"✅ Subnet deleted: {state[subnet_key]}")
            except ClientError as e:
                LOGGER.warning(f"Could not delete subnet {state[subnet_key]}: {e}")

    # --- Delete Route Tables ---
    if state.get("route_table_id"):
        try:
            rt = ec2_resource.RouteTable(state["route_table_id"])
            rt.delete()
            LOGGER.info(f"✅ Route Table deleted: {state['route_table_id']}")
        except ClientError as e:
            LOGGER.warning(f"Could not delete Route Table: {e}")
            
    # --- Delete Security Groups ---
    if state.get("sg_id"):
        try:
            sg = ec2_resource.SecurityGroup(state["sg_id"])
            sg.delete()
            LOGGER.info(f"✅ Security Group deleted: {state['sg_id']}")
        except ClientError as e:
              LOGGER.warning(f"Could not delete Security Group: {e}")

    # --- Delete IAM Instance Profile, Role, and Policy ---
    if state.get("instance_profile_name") and state.get("role_name"):
        profile_name = state["instance_profile_name"]
        role_name = state["role_name"]
        try:
            LOGGER.info(f"Cleaning up IAM resources ({profile_name}, {role_name})...")
            iam_client.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
            iam_client.delete_instance_profile(InstanceProfileName=profile_name)
            iam_client.delete_role_policy(RoleName=role_name, PolicyName="CloudWatchLogsAccess")
            iam_client.delete_role(RoleName=role_name)
            LOGGER.info("✅ IAM resources deleted.")
        except ClientError as e:
            LOGGER.warning(f"Could not fully clean up IAM resources (may be already gone): {e}")

    # --- Delete Key Pairs ---
    if state.get("key_name"):
        try:
            ec2_client.delete_key_pair(KeyName=state["key_name"])
            LOGGER.info(f"✅ Key Pair deleted: {state['key_name']}")
        except ClientError as e:
            LOGGER.warning(f"Could not delete Key Pair: {e}")

    # --- Delete VPC ---
    if state.get("vpc_id"):
        try:
            vpc = ec2_resource.Vpc(state["vpc_id"])
            vpc.delete()
            LOGGER.info(f"✅ VPC deleted: {state['vpc_id']}")
        except ClientError as e:
            LOGGER.error(f"Failed to delete VPC {state['vpc_id']}: {e}")
            sys.exit(1)
            
    LOGGER.info(f"✅ Teardown complete for deployment '{prefix}'.")


def generate_prefix(length=6):
    """Generates a secure random alphanumeric string for resource naming."""
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_password(length=16):
    """Generates a secure random alphanumeric password."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def get_and_validate_ssh_keys(key_file_arg: str) -> Tuple[Path, Path]:
    # ... (code from previous step)
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

def print_custom_ami_summary(
    ami_id: str,
    ami_name: str,
    region: str,
    prefix: str,
    auth_code: str,
    allowed_ips: List[str],
    ssh_key_file: str,
    auto_destroy: bool,
) -> None:
    """Prints a post-completion summary with next-step suggestions."""
    sep = "=" * 60
    print(f"\n{sep}")
    print(f"  Custom AMI ID:   {ami_id}")
    print(f"  Custom AMI Name: {ami_name}")
    print(f"  Region:          {region}")
    print(sep)

    if not auto_destroy:
        print("\nNext steps:\n")
        print(f"  1. Destroy temporary infrastructure when ready:")
        print(f"     python aws_create_infra.py destroy --deployment-file {prefix}-state.json\n")

    allowed_ips_str = ",".join(allowed_ips) if isinstance(allowed_ips, list) else allowed_ips
    print(f"  2. Deactivate auth code '{auth_code}' in the Palo Alto Networks support portal")
    print(f"     to free the license for future use:")
    print(f"     https://support.paloaltonetworks.com  →  Products → Software NGFW Credits\n")

    print(f"  3. Test the new AMI with a fresh deployment:")
    print(f"     python aws_create_infra.py create \\")
    print(f"         --region {region} \\")
    print(f"         --name-tag \"test-{ami_name}\" \\")
    print(f"         --ami-id {ami_id} \\")
    print(f"         --allowed-ips \"{allowed_ips_str}\" \\")
    print(f"         --ssh-key-file {ssh_key_file}")
    print(f"\n{sep}\n")


# --- CLI Handlers ---

def handle_create(args: argparse.Namespace) -> None:
    """Handler for the 'create' command."""
    if not args.license_type and not args.ami_id:
        LOGGER.error("You must specify either --license-type or --ami-id.")
        sys.exit(1)

    if args.license_type and args.ami_id:
        LOGGER.warning("Both --license-type and --ami-id were specified; --ami-id will take precedence.")
        args.license_type = None
        args.version = None

    ssh_pub_key, ssh_priv_key = get_and_validate_ssh_keys(args.ssh_key_file)
    
    prefix = args.deployment_prefix or generate_prefix()
    state_file = Path(f"{prefix}-state.json")
    if state_file.exists() and not args.deployment_prefix:
         # If we generated a random prefix that happens to exist, generate a new one.
         prefix = generate_prefix()

    if state_file.exists():
        LOGGER.error(f"State file {state_file} already exists for this deployment. Use the 'create-restart' command to resume this deployment.")
        sys.exit(1)

    LOGGER.info(f"Using deployment prefix: {prefix}")
    full_name_tag = f"{prefix}-{args.name_tag}"

    instance_type = args.instance_type
    if args.license_type and args.license_type in ['byol-arm', 'bundle2-arm'] and args.instance_type == 'm5.xlarge':
        instance_type = 'm6g.xlarge'
        LOGGER.info(f"License type '{args.license_type}' selected. Defaulting instance type to '{instance_type}'.")

    user_data_content = None
    bootstrap_params = [getattr(args, 'auth_code', None), getattr(args, 'pin_id', None), getattr(args, 'pin_value', None)]
    if any(bootstrap_params):
        if not all(bootstrap_params):
            LOGGER.error("--auth-code, --pin-id, and --pin-value must all be specified together for bootstrapping.")
            sys.exit(1)
        LOGGER.info("Generating bootstrap user-data from --auth-code, --pin-id, --pin-value.")
        user_data_content = build_bootstrap_user_data(args.auth_code, args.pin_id, args.pin_value)
    elif args.user_data:
        user_data_path = Path(args.user_data).expanduser()
        if user_data_path.is_file():
            LOGGER.info(f"Reading user-data from file: {user_data_path}")
            with user_data_path.open("r") as f:
                user_data_content = f.read()
        else:
            LOGGER.info("Using provided string as user-data.")
            user_data_content = args.user_data
    
    # Store invocation details in the state file
    args_dict = {k: v for k, v in vars(args).items() if k != 'func'}
    args_dict['ssh_key_file'] = str(ssh_pub_key) # Ensure we store the public key path
    if user_data_content:
        args_dict['user_data'] = user_data_content

    state = {
        "deployment_prefix": prefix,
        "region": args.region,
        "invocation_string": ' '.join(sys.argv),
        "invocation_args": args_dict
    }
    save_state(prefix, state)

    try:
        final_state = create_infrastructure(
            region=args.region, name_tag=full_name_tag, prefix=prefix, state=state, license_type=args.license_type,
            version=args.version, instance_type=instance_type, vpc_cidr=args.vpc_cidr,
            public_subnet_cidr=args.public_subnet_cidr, private_subnet_cidr=args.private_subnet_cidr,
            allowed_ips=args.allowed_ips, ssh_pub_key_path=ssh_pub_key, user_data=user_data_content,
            ami_id_override=args.ami_id,
        )
        monitor_and_run_command(final_state["management_public_ip"], ssh_priv_key, final_state["region"], final_state["instance_id"])
        LOGGER.info(f"🎉 Infrastructure '{full_name_tag}' deployed successfully!")
        LOGGER.info(f"To destroy it, run: python aws_create_infra.py destroy --deployment-file {prefix}-state.json")
    except (ClientError, RuntimeError, ValueError) as e:
        LOGGER.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)

def handle_create_restart(args: argparse.Namespace) -> None:
    """Handler for the 'create-restart' command."""
    try:
        state = load_state(args.deployment_file)
        prefix = state.get("deployment_prefix")
        if not prefix:
            raise RuntimeError("State file is invalid and missing a 'deployment_prefix'.")
            
        original_args = state.get("invocation_args")
        if not original_args:
            raise RuntimeError("State file is missing 'invocation_args'. Cannot restart.")

        ssh_key_file_from_cli = args.ssh_key_file
        ssh_key_file_from_state = original_args.get('ssh_key_file')
        
        if not ssh_key_file_from_cli and not ssh_key_file_from_state:
             raise ValueError("SSH key file not specified and not found in state file.")
        
        key_file_to_use = ssh_key_file_from_cli or ssh_key_file_from_state
        ssh_pub_key, ssh_priv_key = get_and_validate_ssh_keys(key_file_to_use)

        full_name_tag = f"{prefix}-{original_args['name_tag']}"
        
        instance_type = original_args.get('instance_type', 'm5.xlarge')
        license_type = original_args.get('license_type')
        if license_type and license_type in ['byol-arm', 'bundle2-arm'] and instance_type == 'm5.xlarge':
            instance_type = 'm6g.xlarge'
        
        user_data_content = original_args.get('user_data')
        ami_id_override = original_args.get('ami_id')

        final_state = create_infrastructure(
            region=state['region'], name_tag=full_name_tag, prefix=prefix, state=state, 
            license_type=license_type,
            version=original_args.get('version'),
            instance_type=instance_type,
            vpc_cidr=original_args['vpc_cidr'],
            public_subnet_cidr=original_args['public_subnet_cidr'],
            private_subnet_cidr=original_args['private_subnet_cidr'],
            allowed_ips=original_args['allowed_ips'],
            ssh_pub_key_path=ssh_pub_key,
            user_data=user_data_content,
            ami_id_override=ami_id_override,
        )
        monitor_and_run_command(final_state["management_public_ip"], ssh_priv_key, final_state["region"], final_state["instance_id"])
        LOGGER.info(f"🎉 Resumed infrastructure '{full_name_tag}' deployed successfully!")
        LOGGER.info(f"To destroy it, run: python aws_create_infra.py destroy --deployment-file {args.deployment_file}")

    except (ClientError, RuntimeError, ValueError, FileNotFoundError) as e:
        LOGGER.error(f"An error occurred during restart: {e}", exc_info=True)
        sys.exit(1)

def handle_destroy(args: argparse.Namespace) -> None:
    """Handler for the 'destroy' command."""
    try:
        state = load_state(args.deployment_file)
        region = state.get('region')
        if not region:
            raise ValueError("Region not found in the state file.")
            
        destroy_infrastructure(region, state)
        # Clean up the state file after successful destruction
        state_file = Path(args.deployment_file)
        if state_file.exists():
            state_file.unlink()
            LOGGER.info(f"✅ Deleted state file: {state_file}")
    except (ClientError, RuntimeError, ValueError, FileNotFoundError) as e:
        LOGGER.error(f"An error occurred during destroy: {e}", exc_info=True)
        sys.exit(1)

def handle_set_admin_password(args: argparse.Namespace) -> None:
    """Handler for the 'set-admin-password' command."""
    try:
        state = load_state(args.deployment_file)
        public_ip = state.get("management_public_ip")
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

    except (ClientError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred while setting the password: {e}", exc_info=True)
        sys.exit(1)

def handle_license_firewall(args: argparse.Namespace) -> None:
    """Handler for the 'license-firewall' command."""
    try:
        state = load_state(args.deployment_file)
        public_ip = state.get("management_public_ip")
        instance_id = state.get("instance_id")
        region = state.get("region")

        if not public_ip or not instance_id or not region:
            raise RuntimeError("State file is missing required information (management_public_ip, instance_id, region).")

        ssh_key_file = args.ssh_key_file or state.get('invocation_args', {}).get('ssh_key_file')
        if not ssh_key_file:
            raise ValueError("SSH key file must be specified or be present in the state file.")
                
        _, ssh_priv_key = get_and_validate_ssh_keys(ssh_key_file)
                
        serial_number = license_firewall(public_ip, ssh_priv_key, args.auth_code, region, instance_id)
        
        if serial_number:
            state.setdefault('actions_performed', []).append({
                'command': 'license-firewall',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'auth_code_used': args.auth_code,
                'serial_number': serial_number
            })
            save_state(state['deployment_prefix'], state)
            LOGGER.info("License action recorded in state file.")

        LOGGER.info("✅ Firewall licensed successfully.")

    except (ClientError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred while licensing the firewall: {e}", exc_info=True)
        sys.exit(1)

def handle_upgrade_content(args: argparse.Namespace) -> None:
    """Handler for the 'upgrade-content' command."""
    try:
        state = load_state(args.deployment_file)
        public_ip = state.get("management_public_ip")
        password = state.get("admin_password")

        if not public_ip:
            raise RuntimeError("Public IP not found in state file.")
        if not password:
            raise RuntimeError("Admin password not found in state file. Please run the 'set-admin-password' command first.")
        
        serial_number = upgrade_content_api(public_ip, password)
        
        if serial_number:
            state.setdefault('actions_performed', []).append({
                'command': 'upgrade-content',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'serial_number': serial_number
            })
            save_state(state['deployment_prefix'], state)
            LOGGER.info("Content upgrade action recorded in state file.")
                    
        LOGGER.info("✅ Content upgrade process completed successfully.")

    except (ClientError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during content upgrade: {e}", exc_info=True)
        sys.exit(1)

def handle_upgrade_panos(args: argparse.Namespace) -> None:
    """Handler for the PAN-OS upgrade command."""
    try:
        state = load_state(args.deployment_file)
        public_ip = state.get("management_public_ip")
        password = state.get("admin_password")
        instance_id = state.get("instance_id")
        region = state.get("region")

        if not public_ip:
            raise RuntimeError("Public IP not found in state file.")
        if not password:
            raise RuntimeError("Admin password not found in state file. Please run the 'set-admin-password' command first.")
        if not instance_id or not region:
            raise RuntimeError("State file is missing required information (instance_id, region).")

        target_version = resolve_panos_version(public_ip, password, args.target_version)
        serial_number = upgrade_panos_api(public_ip, password, target_version, region, instance_id)

        if serial_number:
            state.setdefault('actions_performed', []).append({
                'command': 'upgrade-panos',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'target_version': target_version,
                'serial_number': serial_number
            })
            save_state(state['deployment_prefix'], state)
            LOGGER.info("PAN-OS upgrade action recorded in state file.")
                    
        LOGGER.info("✅ PAN-OS upgrade process completed successfully.")

    except (ClientError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during PAN-OS upgrade: {e}", exc_info=True)
        sys.exit(1)

def handle_private_data_reset(args: argparse.Namespace) -> None:
    """Handler for the 'private-data-reset' command."""
    try:
        state = load_state(args.deployment_file)
        public_ip = state.get("management_public_ip")
        instance_id = state.get("instance_id")
        region = state.get("region")

        if not public_ip or not instance_id or not region:
            raise RuntimeError("State file is missing required information (management_public_ip, instance_id, region).")

        ssh_key_file = args.ssh_key_file or state.get('invocation_args', {}).get('ssh_key_file')
        if not ssh_key_file:
            raise ValueError("SSH key file must be specified or be present in the state file.")

        _, ssh_priv_key = get_and_validate_ssh_keys(ssh_key_file)
        
        private_data_reset_ssh(public_ip, ssh_priv_key, region, instance_id)

    except (ClientError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during private-data-reset: {e}", exc_info=True)
        sys.exit(1)

def handle_upgrade_antivirus(args: argparse.Namespace) -> None:
    """Handler for the 'upgrade-antivirus' command."""
    try:
        state = load_state(args.deployment_file)
        public_ip = state.get("management_public_ip")
        password = state.get("admin_password")

        if not public_ip:
            raise RuntimeError("Public IP not found in state file.")
        if not password:
            raise RuntimeError("Admin password not found in state file. Please run the 'set-admin-password' command first.")
        
        serial_number = upgrade_antivirus_api(public_ip, password)
        
        if serial_number:
            state.setdefault('actions_performed', []).append({
                'command': 'upgrade-antivirus',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'serial_number': serial_number
            })
            save_state(state['deployment_prefix'], state)
            LOGGER.info("Antivirus upgrade action recorded in state file.")
                    
        LOGGER.info("✅ Antivirus upgrade process completed successfully.")

    except (ClientError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during antivirus upgrade: {e}", exc_info=True)
        sys.exit(1)

def handle_upgrade_vmseries_plugin(args: argparse.Namespace) -> None:
    """Handler for the 'upgrade-vmseries-plugin' command."""
    try:
        state = load_state(args.deployment_file)
        public_ip = state.get("management_public_ip")
        password = state.get("admin_password")

        if not public_ip:
            raise RuntimeError("Public IP not found in state file.")
        if not password:
            raise RuntimeError("Admin password not found in state file. Please run the 'set-admin-password' command first.")

        upgrade_vmseries_plugin_api(public_ip, password, args.plugin_version)

        state.setdefault('actions_performed', []).append({
            'command': 'upgrade-vmseries-plugin',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'plugin_version': args.plugin_version
        })
        save_state(state['deployment_prefix'], state)
        LOGGER.info("VM-Series plugin upgrade action recorded in state file.")

        LOGGER.info("✅ VM-Series plugin upgrade process completed successfully.")

    except (ClientError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during VM-Series plugin upgrade: {e}", exc_info=True)
        sys.exit(1)


def handle_create_custom_ami(args: argparse.Namespace) -> None:
    """Handler for the 'create-custom-ami' compound command."""
    if not args.license_type and not getattr(args, 'ami_id', None):
        LOGGER.error("You must specify --license-type.")
        sys.exit(1)

    ssh_pub_key, ssh_priv_key = get_and_validate_ssh_keys(args.ssh_key_file)

    prefix = generate_prefix()
    full_name_tag = f"{prefix}-{args.name_tag}"

    args_dict = {k: v for k, v in vars(args).items() if k != 'func'}
    args_dict['ssh_key_file'] = str(ssh_pub_key)

    state = {
        "deployment_prefix": prefix,
        "region": args.region,
        "invocation_string": ' '.join(sys.argv),
        "invocation_args": args_dict
    }
    save_state(prefix, state)

    try:
        # Step 1: Deploy infrastructure with bootstrap user-data
        LOGGER.info("=== Step 1: Creating infrastructure ===")
        bootstrap_user_data = build_bootstrap_user_data(args.auth_code, args.pin_id, args.pin_value)
        # If --version not specified and --target-upgrade-version is a partial spec (X.Y / X.Y.latest),
        # use the same X.Y as the base AMI version so the latest X.Y.x AMI is selected.
        base_version = getattr(args, 'version', None)
        if not base_version:
            parts = args.target_upgrade_version.split(".")
            if len(parts) == 2 or (len(parts) == 3 and parts[2].lower() == "latest"):
                base_version = f"{parts[0]}.{parts[1]}"
                LOGGER.info(f"No --version specified; deriving base AMI version '{base_version}' from --target-upgrade-version.")
        final_state = create_infrastructure(
            region=args.region, name_tag=full_name_tag, prefix=prefix, state=state,
            license_type=args.license_type, version=base_version,
            instance_type=args.instance_type, vpc_cidr=args.vpc_cidr,
            public_subnet_cidr=args.public_subnet_cidr, private_subnet_cidr=args.private_subnet_cidr,
            allowed_ips=args.allowed_ips, ssh_pub_key_path=ssh_pub_key, user_data=bootstrap_user_data,
            ami_id_override=None,
        )
        monitor_and_run_command(final_state["management_public_ip"], ssh_priv_key, final_state["region"], final_state["instance_id"])
        state = final_state
        public_ip = state["management_public_ip"]
        instance_id = state["instance_id"]
        region = state["region"]
        LOGGER.info("✅ Infrastructure created and chassis is ready.")

        # Step 2: Wait for auto-registration to complete (serial number assigned via bootstrap)
        LOGGER.info("=== Step 2: Waiting for auto-registration and device certificate ===")
        serial_number = wait_for_serial_ssh(public_ip, ssh_priv_key)
        state.setdefault('actions_performed', []).append({
            'command': 'auto-registration',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'serial_number': serial_number
        })
        save_state(prefix, state)
        LOGGER.info("✅ Auto-registration complete. Firewall is licensed with device certificate.")

        # Step 3: Set admin password
        LOGGER.info("=== Step 3: Setting admin password ===")
        new_password = generate_password()
        LOGGER.info(f"Generated new password for admin: {new_password}")
        set_firewall_password(public_ip, ssh_priv_key, new_password)
        state["admin_password"] = new_password
        save_state(prefix, state)
        LOGGER.info("✅ Admin password set and saved.")

        # Resolve target PAN-OS version ('X.Y' / 'X.Y.latest' → 'X.Y.Z')
        target_upgrade_version = resolve_panos_version(public_ip, new_password, args.target_upgrade_version)

        # Step 4: Upgrade content (required before PAN-OS upgrade)
        LOGGER.info("=== Step 4: Upgrading content ===")
        serial_number = upgrade_content_api(public_ip, new_password)
        if serial_number:
            state.setdefault('actions_performed', []).append({
                'command': 'upgrade-content',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'serial_number': serial_number
            })
            save_state(prefix, state)
        LOGGER.info("✅ Content upgrade completed.")

        # Step 5: Upgrade VM-Series plugin (optional)
        if args.plugin_version:
            LOGGER.info(f"=== Step 5: Upgrading VM-Series plugin to {args.plugin_version} ===")
            upgrade_vmseries_plugin_api(public_ip, new_password, args.plugin_version)
            state.setdefault('actions_performed', []).append({
                'command': 'upgrade-vmseries-plugin',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'plugin_version': args.plugin_version
            })
            save_state(prefix, state)
            LOGGER.info("✅ VM-Series plugin upgrade completed.")
        else:
            LOGGER.info("=== Step 5: Skipping VM-Series plugin upgrade (no --plugin-version specified) ===")

        # Step 6: Upgrade PAN-OS
        LOGGER.info(f"=== Step 6: Upgrading PAN-OS to {target_upgrade_version} ===")
        serial_number = upgrade_panos_api(public_ip, new_password, target_upgrade_version, region, instance_id)
        if serial_number:
            state.setdefault('actions_performed', []).append({
                'command': 'upgrade-panos',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'target_version': target_upgrade_version,
                'serial_number': serial_number
            })
            save_state(prefix, state)
        LOGGER.info("✅ PAN-OS upgrade completed.")

        # Step 7: Wait for SSH connectivity post-reboot
        LOGGER.info("=== Step 7: Waiting for SSH connectivity post-reboot ===")
        wait_for_ssh_connectivity(public_ip, ssh_priv_key)
        LOGGER.info("✅ Firewall is reachable via SSH.")

        # Step 8: Private data reset + shutdown
        LOGGER.info("=== Step 8: Performing private-data-reset ===")
        private_data_reset_ssh(public_ip, ssh_priv_key, region, instance_id)
        state.setdefault('actions_performed', []).append({
            'command': 'private-data-reset',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        })
        save_state(prefix, state)
        LOGGER.info("✅ Private data reset complete. Instance is stopped.")

        # Step 9: Create AMI from the stopped instance
        LOGGER.info("=== Step 9: Creating AMI ===")
        license_type = args.license_type or "custom"
        ami_name = f"custom-{license_type}-{target_upgrade_version}-{time.strftime('%Y%m%d%H%M%S')}"
        ami_id = create_ami_from_instance(region, instance_id, ami_name)
        if ami_id:
            ami_info = {
                'ami_id': ami_id,
                'ami_name': ami_name,
                'creation_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            }
            state.setdefault('created_amis', []).append(ami_info)
            save_state(prefix, state)
            LOGGER.info(f"✅ AMI created: {ami_id} ({ami_name})")

        # Step 10: Destroy infrastructure (optional)
        if args.auto_destroy:
            LOGGER.info("=== Step 10: Destroying temporary infrastructure (--auto-destroy) ===")
            destroy_infrastructure(region, state)
            state_file = Path(f"{prefix}-state.json")
            if state_file.exists():
                state_file.unlink()
                LOGGER.info(f"✅ Deleted state file: {state_file}")
        else:
            LOGGER.info("=== Step 10: Skipping infrastructure teardown (no --auto-destroy flag) ===")

        LOGGER.info(f"🎉 create-custom-ami completed successfully! AMI: {ami_id}")
        print_custom_ami_summary(
            ami_id=ami_id, ami_name=ami_name, region=region, prefix=prefix,
            auth_code=args.auth_code, allowed_ips=args.allowed_ips,
            ssh_key_file=str(ssh_pub_key),
            auto_destroy=args.auto_destroy,
        )

    except (ClientError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during create-custom-ami: {e}", exc_info=True)
        sys.exit(1)


def handle_create_custom_ami_restart(args: argparse.Namespace) -> None:
    """Handler for 'create-custom-ami-restart'. Resumes an interrupted create-custom-ami from the state file."""
    try:
        state = load_state(args.deployment_file)
        prefix = state.get("deployment_prefix")
        region = state.get("region")
        instance_id = state.get("instance_id")
        public_ip = state.get("management_public_ip")
        original_args = state.get("invocation_args", {})

        if not instance_id or not region or not prefix:
            raise RuntimeError("State file is missing instance_id, region, or deployment_prefix. Cannot restart.")

        ssh_key_file = args.ssh_key_file or original_args.get("ssh_key_file")
        if not ssh_key_file:
            raise ValueError("SSH key file not found in state or CLI args. Use --ssh-key-file.")
        _, ssh_priv_key = get_and_validate_ssh_keys(ssh_key_file)

        target_upgrade_version = original_args.get("target_upgrade_version")
        plugin_version = original_args.get("plugin_version")
        license_type = original_args.get("license_type", "byol-x86")
        auto_destroy = original_args.get("auto_destroy", False)
        new_password = state.get("admin_password")

        actions_done = {a["command"] for a in state.get("actions_performed", [])}
        ami_id = None
        ami_name = None
        if state.get("created_amis"):
            last = state["created_amis"][-1]
            ami_id = last.get("ami_id")
            ami_name = last.get("ami_name")

        LOGGER.info(f"Resuming create-custom-ami for prefix '{prefix}'. Completed steps: {actions_done or 'none'}")

        # Always wait for SSH before attempting any operation
        if "private-data-reset" not in actions_done:
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
                "serial_number": serial_number
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
                    "serial_number": serial_number
                })
                save_state(prefix, state)
                actions_done.add("upgrade-content")
            LOGGER.info("✅ Content upgrade completed.")

        # Step 5: Plugin (optional)
        if plugin_version and "upgrade-vmseries-plugin" not in actions_done:
            LOGGER.info(f"=== Resuming Step 5: Upgrading VM-Series plugin to {plugin_version} ===")
            upgrade_vmseries_plugin_api(public_ip, new_password, plugin_version)
            state.setdefault("actions_performed", []).append({
                "command": "upgrade-vmseries-plugin",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "plugin_version": plugin_version
            })
            save_state(prefix, state)
            actions_done.add("upgrade-vmseries-plugin")
            LOGGER.info("✅ VM-Series plugin upgrade completed.")

        # Step 6: Upgrade PAN-OS
        if "upgrade-panos" not in actions_done:
            target_upgrade_version = resolve_panos_version(public_ip, new_password, target_upgrade_version)
            LOGGER.info(f"=== Resuming Step 6: Upgrading PAN-OS to {target_upgrade_version} ===")
            serial_number = upgrade_panos_api(public_ip, new_password, target_upgrade_version, region, instance_id)
            if serial_number:
                state.setdefault("actions_performed", []).append({
                    "command": "upgrade-panos",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "target_version": target_upgrade_version,
                    "serial_number": serial_number
                })
                save_state(prefix, state)
                actions_done.add("upgrade-panos")
            LOGGER.info("✅ PAN-OS upgrade completed.")

        # Step 7: Wait for SSH post-reboot (always run if private-data-reset not yet done)
        if "private-data-reset" not in actions_done:
            LOGGER.info("=== Resuming Step 7: Waiting for SSH connectivity post-reboot ===")
            wait_for_ssh_connectivity(public_ip, ssh_priv_key)
            LOGGER.info("✅ Firewall is reachable via SSH.")

            # Step 8: Private data reset + shutdown
            LOGGER.info("=== Resuming Step 8: Performing private-data-reset ===")
            private_data_reset_ssh(public_ip, ssh_priv_key, region, instance_id)
            state.setdefault("actions_performed", []).append({
                "command": "private-data-reset",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            })
            save_state(prefix, state)
            actions_done.add("private-data-reset")
            LOGGER.info("✅ Private data reset complete. Instance is stopped.")

        # Step 9: Create AMI
        if not state.get("created_amis"):
            LOGGER.info("=== Resuming Step 9: Creating AMI ===")
            ami_name = f"custom-{license_type}-{target_upgrade_version}-{time.strftime('%Y%m%d%H%M%S')}"
            ami_id = create_ami_from_instance(region, instance_id, ami_name)
            if ami_id:
                state.setdefault("created_amis", []).append({
                    "ami_id": ami_id,
                    "ami_name": ami_name,
                    "creation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                })
                save_state(prefix, state)
                LOGGER.info(f"✅ AMI created: {ami_id} ({ami_name})")
        else:
            LOGGER.info(f"=== Step 9: AMI already created ({ami_id}), skipping. ===")

        # Step 10: Destroy (optional)
        if auto_destroy:
            LOGGER.info("=== Resuming Step 10: Destroying temporary infrastructure ===")
            destroy_infrastructure(region, state)
            state_file = Path(f"{prefix}-state.json")
            if state_file.exists():
                state_file.unlink()
                LOGGER.info(f"✅ Deleted state file: {state_file}")
        else:
            LOGGER.info("=== Step 10: Skipping infrastructure teardown (no --auto-destroy flag) ===")

        LOGGER.info(f"🎉 create-custom-ami-restart completed successfully! AMI: {ami_id}")
        print_custom_ami_summary(
            ami_id=ami_id, ami_name=ami_name, region=region, prefix=prefix,
            auth_code=original_args.get("auth_code", ""),
            allowed_ips=original_args.get("allowed_ips", []),
            ssh_key_file=original_args.get("ssh_key_file", ""),
            auto_destroy=auto_destroy,
        )

    except (ClientError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during create-custom-ami-restart: {e}", exc_info=True)
        sys.exit(1)


def handle_create_ami(args: argparse.Namespace) -> None:
    """Handler for the 'create-ami' command."""
    try:
        state = load_state(args.deployment_file)
        instance_id = state.get("instance_id")
        region = state.get("region")
        prefix = state.get("deployment_prefix")

        if not instance_id or not region or not prefix:
            raise RuntimeError("State file is missing required information (instance_id, region, or deployment_prefix).")

        ami_name = args.ami_name
        if not ami_name:
            LOGGER.info("AMI name not provided. Constructing name from instance tags and state...")
            license_type = state.get("invocation_args", {}).get("license_type", "unknown")
            version = "unknown"
            
            # Try to get the version from EC2 tags first
            try:
                ec2_client = boto3.client("ec2", region_name=region)
                response = ec2_client.describe_tags(Filters=[{'Name': 'resource-id', 'Values': [instance_id]}])
                for tag in response['Tags']:
                    if tag['Key'] == 'sw-version':
                        version = tag['Value']
                        LOGGER.info(f"Found 'sw-version' tag on instance: {version}")
                        break
            except ClientError as e:
                LOGGER.warning(f"Could not read tags from instance, will fall back to version from state file: {e}")

            if version == "unknown":
                version = state.get("invocation_args", {}).get("version", "unknown")
                LOGGER.info(f"Using version from original creation parameters: {version}")

            ami_name = f"custom-{license_type}-{version}-{time.strftime('%Y%m%d%H%M%S')}"
            LOGGER.info(f"Constructed AMI name: {ami_name}")

        ami_id = create_ami_from_instance(region, instance_id, ami_name)

        # If AMI creation was successful, update and save the state
        if ami_id:
            ami_info = {
                'ami_id': ami_id,
                'ami_name': ami_name,
                'creation_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            }
            state.setdefault('created_amis', []).append(ami_info)
            save_state(prefix, state)
            LOGGER.info(f"✅ AMI information saved to state file: {args.deployment_file}")

    except (ClientError, RuntimeError, ValueError, FileNotFoundError, TimeoutError) as e:
        LOGGER.error(f"An error occurred during AMI creation: {e}", exc_info=True)
        sys.exit(1)

def main() -> None:
    parser = argparse.ArgumentParser(description="AWS Infrastructure CLI for Palo Alto Networks VM-Series", formatter_class=argparse.RawTextHelpFormatter)
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- Create Command ---
    parser_create = subparsers.add_parser("create", help="Create a new VPC and VM-Series instance.")
    parser_create.add_argument("--region", required=True, help="The AWS region to create the infrastructure in.")
    parser_create.add_argument("--name-tag", required=True, help="A base name to tag all created resources (e.g. pa-fw-test).")
    parser_create.add_argument("--deployment-prefix", required=False, help="Optional prefix for all resource names. A 6-char random one is generated if omitted.")
    parser_create.add_argument("--license-type", required=False,
                                default="byol-x86",
                                choices=list(PRODUCT_CODES.keys()),
                                help="VM-Series license type (default: byol-x86). Required if --ami-id is not provided.")
    parser_create.add_argument("--ami-id", required=False, help="A specific AMI ID to use, bypassing license and version lookup.")
    parser_create.add_argument("--version", required=False, help="Optional: Specify a VM-Series version (e.g., '11.0.3').")
    parser_create.add_argument("--ssh-key-file", required=False, default="~/.ssh/id_rsa.pub", metavar="PATH", help="Path to your SSH public or private key file (default: ~/.ssh/id_rsa.pub).")
    parser_create.add_argument("--allowed-ips", required=True, type=lambda s: [item.strip() for item in s.split(',')], help="Comma-separated string of IPv4 CIDR blocks for SSH access.")
    parser_create.add_argument("--user-data", required=False, help="Path to a user-data file or a raw string to be passed to the instance.")
    parser_create.add_argument("--auth-code", required=False, help="BYOL auth code for basic bootstrapping (requires --pin-id and --pin-value).")
    parser_create.add_argument("--pin-id", required=False, help="VM-Series auto-registration PIN ID for basic bootstrapping.")
    parser_create.add_argument("--pin-value", required=False, help="VM-Series auto-registration PIN value for basic bootstrapping.")
    parser_create.add_argument("--instance-type", default="m5.xlarge", help="EC2 instance type (default: m5.xlarge).")
    parser_create.add_argument("--vpc-cidr", default="10.0.0.0/16", help="CIDR block for the VPC (default: 10.0.0.0/16).")
    parser_create.add_argument("--public-subnet-cidr", default="10.0.1.0/24", help="CIDR for the public subnet (default: 10.0.1.0/24).")
    parser_create.add_argument("--private-subnet-cidr", default="10.0.2.0/24", help="CIDR for the private subnet (default: 10.0.2.0/24).")
    parser_create.set_defaults(func=handle_create)

    # --- Destroy Command ---
    parser_destroy = subparsers.add_parser("destroy", help="Destroy an existing deployment using its state file.")
    parser_destroy.add_argument("--deployment-file", required=True, help="Path to the deployment state file (e.g., 'abc123-state.json').")
    parser_destroy.set_defaults(func=handle_destroy)

    # --- Create Restart Command ---
    parser_restart = subparsers.add_parser("create-restart", help="Resume an interrupted deployment using its state file.")
    parser_restart.add_argument("--deployment-file", required=True, help="Path to the deployment state file to resume.")
    parser_restart.add_argument("--ssh-key-file", required=False, metavar="PATH", help="Path to the SSH key file. If omitted, uses the path from the state file.")
    parser_restart.set_defaults(func=handle_create_restart)

    # --- Set Admin Password Command ---
    parser_set_password = subparsers.add_parser("set-admin-password", help="Set a new random password for the admin user on a deployment.")
    parser_set_password.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_set_password.add_argument("--ssh-key-file", required=False, metavar="PATH", help="Path to the SSH key file. If omitted, uses the path from the state file.")
    parser_set_password.set_defaults(func=handle_set_admin_password)

    # --- License Firewall Command ---
    parser_license = subparsers.add_parser("license-firewall", help="License a BYOL firewall deployment.")
    parser_license.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_license.add_argument("--ssh-key-file", required=False, metavar="PATH", help="Path to the SSH key file. If omitted, uses the path from the state file.")
    parser_license.add_argument("--auth-code", required=True, help="The auth code for licensing.")
    parser_license.set_defaults(func=handle_license_firewall)

    # --- Upgrade Content Command ---
    parser_upgrade_content = subparsers.add_parser("upgrade-content", help="Download and install the latest content on a licensed firewall.")
    parser_upgrade_content.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_upgrade_content.set_defaults(func=handle_upgrade_content)

    # --- Upgrade PAN-OS Command ---
    parser_upgrade_panos = subparsers.add_parser("upgrade-panos", help="Upgrade the PAN-OS software on a firewall.")
    parser_upgrade_panos.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_upgrade_panos.add_argument("--target-version", required=True, help="The target PAN-OS version (e.g., '10.2.5').")
    parser_upgrade_panos.set_defaults(func=handle_upgrade_panos)

    # --- Private Data Reset Command ---
    parser_reset = subparsers.add_parser("private-data-reset", help="Factory reset a firewall and shut it down.")
    parser_reset.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_reset.add_argument("--ssh-key-file", required=False, metavar="PATH", help="Path to the SSH key file. If omitted, uses the path from the state file.")
    parser_reset.set_defaults(func=handle_private_data_reset)
    
    # --- Upgrade Antivirus Command ---
    parser_upgrade_antivirus = subparsers.add_parser("upgrade-antivirus", help="Download and install the latest antivirus update.")
    parser_upgrade_antivirus.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_upgrade_antivirus.set_defaults(func=handle_upgrade_antivirus)

    # --- Create AMI Command ---
    parser_create_ami = subparsers.add_parser("create-ami", help="Create an AMI from an existing deployment.")
    parser_create_ami.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_create_ami.add_argument("--ami-name", required=False, help="Optional: A name for the new AMI. If omitted, a name will be generated.")
    parser_create_ami.set_defaults(func=handle_create_ami)

    # --- Upgrade VM-Series Plugin Command ---
    parser_upgrade_plugin = subparsers.add_parser("upgrade-vmseries-plugin", help="Download and install a specific VM-Series plugin version.")
    parser_upgrade_plugin.add_argument("--deployment-file", required=True, help="Path to the deployment state file.")
    parser_upgrade_plugin.add_argument("--plugin-version", required=True, help="The VM-Series plugin version to install (e.g., '1.0.15').")
    parser_upgrade_plugin.set_defaults(func=handle_upgrade_vmseries_plugin)

    # --- Create Custom AMI Command ---
    parser_create_custom_ami = subparsers.add_parser("create-custom-ami", help="Compound command: deploy, license, upgrade, reset, and snapshot into a custom AMI.")
    parser_create_custom_ami.add_argument("--region", required=True, help="The AWS region to create the infrastructure in.")
    parser_create_custom_ami.add_argument("--name-tag", required=True, help="A base name to tag all created resources.")
    parser_create_custom_ami.add_argument("--license-type", required=False,
                                          default="byol-x86",
                                          choices=list(PRODUCT_CODES.keys()),
                                          help="VM-Series license type (default: byol-x86).")
    parser_create_custom_ami.add_argument("--version", required=False, help="Optional: Base AMI version to start from (e.g., '11.0.3').")
    parser_create_custom_ami.add_argument("--ssh-key-file", required=False, default="~/.ssh/id_rsa.pub", metavar="PATH", help="Path to your SSH public or private key file (default: ~/.ssh/id_rsa.pub).")
    parser_create_custom_ami.add_argument("--allowed-ips", required=True, type=lambda s: [item.strip() for item in s.split(',')], help="Comma-separated string of IPv4 CIDR blocks for SSH access.")
    parser_create_custom_ami.add_argument("--instance-type", default="m5.xlarge", help="EC2 instance type (default: m5.xlarge).")
    parser_create_custom_ami.add_argument("--vpc-cidr", default="10.0.0.0/16", help="CIDR block for the VPC (default: 10.0.0.0/16).")
    parser_create_custom_ami.add_argument("--public-subnet-cidr", default="10.0.1.0/24", help="CIDR for the public subnet (default: 10.0.1.0/24).")
    parser_create_custom_ami.add_argument("--private-subnet-cidr", default="10.0.2.0/24", help="CIDR for the private subnet (default: 10.0.2.0/24).")
    parser_create_custom_ami.add_argument("--auth-code", required=True, help="BYOL auth code for bootstrap auto-registration.")
    parser_create_custom_ami.add_argument("--pin-id", required=True, help="VM-Series auto-registration PIN ID.")
    parser_create_custom_ami.add_argument("--pin-value", required=True, help="VM-Series auto-registration PIN value.")
    parser_create_custom_ami.add_argument("--target-upgrade-version", required=True, help="The target PAN-OS version to upgrade to (e.g., '11.1.2').")
    parser_create_custom_ami.add_argument("--plugin-version", required=False, help="Optional: VM-Series plugin version to install (e.g., '1.0.15').")
    parser_create_custom_ami.add_argument("--auto-destroy", action="store_true", default=False, help="Automatically destroy the temporary infrastructure after AMI creation.")
    parser_create_custom_ami.set_defaults(func=handle_create_custom_ami)

    # --- Create Custom AMI Restart Command ---
    parser_cca_restart = subparsers.add_parser("create-custom-ami-restart", help="Resume an interrupted create-custom-ami using its state file.")
    parser_cca_restart.add_argument("--deployment-file", required=True, help="Path to the state file from the interrupted create-custom-ami run.")
    parser_cca_restart.add_argument("--ssh-key-file", required=False, metavar="PATH", help="Path to SSH key file. If omitted, uses the path from the state file.")
    parser_cca_restart.set_defaults(func=handle_create_custom_ami_restart)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
