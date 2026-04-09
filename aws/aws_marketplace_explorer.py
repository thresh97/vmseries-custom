#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AWS Marketplace Explorer for Palo Alto Networks VM-Series 🕵️

An interactive CLI tool to discover available VM-Series firewall AMIs or find
the product code for a specific AMI.

This script provides four commands:
  1. `list-versions`: Interactively guides the user to select a region and
     license type, then displays available PAN-OS versions. Can also accept
     a product code directly.
  2. `find-product-code`: Takes an AMI ID and region as input and returns the
     associated AWS Marketplace product code.
  3. `find-regional-inconsistencies`: Scans all AWS regions for a given
     product code and reports which AMI versions are missing from which regions.
  4. `allow-launch`: Checks if a specific instance type is compatible with a
     given product code in a region.

Prerequisites:
  - Python 3.7+
  - An AWS account with credentials configured.
  - Required Python packages: `boto3`, `pyyaml`
    (install with: pip install -r requirements.txt)

Example Usage:
  # List available versions interactively
  python aws_marketplace_explorer.py list-versions --region us-west-2

  # Check if an instance type is compatible with a product
  python aws_marketplace_explorer.py allow-launch --region us-west-2 \
    --product-code 6njl1pau431dv1qxipg63mvah --instance-type m5.xlarge
"""

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Dict, Set

import boto3
import yaml
from botocore.exceptions import NoCredentialsError, ClientError

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOGGER = logging.getLogger(__name__)


def load_product_codes() -> Dict[str, str]:
    """Loads product codes from the external YAML file."""
    config_file = Path("product_codes.yaml")
    if not config_file.is_file():
        LOGGER.error(f"Configuration file '{config_file}' not found in the current directory.")
        sys.exit(1)
    with config_file.open("r") as f:
        return yaml.safe_load(f)

PRODUCT_CODES = load_product_codes()


def validate_aws_credentials():
    """Checks for AWS credentials and prints the identity."""
    LOGGER.info("Step 1: Validating AWS credentials...")
    try:
        sts_client = boto3.client("sts")
        identity = sts_client.get_caller_identity()
        LOGGER.info(f"✅ Credentials validated for ARN: {identity['Arn']}")
    except NoCredentialsError:
        LOGGER.error("❌ AWS credentials not found.")
        LOGGER.error("Please configure your credentials (e.g., run 'aws configure').")
        sys.exit(1)
    except ClientError as e:
        LOGGER.error(f"❌ An AWS API error occurred: {e}")
        sys.exit(1)


def select_vm_series_type() -> str:
    """Prompts the user to select a VM-Series license type."""
    LOGGER.info("\nStep 2: Select a VM-Series License Type...")
    license_types = list(PRODUCT_CODES.keys())

    for i, license_type in enumerate(license_types):
        print(f"  {i+1:2d}) {license_type}")

    while True:
        try:
            choice = int(input("Enter the number for your desired license type: "))
            if 1 <= choice <= len(license_types):
                selected_type = license_types[choice - 1]
                LOGGER.info(f"✅ License type selected: {selected_type}")
                return selected_type
            else:
                print("Invalid number. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def get_license_type_from_product_code(product_code: str) -> str | None:
    """Finds the license type name for a given product code."""
    for license_type, code in PRODUCT_CODES.items():
        if code == product_code:
            return license_type
    return None

def get_versions_for_region(region: str, product_code: str) -> Set[str]:
    """Queries and returns a set of available AMI versions for a region and product."""
    versions = set()
    ec2_client = boto3.client("ec2", region_name=region)
    try:
        paginator = ec2_client.get_paginator('describe_images')
        pages = paginator.paginate(
            Owners=["aws-marketplace"],
            Filters=[
                {"Name": "product-code", "Values": [product_code]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "name", "Values": ["*PA-*-AWS*"]},
            ],
        )
        for page in pages:
            for image in page.get('Images', []):
                name = image.get("Name", "N/A")
                version_match = re.search(r'(\d{1,2}\.\d{1,2}\.\d{1,2}(?:-h\d+)?)', name)
                if version_match:
                    versions.add(version_match.group(1))
    except ClientError as e:
        if e.response['Error']['Code'] == 'AuthFailure':
            LOGGER.debug(f"Skipping region {region} due to authorization failure (region may not be enabled).")
        else:
            LOGGER.warning(f"Could not query region {region}: {e}")
    return versions

def get_latest_ami_for_product(region: str, product_code: str) -> str | None:
    """Finds the most recent AMI ID for a given product code."""
    ec2_client = boto3.client("ec2", region_name=region)
    try:
        paginator = ec2_client.get_paginator('describe_images')
        pages = paginator.paginate(
            Owners=["aws-marketplace"],
            Filters=[
                {"Name": "product-code", "Values": [product_code]},
                {"Name": "state", "Values": ["available"]},
            ],
        )
        all_images = [image for page in pages for image in page.get('Images', [])]
        if not all_images:
            return None
        
        sorted_images = sorted(all_images, key=lambda x: x["CreationDate"], reverse=True)
        return sorted_images[0]['ImageId']

    except ClientError as e:
        LOGGER.error(f"Could not query for latest AMI: {e}")
        return None

def display_ami_versions(region: str, license_type: str):
    """Queries and displays available AMIs for the selected region and license."""
    LOGGER.info(f"\nFinding available versions for '{license_type}' in '{region}'...")
    product_code = PRODUCT_CODES[license_type]
    ec2_client = boto3.client("ec2", region_name=region)

    try:
        paginator = ec2_client.get_paginator('describe_images')
        pages = paginator.paginate(
            Owners=["aws-marketplace"],
            Filters=[
                {"Name": "product-code", "Values": [product_code]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "name", "Values": ["*PA-*-AWS*"]},
            ],
        )
        
        all_images = []
        for page in pages:
            all_images.extend(page['Images'])

        if not all_images:
            LOGGER.warning("No AMIs found for this selection.")
            LOGGER.warning("Please ensure you are subscribed to this product in the AWS Marketplace for this region.")
            return

        def version_sort_key(image):
            name = image.get("Name", "")
            m = re.search(r'(\d{1,2})\.(\d{1,2})\.(\d{1,2})(?:-h(\d+))?', name)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0))
            return (0, 0, 0, 0)

        sorted_images = sorted(all_images, key=version_sort_key, reverse=True)

        print("\n" + "="*80)
        print(f"{'Version':<25} {'AMI ID':<25} {'Creation Date':<30}")
        print("-"*80)

        for image in sorted_images:
            name = image.get("Name", "N/A")
            version_match = re.search(r'(\d{1,2}\.\d{1,2}\.\d{1,2}(?:-h\d+)?)', name)
            version = version_match.group(1) if version_match else "N/A"

            print(f"{version:<25} {image['ImageId']:<25} {image['CreationDate']:<30}")

        print("="*80 + "\n")
        LOGGER.info(f"✅ Found {len(sorted_images)} available versions.")

    except ClientError as e:
        LOGGER.error(f"❌ An error occurred while searching for AMIs: {e}")
        sys.exit(1)

def find_product_code_by_ami(region: str, ami_id: str):
    """Queries for an AMI ID and displays its associated product codes."""
    LOGGER.info(f"Searching for product code for AMI ID '{ami_id}' in region '{region}'...")
    ec2_client = boto3.client("ec2", region_name=region)

    try:
        response = ec2_client.describe_images(ImageIds=[ami_id])

        if not response.get("Images"):
            LOGGER.error(f"❌ AMI ID '{ami_id}' not found in region '{region}'.")
            return

        image = response["Images"][0]
        product_codes = [pc['ProductCodeId'] for pc in image.get("ProductCodes", [])]

        if not product_codes:
            LOGGER.warning(f"AMI ID '{ami_id}' does not have any associated product codes.")
            return
            
        print("\n" + "="*50)
        print(f"Product Code(s) for AMI {ami_id}:")
        for pc in product_codes:
            license_type = get_license_type_from_product_code(pc)
            label = f"  ({license_type})" if license_type else "  (unknown license type)"
            print(f"  - {pc}{label}")
        print("="*50 + "\n")
        LOGGER.info("✅ Search complete.")

    except ClientError as e:
        if "InvalidAMIID.NotFound" in str(e):
             LOGGER.error(f"❌ AMI ID '{ami_id}' not found in region '{region}'.")
        else:
            LOGGER.error(f"❌ An AWS API error occurred: {e}")
        sys.exit(1)

def find_regional_inconsistencies(start_region: str, product_code: str):
    """Scans all regions for a product code and reports version inconsistencies."""
    LOGGER.info(f"Starting scan for product code {product_code} across all AWS regions...")
    ec2_client = boto3.client("ec2", region_name=start_region)
    all_regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    
    regional_versions = {}
    master_version_set = set()

    for region in all_regions:
        LOGGER.info(f"Scanning region: {region}...")
        versions = get_versions_for_region(region, product_code)
        regional_versions[region] = versions
        master_version_set.update(versions)

    LOGGER.info("Scan complete. Analyzing results...")
    
    inconsistencies_found = False
    sorted_master_list = sorted(list(master_version_set), reverse=True)

    print("\n" + "="*80)
    print(f"Regional Inconsistency Report for Product Code: {product_code}")
    print("="*80)

    for version in sorted_master_list:
        missing_in_regions = []
        for region, versions in regional_versions.items():
            if version not in versions:
                missing_in_regions.append(region)
        
        if missing_in_regions:
            inconsistencies_found = True
            print(f"\nVersion '{version}' is MISSING in the following regions:")
            # Print in columns for readability
            for i in range(0, len(missing_in_regions), 4):
                 print("    " + "    ".join(f"{r:<15}" for r in missing_in_regions[i:i+4]))

    if not inconsistencies_found:
        print("\n✅ No regional inconsistencies found. All regions are synchronized.")
    
    print("\n" + "="*80)


def check_instance_type_compatibility(region: str, product_code: str, instance_type: str):
    """Uses a DryRun to check if an instance type is compatible with a product AMI."""
    LOGGER.info(f"Checking compatibility of instance type '{instance_type}' with product '{product_code}' in {region}...")
    ec2_client = boto3.client("ec2", region_name=region)
    ec2_resource = boto3.resource("ec2", region_name=region)
    
    vpc = None
    subnet = None
    try:
        # Create temporary network resources for the dry run
        LOGGER.info("Creating temporary VPC and Subnet for validation...")
        vpc = ec2_resource.create_vpc(CidrBlock='10.255.0.0/28', TagSpecifications=[{'ResourceType': 'vpc', 'Tags': [{'Key': 'Name', 'Value': 'temp-validation-vpc'}]}])
        vpc.wait_until_available()
        subnet = vpc.create_subnet(CidrBlock='10.255.0.0/28', TagSpecifications=[{'ResourceType': 'subnet', 'Tags': [{'Key': 'Name', 'Value': 'temp-validation-subnet'}]}])
        
        ami_id = get_latest_ami_for_product(region, product_code)
        if not ami_id:
             LOGGER.error(f"Could not retrieve a valid AMI ID for product '{product_code}' in region '{region}'. Cannot check compatibility.")
             return

        LOGGER.info(f"Found latest AMI {ami_id} for compatibility check.")
        ec2_client.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            SubnetId=subnet.id,
            MinCount=1,
            MaxCount=1,
            DryRun=True
        )
    except ClientError as e:
        if 'DryRunOperation' in str(e):
            LOGGER.info(f"✅ SUCCESS: Instance type '{instance_type}' is compatible with product code '{product_code}' in {region}.")
        elif 'Unsupported' in str(e) or 'InvalidParameterValue' in str(e):
            LOGGER.error(f"❌ FAILURE: Instance type '{instance_type}' is NOT compatible with product code '{product_code}' in {region}.")
            LOGGER.error(f"   Reason: {e}")
        else:
            LOGGER.error(f"An unexpected AWS API error occurred: {e}")
    except Exception as e:
        LOGGER.error(f"An unexpected error occurred: {e}")
    finally:
        # Ensure temporary resources are always cleaned up
        if subnet:
            subnet.delete()
        if vpc:
            vpc.delete()
        LOGGER.info("✅ Temporary validation resources have been deleted.")


def handle_list_versions(args):
    """Handler for the list-versions command."""
    print("--- Palo Alto Networks VM-Series AMI Explorer ---")
    validate_aws_credentials()

    if args.product_code:
        LOGGER.info(f"Using provided product code: {args.product_code}")
        selected_license = get_license_type_from_product_code(args.product_code)
        if not selected_license:
            LOGGER.error(f"Product code '{args.product_code}' does not match any known license types.")
            sys.exit(1)
        LOGGER.info(f"Matching license type is '{selected_license}'")
    elif args.license_type:
        if args.license_type not in PRODUCT_CODES:
            LOGGER.error(f"Unknown license type '{args.license_type}'. Valid choices: {', '.join(PRODUCT_CODES.keys())}")
            sys.exit(1)
        selected_license = args.license_type
    else:
        selected_license = select_vm_series_type()

    display_ami_versions(args.region, selected_license)
    print("--- Explorer finished ---")

def handle_find_product_code(args):
    """Handler for the find-product-code command."""
    print("--- Palo Alto Networks Product Code Finder ---")
    validate_aws_credentials()
    find_product_code_by_ami(args.region, args.ami_id)
    print("--- Finder finished ---")

def handle_find_regional_inconsistencies(args):
    """Handler for the find-regional-inconsistencies command."""
    print("--- Palo Alto Networks Regional Inconsistency Finder ---")
    validate_aws_credentials()
    find_regional_inconsistencies(args.region, args.product_code)
    print("--- Finder finished ---")

def handle_allow_launch(args):
    """Handler for the allow-launch command."""
    print("--- Palo Alto Networks Instance Type Compatibility Checker ---")
    validate_aws_credentials()
    check_instance_type_compatibility(args.region, args.product_code, args.instance_type)
    print("--- Checker finished ---")


def main():
    """Main function to run the explorer."""
    parser = argparse.ArgumentParser(description="AWS Marketplace Explorer for Palo Alto Networks VM-Series")
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Subparser for listing versions
    parser_list = subparsers.add_parser("list-versions", help="List available VM-Series versions by license type or product code.")
    parser_list.add_argument("--region", default="us-east-1", help="The AWS region to search in (default: us-east-1).")
    parser_list.add_argument("--license-type", help=f"License type to list versions for. Choices: {', '.join(PRODUCT_CODES.keys())}. If omitted, an interactive menu is shown.")
    parser_list.add_argument("--product-code", help="Directly specify a product code, skipping license type selection.")
    parser_list.set_defaults(func=handle_list_versions)

    # Subparser for finding a product code by AMI ID
    parser_find = subparsers.add_parser("find-product-code", help="Find the product code for a specific AMI ID.")
    parser_find.add_argument("--region", required=True, help="The AWS region where the AMI exists.")
    parser_find.add_argument("--ami-id", required=True, help="The AMI ID to look up.")
    parser_find.set_defaults(func=handle_find_product_code)
    
    # Subparser for finding regional inconsistencies
    parser_find_inconsistencies = subparsers.add_parser("find-regional-inconsistencies", help="Find AMI version inconsistencies across all AWS regions.")
    parser_find_inconsistencies.add_argument("--region", default="us-east-1", help="The AWS region to start the scan from (default: us-east-1).")
    parser_find_inconsistencies.add_argument("--product-code", required=True, help="The product code to scan for.")
    parser_find_inconsistencies.set_defaults(func=handle_find_regional_inconsistencies)

    # Subparser for checking instance type launch compatibility
    parser_allow_launch = subparsers.add_parser("allow-launch", help="Check if an instance type can be launched with a product code.")
    parser_allow_launch.add_argument("--region", default="us-east-1", help="The AWS region to check in (default: us-east-1).")
    parser_allow_launch.add_argument("--product-code", required=True, help="The product code for the AMI.")
    parser_allow_launch.add_argument("--instance-type", required=True, help="The instance type to check (e.g., m5.xlarge).")
    parser_allow_launch.set_defaults(func=handle_allow_launch)
    
    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

