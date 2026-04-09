#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Azure Marketplace Explorer for Palo Alto Networks VM-Series

An interactive CLI tool to discover available VM-Series versions in the Azure
Marketplace, and to find regional availability inconsistencies.

This script provides two commands:
  1. `list-versions`: Lists available VM-Series versions for a region and
     license type, sorted by version number (newest first).
  2. `find-regional-inconsistencies`: Scans Azure regions for version
     availability gaps across a given SKU.

Background: Azure Marketplace Lag
-----------------------------------
PAN does not publish every PAN-OS version to the Azure Marketplace immediately
after release. Use this tool to discover what is currently available so you can
plan your base image version for `create-custom-image`.

Prerequisites:
  - Python 3.12+
  - Azure credentials configured (run 'az login')
  - Required Python packages (see requirements.txt)

Example Usage:
  # List available versions interactively
  python azure_marketplace_explorer.py list-versions --region eastus

  # List non-interactively for a specific license type
  python azure_marketplace_explorer.py list-versions --region eastus --license-type byol

  # Find which versions are missing from some regions
  python azure_marketplace_explorer.py find-regional-inconsistencies --license-type byol
"""

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.subscription import SubscriptionClient
    from azure.core.exceptions import AzureError
except ImportError as e:
    print(f"Azure SDK libraries not found: {e}", file=sys.stderr)
    print("Please install dependencies: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOGGER = logging.getLogger(__name__)

# Azure regions to scan when finding regional inconsistencies
# A curated list of commonly used regions; expand as needed.
AZURE_REGIONS = [
    "eastus", "eastus2", "westus", "westus2", "westus3",
    "centralus", "northcentralus", "southcentralus",
    "westeurope", "northeurope", "uksouth", "ukwest",
    "germanywestcentral", "switzerlandnorth",
    "australiaeast", "australiasoutheast",
    "southeastasia", "eastasia",
    "japaneast", "japanwest",
    "canadacentral", "canadaeast",
    "brazilsouth",
    "southindia", "centralindia",
    "uaenorth",
]


def load_marketplace_skus() -> Dict[str, str]:
    """Loads marketplace SKU mappings from the external YAML file."""
    config_file = Path("marketplace_skus.yaml")
    if not config_file.is_file():
        LOGGER.error(f"Configuration file '{config_file}' not found in the current directory.")
        sys.exit(1)
    with config_file.open("r") as f:
        return yaml.safe_load(f)

MARKETPLACE_SKUS = load_marketplace_skus()


def get_subscription_id(credential) -> str:
    """Returns the first available subscription ID from the current az login context."""
    sub_client = SubscriptionClient(credential)
    subs = list(sub_client.subscriptions.list())
    if not subs:
        LOGGER.error("No Azure subscriptions found. Please run 'az login'.")
        sys.exit(1)
    return subs[0].subscription_id


def select_license_type() -> str:
    """Prompts the user to select a VM-Series license type interactively."""
    LOGGER.info("\nSelect a VM-Series License Type...")
    license_types = list(MARKETPLACE_SKUS.keys())

    for i, lt in enumerate(license_types):
        print(f"  {i+1:2d}) {lt}  (SKU: {MARKETPLACE_SKUS[lt]})")

    while True:
        try:
            choice = int(input("Enter the number for your desired license type: "))
            if 1 <= choice <= len(license_types):
                selected = license_types[choice - 1]
                LOGGER.info(f"✅ License type selected: {selected}")
                return selected
            print("Invalid number. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")


def _version_sort_key(version_str: str) -> List[int]:
    """Returns a sortable key for a PAN-OS version string like '11.1.3' or '10.2.7'."""
    result = []
    for part in re.split(r'[.\-]', version_str):
        try:
            result.append(int(part))
        except ValueError:
            result.append(0)
    return result


def get_versions_for_region(
    compute_client: ComputeManagementClient,
    region: str,
    sku: str,
) -> Set[str]:
    """Returns the set of available VM-Series version strings for a region and SKU."""
    versions = set()
    try:
        images = compute_client.virtual_machine_images.list(
            location=region,
            publisher_name="paloaltonetworks",
            offer="vmseries-flex",
            skus=sku,
        )
        for img in images:
            versions.add(img.name)
    except AzureError as e:
        LOGGER.debug(f"Could not query region '{region}': {e}")
    return versions


def display_versions(region: str, license_type: str, compute_client: ComputeManagementClient) -> None:
    """Queries and displays available VM-Series versions for a region and license type."""
    sku = MARKETPLACE_SKUS[license_type]
    LOGGER.info(f"Finding available versions for SKU '{sku}' in '{region}'...")

    try:
        images = list(compute_client.virtual_machine_images.list(
            location=region,
            publisher_name="paloaltonetworks",
            offer="vmseries-flex",
            skus=sku,
        ))
    except AzureError as e:
        LOGGER.error(f"Failed to query Marketplace: {e}")
        sys.exit(1)

    if not images:
        LOGGER.warning(f"No VM-Series images found for SKU '{sku}' in '{region}'.")
        LOGGER.warning("Ensure your subscription has accepted the Marketplace terms for this product.")
        return

    sorted_images = sorted(images, key=lambda img: _version_sort_key(img.name), reverse=True)

    print("\n" + "="*70)
    print(f"  VM-Series Marketplace versions — SKU: {sku}  |  Region: {region}")
    print(f"  Publisher: paloaltonetworks  |  Offer: vmseries-flex")
    print("="*70)
    print(f"{'Version':<30}")
    print("-"*70)

    for img in sorted_images:
        print(f"{img.name:<30}")

    print("="*70)
    print(f"  Total: {len(sorted_images)} versions available\n")
    LOGGER.info(f"✅ Found {len(sorted_images)} available versions.")


def find_regional_inconsistencies(license_type: str, credential, subscription_id: str) -> None:
    """Scans all regions and reports which versions are missing from which regions."""
    sku = MARKETPLACE_SKUS[license_type]
    compute_client = ComputeManagementClient(credential, subscription_id)

    LOGGER.info(f"Scanning {len(AZURE_REGIONS)} Azure regions for SKU '{sku}'...")
    regional_versions: Dict[str, Set[str]] = {}
    master_version_set: Set[str] = set()

    for region in AZURE_REGIONS:
        LOGGER.info(f"  Scanning: {region}...")
        versions = get_versions_for_region(compute_client, region, sku)
        regional_versions[region] = versions
        master_version_set.update(versions)

    LOGGER.info("Scan complete. Analyzing results...")

    if not master_version_set:
        LOGGER.warning("No versions found across any region. Check your subscription and Marketplace terms acceptance.")
        return

    sorted_master = sorted(master_version_set, key=_version_sort_key, reverse=True)
    inconsistencies_found = False

    print("\n" + "="*80)
    print(f"  Regional Inconsistency Report — SKU: {sku}  |  License: {license_type}")
    print("="*80)

    for version in sorted_master:
        missing = [r for r, vs in regional_versions.items() if version not in vs]
        if missing:
            inconsistencies_found = True
            print(f"\nVersion '{version}' is MISSING in:")
            for i in range(0, len(missing), 4):
                print("    " + "    ".join(f"{r:<20}" for r in missing[i:i+4]))

    if not inconsistencies_found:
        print("\n✅ No regional inconsistencies found. All regions are synchronized.")

    print("\n" + "="*80 + "\n")


# --- CLI Handlers ---

def handle_list_versions(args: argparse.Namespace) -> None:
    """Handler for the list-versions command."""
    print("--- Palo Alto Networks VM-Series Azure Marketplace Explorer ---")

    if args.license_type:
        if args.license_type not in MARKETPLACE_SKUS:
            LOGGER.error(f"Unknown license type '{args.license_type}'. Valid choices: {', '.join(MARKETPLACE_SKUS.keys())}")
            sys.exit(1)
        selected_license = args.license_type
    else:
        selected_license = select_license_type()

    credential = DefaultAzureCredential()
    subscription_id = get_subscription_id(credential)
    compute_client = ComputeManagementClient(credential, subscription_id)

    display_versions(args.region, selected_license, compute_client)
    print("--- Explorer finished ---")


def handle_find_regional_inconsistencies(args: argparse.Namespace) -> None:
    """Handler for the find-regional-inconsistencies command."""
    print("--- Palo Alto Networks VM-Series Regional Inconsistency Finder ---")

    if args.license_type not in MARKETPLACE_SKUS:
        LOGGER.error(f"Unknown license type '{args.license_type}'. Valid choices: {', '.join(MARKETPLACE_SKUS.keys())}")
        sys.exit(1)

    credential = DefaultAzureCredential()
    subscription_id = get_subscription_id(credential)

    find_regional_inconsistencies(args.license_type, credential, subscription_id)
    print("--- Finder finished ---")


def main() -> None:
    """Main function to run the explorer."""
    parser = argparse.ArgumentParser(
        description="Azure Marketplace Explorer for Palo Alto Networks VM-Series"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- list-versions ---
    parser_list = subparsers.add_parser(
        "list-versions",
        help="List available VM-Series versions for a region and license type."
    )
    parser_list.add_argument(
        "--region", default="eastus",
        help="Azure region to query (default: eastus)."
    )
    parser_list.add_argument(
        "--license-type",
        choices=list(MARKETPLACE_SKUS.keys()),
        help=f"License type to list versions for. Choices: {', '.join(MARKETPLACE_SKUS.keys())}. If omitted, an interactive menu is shown."
    )
    parser_list.set_defaults(func=handle_list_versions)

    # --- find-regional-inconsistencies ---
    parser_find = subparsers.add_parser(
        "find-regional-inconsistencies",
        help="Scan Azure regions for VM-Series version availability gaps."
    )
    parser_find.add_argument(
        "--license-type",
        required=True,
        choices=list(MARKETPLACE_SKUS.keys()),
        help=f"License type to scan. Choices: {', '.join(MARKETPLACE_SKUS.keys())}."
    )
    parser_find.set_defaults(func=handle_find_regional_inconsistencies)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
