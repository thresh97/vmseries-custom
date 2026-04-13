#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GCP Marketplace Explorer for Palo Alto Networks VM-Series

An interactive CLI tool to discover available VM-Series images in the GCP
Marketplace (public image catalog), and to list images in a custom project.

This script provides two commands:
  1. `list-images`: Lists available VM-Series images for a given license type
     from the paloaltonetworks-public project, sorted by name (newest first).
  2. `list-custom-images`: Lists custom VM-Series images you have created in
     your own GCP project.

Prerequisites:
  - Python 3.12+
  - GCP credentials configured (run 'gcloud auth application-default login')
  - Required Python packages (see requirements.txt)

Example Usage:
  # List available marketplace images for byol
  python gcp_marketplace_explorer.py list-images --license-type byol

  # List all marketplace images (interactive license type selection)
  python gcp_marketplace_explorer.py list-images

  # List custom images in your project
  python gcp_marketplace_explorer.py list-custom-images --project-id my-gcp-project
"""

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

import yaml

try:
    from google.cloud import compute_v1
    import google.auth
except ImportError as e:
    print(f"Google Cloud SDK libraries not found: {e}", file=sys.stderr)
    print("Please install dependencies: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOGGER = logging.getLogger(__name__)


def load_marketplace_images() -> Dict:
    """Loads marketplace image mappings from the external YAML file."""
    config_file = Path(__file__).parent / "marketplace_images.yaml"
    if not config_file.is_file():
        config_file = Path("marketplace_images.yaml")
    if not config_file.is_file():
        LOGGER.error("Configuration file 'marketplace_images.yaml' not found.")
        sys.exit(1)
    with config_file.open("r") as f:
        return yaml.safe_load(f)

MARKETPLACE_IMAGES = load_marketplace_images()


def _version_sort_key(name: str) -> List[int]:
    """Returns a sortable key from a GCP image name (e.g. 'vmseries-flex-byol-1014-2102')."""
    result = []
    for part in re.split(r'[.\-]', name):
        try:
            result.append(int(part))
        except ValueError:
            result.append(0)
    return result


def select_license_type() -> str:
    """Prompts the user to select a VM-Series license type interactively."""
    LOGGER.info("\nSelect a VM-Series License Type...")
    license_types = list(MARKETPLACE_IMAGES.keys())

    for i, lt in enumerate(license_types):
        cfg = MARKETPLACE_IMAGES[lt]
        print(f"  {i+1:2d}) {lt}  (project: {cfg['project']}, family: {cfg['family']})")

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


def list_marketplace_images(license_type: str) -> None:
    """Lists available VM-Series images for the given license type from the public GCP image catalog."""
    image_config = MARKETPLACE_IMAGES.get(license_type)
    if not image_config:
        LOGGER.error(f"Unknown license type '{license_type}'. Check marketplace_images.yaml.")
        sys.exit(1)

    image_project = image_config["project"]
    image_family = image_config["family"]

    images_client = compute_v1.ImagesClient()

    LOGGER.info(f"Querying images in project '{image_project}' matching family '{image_family}'...")

    try:
        # List all images in the public project, filtered by name prefix
        # Exclude special-purpose variants (tf=Terraform, mp=Marketplace, mptf=both)
        _EXCLUDED = ("-tf-", "-mp-", "-mptf-")
        name_prefix = image_family.rsplit("-", 1)[0]
        all_images = list(images_client.list(project=image_project))
        matching = [
            img for img in all_images
            if img.name.startswith(name_prefix) and not any(x in img.name for x in _EXCLUDED)
        ]
    except Exception as e:
        LOGGER.error(f"Failed to query GCP images: {e}")
        sys.exit(1)

    if not matching:
        LOGGER.warning(f"No VM-Series images found matching family '{image_family}' in project '{image_project}'.")
        LOGGER.warning("Try running: gcloud compute images list --project paloaltonetworksgcp-public --no-standard-images")
        return

    sorted_images = sorted(matching, key=lambda img: _version_sort_key(img.name), reverse=True)

    # Get the latest from family
    try:
        latest = images_client.get_from_family(project=image_project, family=image_family)
        latest_name = latest.name
    except Exception:
        latest_name = sorted_images[0].name if sorted_images else None

    print("\n" + "="*90)
    print(f"  VM-Series GCP Images — License: {license_type}  |  Family: {image_family}")
    print(f"  Project: {image_project}")
    print("="*90)
    print(f"{'Image Name':<55} {'Family':<35} {'Status'}")
    print("-"*90)

    for img in sorted_images:
        status = "← latest in family" if img.name == latest_name else ""
        family_str = img.family or ""
        print(f"{img.name:<55} {family_str:<35} {status}")

    print("="*90)
    print(f"  Total: {len(sorted_images)} images found\n")

    if latest_name:
        print(f"  Latest (for use with --family flag or get_from_family):")
        print(f"    {latest_name}\n")

    LOGGER.info(f"✅ Found {len(sorted_images)} images.")


def list_custom_images(project_id: str, filter_prefix: Optional[str] = None) -> None:
    """Lists custom VM-Series images in the user's GCP project."""
    images_client = compute_v1.ImagesClient()

    LOGGER.info(f"Listing custom images in project '{project_id}'...")

    try:
        all_images = list(images_client.list(project=project_id))
    except Exception as e:
        LOGGER.error(f"Failed to list images in project '{project_id}': {e}")
        sys.exit(1)

    if filter_prefix:
        images = [img for img in all_images if img.name.startswith(filter_prefix)]
    else:
        # Show images that look like custom VM-Series images (contain 'custom' or 'vmseries')
        images = [
            img for img in all_images
            if "custom" in img.name or "vmseries" in img.name or "panos" in img.name
        ]
        if not images:
            images = all_images  # Fall back to showing all if no matches

    if not images:
        LOGGER.warning(f"No custom images found in project '{project_id}'.")
        return

    sorted_images = sorted(images, key=lambda img: img.creation_timestamp or "", reverse=True)

    print("\n" + "="*100)
    print(f"  Custom Images in Project: {project_id}")
    print("="*100)
    print(f"{'Image Name':<55} {'Created':<30} {'Self-Link'}")
    print("-"*100)

    for img in sorted_images:
        created = img.creation_timestamp or "unknown"
        self_link = img.self_link or ""
        print(f"{img.name:<55} {created:<30} {self_link}")

    print("="*100)
    print(f"  Total: {len(sorted_images)} images found\n")
    LOGGER.info(f"✅ Found {len(sorted_images)} images.")


# --- CLI Handlers ---

def handle_list_images(args: argparse.Namespace) -> None:
    """Handler for the list-images command."""
    print("--- Palo Alto Networks VM-Series GCP Marketplace Explorer ---")

    if args.license_type:
        if args.license_type not in MARKETPLACE_IMAGES:
            LOGGER.error(f"Unknown license type '{args.license_type}'. Valid choices: {', '.join(MARKETPLACE_IMAGES.keys())}")
            sys.exit(1)
        selected_license = args.license_type
    else:
        selected_license = select_license_type()

    list_marketplace_images(selected_license)
    print("--- Explorer finished ---")


def handle_list_custom_images(args: argparse.Namespace) -> None:
    """Handler for the list-custom-images command."""
    print("--- Palo Alto Networks VM-Series Custom GCP Image Lister ---")
    list_custom_images(args.project_id, filter_prefix=args.filter_prefix)
    print("--- Lister finished ---")


def main() -> None:
    """Main function to run the explorer."""
    parser = argparse.ArgumentParser(
        description="GCP Marketplace Explorer for Palo Alto Networks VM-Series"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- list-images ---
    parser_list = subparsers.add_parser(
        "list-images",
        help="List available VM-Series images from the GCP public image catalog."
    )
    parser_list.add_argument(
        "--license-type",
        choices=list(MARKETPLACE_IMAGES.keys()),
        help=f"License type to list images for. Choices: {', '.join(MARKETPLACE_IMAGES.keys())}. If omitted, an interactive menu is shown."
    )
    parser_list.set_defaults(func=handle_list_images)

    # --- list-custom-images ---
    parser_custom = subparsers.add_parser(
        "list-custom-images",
        help="List custom VM-Series images you have created in your GCP project."
    )
    parser_custom.add_argument(
        "--project-id",
        required=True,
        help="GCP project ID to list images from."
    )
    parser_custom.add_argument(
        "--filter-prefix",
        required=False,
        help="Optional: only show images whose names start with this prefix."
    )
    parser_custom.set_defaults(func=handle_list_custom_images)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
