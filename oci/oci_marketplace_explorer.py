#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OCI Marketplace Explorer for Palo Alto Networks VM-Series

An interactive CLI tool to discover available VM-Series listings in the OCI
Marketplace and to list custom images you have created in a compartment.

This script provides two commands:
  1. `list-listings`: Browse OCI Marketplace for VM-Series listings and show
     the image OCIDs available under each package version.
  2. `list-custom-images`: List custom VM-Series images in a compartment.

Use the image OCIDs discovered here with the --image-ocid flag of
oci_create_infra.py to bypass the Marketplace subscription flow.

Prerequisites:
  - Python 3.12+
  - OCI credentials configured (run 'oci setup config' for api_key auth)
  - Required Python packages (see requirements.txt)

Example Usage:
  # List VM-Series Marketplace listings
  python oci_marketplace_explorer.py list-listings \\
      --compartment-id ocid1.compartment.oc1..xxx \\
      --region us-ashburn-1

  # List custom images in a compartment
  python oci_marketplace_explorer.py list-custom-images \\
      --compartment-id ocid1.compartment.oc1..xxx \\
      --region us-ashburn-1

  # Filter custom images by name prefix
  python oci_marketplace_explorer.py list-custom-images \\
      --compartment-id ocid1.compartment.oc1..xxx \\
      --region us-ashburn-1 \\
      --filter-prefix custom-byol
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

try:
    import oci
except ImportError as e:
    print(f"OCI SDK not found: {e}", file=sys.stderr)
    print("Please install dependencies: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOGGER = logging.getLogger(__name__)


def load_marketplace_listings() -> Dict:
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


def get_oci_clients(auth_method: str, config_file: str, profile: str, region: str):
    """Returns initialized OCI clients."""
    if auth_method == "api_key":
        try:
            config = oci.config.from_file(file_location=config_file, profile_name=profile)
            oci.config.validate_config(config)
            config["region"] = region
        except Exception as e:
            LOGGER.error(f"Failed to load OCI config: {e}")
            sys.exit(1)
        compute_client = oci.core.ComputeClient(config)
        marketplace_client = oci.marketplace.MarketplaceClient(config)
    elif auth_method == "instance_principal":
        try:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        except Exception as e:
            LOGGER.error(f"Failed to initialize Instance Principal auth: {e}")
            sys.exit(1)
        base_config = {"region": region}
        compute_client = oci.core.ComputeClient(base_config, signer=signer)
        marketplace_client = oci.marketplace.MarketplaceClient(base_config, signer=signer)
    else:
        LOGGER.error(f"Unknown auth method '{auth_method}'.")
        sys.exit(1)

    return compute_client, marketplace_client


def list_marketplace_listings(
    marketplace_client: Any,
    compute_client: Any,
    compartment_id: str,
    license_type: Optional[str] = None,
) -> None:
    """Lists available VM-Series Marketplace listings and their package image OCIDs."""
    if license_type:
        listing_configs = {license_type: MARKETPLACE_LISTINGS[license_type]}
    else:
        listing_configs = MARKETPLACE_LISTINGS

    print("\n" + "="*80)
    print("  Palo Alto Networks VM-Series — OCI Marketplace Listings")
    print("="*80)

    for lt, cfg in listing_configs.items():
        listing_name = cfg["name"]
        pricing_type = cfg["pricing_type"]

        print(f"\n  License Type: {lt}  (pricing: {pricing_type})")
        print(f"  Searching for: '{listing_name}'")
        print("-"*80)

        try:
            response = marketplace_client.list_listings(
                compartment_id=compartment_id,
                name=listing_name,
            )
            listings = response.data
        except Exception as e:
            LOGGER.error(f"  Failed to query Marketplace: {e}")
            continue

        if not listings:
            print(f"  No listings found matching '{listing_name}'.")
            continue

        for listing in listings:
            print(f"\n  Listing: {listing.name}")
            print(f"  Listing ID: {listing.id}")
            print(f"  Publisher: {getattr(listing, 'publisher_name', 'N/A')}")

            # Get packages for this listing
            try:
                pkg_response = marketplace_client.list_packages(
                    listing_id=listing.id,
                    compartment_id=compartment_id,
                )
                packages = pkg_response.data
            except Exception as e:
                LOGGER.warning(f"  Could not list packages: {e}")
                continue

            if not packages:
                print("  No packages found.")
                continue

            print(f"\n  {'Version':<20} {'App Catalog Listing ID':<55} {'Image OCID'}")
            print(f"  {'-'*18:<20} {'-'*53:<55} {'-'*20}")

            for pkg in packages[:10]:  # Show up to 10 versions
                version = getattr(pkg, 'version', 'N/A')
                app_listing_id = getattr(pkg, 'app_catalog_listing_id', 'N/A') or 'N/A'
                image_ocid = getattr(pkg, 'app_catalog_listing_resource_id', 'N/A') or 'N/A'
                # Truncate long OCIDs for display
                app_listing_short = (app_listing_id[:52] + '...') if len(app_listing_id) > 55 else app_listing_id
                print(f"  {version:<20} {app_listing_short:<55} {image_ocid}")

            if len(packages) > 10:
                print(f"  ... and {len(packages) - 10} more versions.")

            if packages:
                latest_pkg = packages[0]
                latest_image = getattr(latest_pkg, 'app_catalog_listing_resource_id', None)
                if latest_image:
                    print(f"\n  ✅ Latest image OCID (for --image-ocid):")
                    print(f"     {latest_image}")

    print("\n" + "="*80)
    print("  Tip: Use the image OCID above with:")
    print("       python oci_create_infra.py create --image-ocid <ocid> ...")
    print("="*80 + "\n")


def list_custom_images(
    compute_client: Any,
    compartment_id: str,
    filter_prefix: Optional[str] = None,
) -> None:
    """Lists custom VM-Series images in the specified compartment."""
    LOGGER.info(f"Listing custom images in compartment '{compartment_id}'...")

    try:
        response = compute_client.list_images(
            compartment_id=compartment_id,
        )
        all_images = response.data
    except Exception as e:
        LOGGER.error(f"Failed to list images: {e}")
        sys.exit(1)

    # Filter by lifecycle_state AVAILABLE only
    available_images = [img for img in all_images if img.lifecycle_state == "AVAILABLE"]

    if filter_prefix:
        images = [img for img in available_images if img.display_name.startswith(filter_prefix)]
    else:
        # Show images that look like custom VM-Series images
        images = [
            img for img in available_images
            if any(kw in img.display_name.lower() for kw in ["custom", "vmseries", "panos", "pa-", "byol", "bundle"])
        ]
        if not images:
            images = available_images  # Fall back to all if no matches

    if not images:
        LOGGER.warning(f"No custom images found in compartment.")
        return

    # Sort by time_created (newest first)
    images_sorted = sorted(images, key=lambda img: str(img.time_created or ""), reverse=True)

    print("\n" + "="*110)
    print(f"  Custom Images in Compartment: {compartment_id}")
    print("="*110)
    print(f"  {'Display Name':<50} {'Created':<30} {'OCID'}")
    print(f"  {'-'*48:<50} {'-'*28:<30} {'-'*30}")

    for img in images_sorted:
        created = str(img.time_created)[:19] if img.time_created else "unknown"
        ocid = img.id or ""
        name = img.display_name or ""
        print(f"  {name:<50} {created:<30} {ocid}")

    print("="*110)
    print(f"  Total: {len(images_sorted)} images found\n")
    LOGGER.info(f"✅ Found {len(images_sorted)} custom images.")


# --- CLI Handlers ---

def handle_list_listings(args: argparse.Namespace) -> None:
    """Handler for the list-listings command."""
    print("--- Palo Alto Networks VM-Series OCI Marketplace Explorer ---")

    if args.license_type and args.license_type not in MARKETPLACE_LISTINGS:
        LOGGER.error(f"Unknown license type '{args.license_type}'. Valid: {', '.join(MARKETPLACE_LISTINGS.keys())}")
        sys.exit(1)

    compute_client, marketplace_client = get_oci_clients(
        auth_method=args.auth_method,
        config_file=args.oci_config_file,
        profile=args.profile,
        region=args.region,
    )

    list_marketplace_listings(
        marketplace_client=marketplace_client,
        compute_client=compute_client,
        compartment_id=args.compartment_id,
        license_type=args.license_type,
    )
    print("--- Explorer finished ---")


def handle_list_custom_images(args: argparse.Namespace) -> None:
    """Handler for the list-custom-images command."""
    print("--- Palo Alto Networks VM-Series OCI Custom Image Lister ---")

    compute_client, _ = get_oci_clients(
        auth_method=args.auth_method,
        config_file=args.oci_config_file,
        profile=args.profile,
        region=args.region,
    )

    list_custom_images(
        compute_client=compute_client,
        compartment_id=args.compartment_id,
        filter_prefix=args.filter_prefix,
    )
    print("--- Lister finished ---")


def main() -> None:
    """Main function to run the explorer."""
    parser = argparse.ArgumentParser(
        description="OCI Marketplace Explorer for Palo Alto Networks VM-Series"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Shared auth args
    def _add_auth_args(p):
        p.add_argument("--auth-method", default="api_key",
                       choices=["api_key", "instance_principal"],
                       help="OCI authentication method (default: api_key).")
        p.add_argument("--oci-config-file", default="~/.oci/config", metavar="PATH",
                       help="Path to OCI config file (default: ~/.oci/config).")
        p.add_argument("--profile", default="DEFAULT",
                       help="OCI config profile name (default: DEFAULT).")

    # --- list-listings ---
    parser_list = subparsers.add_parser(
        "list-listings",
        help="Browse OCI Marketplace for VM-Series listings and show image OCIDs.",
    )
    parser_list.add_argument("--compartment-id", required=True, help="OCI compartment OCID.")
    parser_list.add_argument("--region", required=True, help="OCI region (e.g., us-ashburn-1).")
    parser_list.add_argument(
        "--license-type",
        choices=list(MARKETPLACE_LISTINGS.keys()),
        required=False,
        help="Filter by license type. If omitted, all types are shown.",
    )
    _add_auth_args(parser_list)
    parser_list.set_defaults(func=handle_list_listings)

    # --- list-custom-images ---
    parser_custom = subparsers.add_parser(
        "list-custom-images",
        help="List custom VM-Series images you have created in a compartment.",
    )
    parser_custom.add_argument("--compartment-id", required=True, help="OCI compartment OCID.")
    parser_custom.add_argument("--region", required=True, help="OCI region (e.g., us-ashburn-1).")
    parser_custom.add_argument(
        "--filter-prefix",
        required=False,
        help="Optional: only show images whose display names start with this prefix.",
    )
    _add_auth_args(parser_custom)
    parser_custom.set_defaults(func=handle_list_custom_images)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
