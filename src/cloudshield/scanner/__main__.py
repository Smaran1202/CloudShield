import argparse
import json
import os
from collections import Counter

import boto3

from cloudshield.config import load_env_file
from cloudshield.scanner.scan import scan_account


def main(argv: list[str] | None = None, load_env: bool = True) -> int:
    if load_env:
        load_env_file()
    parser = argparse.ArgumentParser(prog="python -m cloudshield.scanner")
    parser.add_argument("--profile", help="AWS profile name (default: AWS_PROFILE or the chain)")
    parser.add_argument("--regions", help="comma separated regions (default: AWS_REGION)")
    parser.add_argument("--out", help="write the full result to this JSON file")
    args = parser.parse_args(argv)

    session = boto3.Session(profile_name=args.profile)
    if session.get_credentials() is None:
        raise SystemExit("No AWS credentials found. Use --profile or set AWS_PROFILE.")

    if args.regions:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    else:
        region = os.environ.get("AWS_REGION") or session.region_name
        regions = [region] if region else []
    if not regions:
        raise SystemExit("No region. Use --regions, set AWS_REGION, or set one on the profile.")

    result = scan_account(session, regions)

    counts = Counter(resource["resource_type"] for resource in result["resources"])
    print(f"Regions scanned: {', '.join(regions)}")
    for resource_type, count in sorted(counts.items()):
        print(f"{resource_type}: {count}")
    print(f"Errors: {len(result['errors'])}")
    for error in result["errors"]:
        print(f"  [{error['service']} {error['region']} {error['resource']}] {error['message']}")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as file:
            json.dump(result, file, indent=2, default=str)
        print(f"Full result written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
