"""CLI entry — mirrors extract-pcf-inventory.sh arguments."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pcf_inventory_extractor.client import CfProgrammaticAuthError
from pcf_inventory_extractor.extraction import ExtractConfig, default_output_name
from pcf_inventory_extractor.run import run_extraction


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Cloud Foundry Application Metadata Extractor (v3 API)",
    )
    p.add_argument(
        "org_name",
        help="Cloud Foundry organization name",
    )
    p.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Output CSV (default: pcfusage_<org>_YYYYMMDDHHMMSS.csv)",
    )
    p.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Verbose diagnostic output to stderr",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL certificate verification (insecure; use only for self-signed certs)",
    )
    p.add_argument(
        "--no-env-vars",
        action="store_true",
        help="Skip extracting environment variables (Env Vars column will be empty)",
    )
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    out = args.output
    if not out:
        out = default_output_name(args.org_name)
    path = Path(out).expanduser().resolve()
    cfg = ExtractConfig(
        org_name=args.org_name,
        output_path=path,
        debug=bool(args.debug),
        https_verify=not args.insecure,
        skip_env_vars=bool(args.no_env_vars),
    )
    try:
        run_extraction(cfg)
    except CfProgrammaticAuthError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
