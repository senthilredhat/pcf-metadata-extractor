"""PCF v3 org inventory run (orchestrates org_extract + app + process)."""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TextIO

from pcf_inventory_extractor.client import CfApiClient
from pcf_inventory_extractor.client.uaa_auth import (
    CfProgrammaticAuthError,
    fetch_access_token,
    normalize_api_base,
)
from pcf_inventory_extractor.constants import CONFIG_CSV_TIMESTAMP_FORMAT, CONFIG_OUTPUT_PREFIX
from pcf_inventory_extractor.extraction import org
from pcf_inventory_extractor.output.csv import write_header
from pcf_inventory_extractor.utils.helpers import log_debug


def sanitize_filename_component(s: str) -> str:
    """Remove characters that could cause path traversal or filesystem issues."""
    # Remove path separators and dangerous characters
    s = re.sub(r'[/\\:*?"<>|\x00-\x1f]', '_', s)
    # Remove leading dots to prevent hidden files
    s = s.lstrip('.')
    # Limit length
    s = s[:100]
    return s or "unknown"


def default_output_name(org: str) -> str:
    ts = datetime.now().strftime(CONFIG_CSV_TIMESTAMP_FORMAT)
    safe_org = sanitize_filename_component(org)
    return f"{CONFIG_OUTPUT_PREFIX}_{safe_org}_{ts}.csv"


@dataclass
class ExtractConfig:
    org_name: str
    output_path: Path
    debug: bool = False
    cf_api_url: str | None = None
    cf_username: str | None = None
    cf_password: str | None = None
    https_verify: bool = True
    skip_env_vars: bool = False


def _password_nonempty(cfg: ExtractConfig) -> bool:
    return cfg.cf_password is not None and cfg.cf_password != ""


def _programmatic_login_requested(cfg: ExtractConfig) -> bool:
    a = (cfg.cf_api_url or "").strip()
    u = (cfg.cf_username or "").strip()
    return bool(a or u or _password_nonempty(cfg))


def _programmatic_login_complete(cfg: ExtractConfig) -> bool:
    a = (cfg.cf_api_url or "").strip()
    u = (cfg.cf_username or "").strip()
    return bool(a and u and _password_nonempty(cfg))


def _programmatic_login_partial(cfg: ExtractConfig) -> bool:
    return _programmatic_login_requested(cfg) and not _programmatic_login_complete(cfg)


def validate_cf_environment() -> None:
    try:
        subprocess.run(
            ["cf", "version"],
            check=True,
            capture_output=True,
        )
    except FileNotFoundError as e:
        print("cf CLI not found in PATH", file=sys.stderr)
        raise SystemExit(1) from e
    except subprocess.CalledProcessError as e:
        print("cf version failed", file=sys.stderr)
        raise SystemExit(1) from e
    r = subprocess.run(
        ["cf", "target"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        print("Not logged in to Cloud Foundry. Run 'cf login' first.", file=sys.stderr)
        raise SystemExit(1)


class InventoryExtractor:
    def __init__(self, client: CfApiClient, cfg: ExtractConfig) -> None:
        self.client = client
        self.cfg = cfg
        self.org_name = cfg.org_name
        self.org_guid = ""
        self.org_sg = ""
        self.global_sg = ""
        self.debug = cfg.debug
        self.https_verify = cfg.https_verify
        self.skip_env_vars = cfg.skip_env_vars
        self.warning_count = 0
        self._out: TextIO | None = None

    def _fd(self) -> TextIO:
        if self._out is None:
            raise RuntimeError("output file not open")
        return self._out

    def _debug(self, msg: str) -> None:
        log_debug(msg, self.debug)

    def _validate(self, j: str, context: str) -> bool:
        if (not j) or (j.strip() == "{}"):
            self._debug(f"empty API response {context}")
            self.warning_count += 1
            return False
        import json
        try:
            json.loads(j)
        except json.JSONDecodeError:
            self._debug(f"invalid JSON {context}")
            self.warning_count += 1
            return False
        return True

    def run(self) -> None:
        if _programmatic_login_partial(self.cfg):
            raise CfProgrammaticAuthError(
                "CF API URL, username, and password are all required for programmatic login."
            )
        if _programmatic_login_complete(self.cfg):
            api = normalize_api_base(self.cfg.cf_api_url or "")
            token = fetch_access_token(
                api,
                (self.cfg.cf_username or "").strip(),
                self.cfg.cf_password or "",
                https_verify=self.cfg.https_verify,
            )
            self.client.connect_with_token(api, token, https_verify=self.cfg.https_verify)
        else:
            validate_cf_environment()
            self.client.connect(https_verify=self.cfg.https_verify)
        try:
            self._out = open(
                self.cfg.output_path, "w", encoding="utf-8", newline=""
            )
            try:
                write_header(self._out)
                self.org_guid = org.extract_org_guid(self)
                self.org_sg = org.org_security_groups(
                    self, self.org_guid
                )
                self.global_sg = org.global_security_groups(self)
                org.extract_spaces(self)
            finally:
                if self._out:
                    self._out.close()
                    self._out = None
            print(
                f"Report generated: {self.cfg.output_path}",
                file=sys.stderr,
            )
            if self.warning_count:
                print(
                    f"Data quality: {self.warning_count} warning(s) — "
                    "some data may be incomplete",
                    file=sys.stderr,
                )
            else:
                print("Data quality: no warnings.", file=sys.stderr)
        finally:
            self.client.close()
