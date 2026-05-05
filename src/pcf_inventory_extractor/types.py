"""Shared typing (avoid circular imports)."""

from __future__ import annotations

from typing import Protocol, TextIO

from pcf_inventory_extractor.client import CfApiClient


class ExtractorLike(Protocol):
    client: CfApiClient
    org_name: str
    org_guid: str
    debug: bool
    warning_count: int
    skip_env_vars: bool

    def _validate(self, j: str, context: str) -> bool: ...
    def _debug(self, msg: str) -> None: ...
    def _fd(self) -> TextIO: ...
