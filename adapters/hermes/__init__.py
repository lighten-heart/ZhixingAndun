"""Version-pinned, fail-closed Hermes integration.

This adapter is a cooperative in-process enforcement boundary, not an OS sandbox.
The adjacent baseline.json records the statically inspected upstream revision;
it does not establish a verified live-model run. HermesGuardAdapter in adapter.py
defines the bounded local read/delegation profile. Native writes, shell execution,
MCP direct dispatch and native memory persistence are disabled in this profile.
"""

from .adapter import BaselineMismatch, HermesGuardAdapter, verify_baseline

__all__ = ["BaselineMismatch", "HermesGuardAdapter", "verify_baseline"]
