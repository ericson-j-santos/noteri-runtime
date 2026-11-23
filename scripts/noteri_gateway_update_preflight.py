#!/usr/bin/env python3
"""Read-only classifier for the governed Noteri Gateway update path."""
from __future__ import annotations

import json
import os
import socket

import noteri_gateway_legacy_pin_inventory as legacy
import noteri_gateway_refresh as refresh


def inventory() -> dict[str, object]:
    if os.name != "nt" or socket.gethostname().casefold() != refresh.EXPECTED_HOST.casefold():
        raise refresh.RefreshError("NOTERI_WINDOWS_REQUIRED")
    current = refresh.read_update_receipt()
    if current is not None and current[0].get("result") == "HOST_UPDATE_OK":
        verified = refresh.verify_previous_v2_receipt(current[0])
        return {
            "result": "NOTERI_GATEWAY_UPDATE_PREFLIGHT",
            "update_mode": "standard_v2",
            "source_commit": verified["source_commit"],
            "receipt_sha256": verified["receipt_sha256"],
            "manifest_sha256": None,
            "installation_authorized": False,
            "managed_runtime_changed": False,
        }
    legacy_report = legacy.inventory(refresh.INSTALL_ROOT)
    return {
        "result": "NOTERI_GATEWAY_UPDATE_PREFLIGHT",
        "update_mode": "legacy_v1_rebaseline",
        "source_commit": legacy.LEGACY_SOURCE_COMMIT,
        "receipt_sha256": legacy_report["receipt_sha256"],
        "manifest_sha256": legacy_report["manifest_sha256"],
        "installation_authorized": False,
        "managed_runtime_changed": False,
    }


def main() -> int:
    try:
        print(json.dumps(inventory(), sort_keys=True))
        return 0
    except Exception as exc:
        reason = str(exc) if isinstance(
            exc, (refresh.RefreshError, legacy.PinInventoryBlocked)
        ) else "HOST_READ_FAILED"
        print(json.dumps({
            "result": "NOTERI_GATEWAY_UPDATE_PREFLIGHT_BLOCKED",
            "reason": reason,
        }, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
