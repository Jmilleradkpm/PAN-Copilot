#!/usr/bin/env python3
"""Ensure Mac Catalyst Info.plist has a valid UIDeviceFamily for App Store validation."""
from __future__ import annotations

import plistlib
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: fix-maccatalyst-uidevicefamily.py <Info.plist>", file=sys.stderr)
        return 2

    path = sys.argv[1]
    with open(path, "rb") as handle:
        plist = plistlib.load(handle)

    raw = plist.get("UIDeviceFamily", [])
    if raw is None:
        raw = []

    valid: list[int] = []
    for value in raw:
        if isinstance(value, int):
            if value in (1, 2, 6):
                valid.append(value)
        elif isinstance(value, str) and value.strip().isdigit():
            valid.append(int(value.strip()))

    # Mac App Store (Mac Catalyst): iPhone (1) is rejected; empty strings fail validation.
    valid = [family for family in valid if family != 1]
    if not valid:
        valid = [2]

    plist["UIDeviceFamily"] = valid

    with open(path, "wb") as handle:
        plistlib.dump(plist, handle)

    print(f"UIDeviceFamily set to {valid} in {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())