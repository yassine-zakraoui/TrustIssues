"""Validate a participant submission directory or image (thin wrapper around the CLI logic).

Usage: uv run python scripts/validate_submission.py PATH_OR_IMAGE [--live-url URL]
"""

from __future__ import annotations

import argparse
import json
import sys

from sentinel.sandbox.submission import validate_submission


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--live-url", default=None)
    args = parser.parse_args()
    report = validate_submission(args.target, live_url=args.live_url)
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
