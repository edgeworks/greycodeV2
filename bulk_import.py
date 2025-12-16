#!/usr/bin/env python3

import argparse
import json
import sys
import requests

DEFAULT_URL = "http://localhost:8000/enrich/process"


def load_events(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to read JSON file: {e}")
        sys.exit(1)

    if not isinstance(data, list):
        print("[ERROR] JSON root must be a list of objects")
        sys.exit(1)

    required_fields = {"sha256", "computer", "image"}
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            print(f"[ERROR] Entry {i} is not an object")
            sys.exit(1)
        missing = required_fields - entry.keys()
        if missing:
            print(f"[ERROR] Entry {i} missing fields: {missing}")
            sys.exit(1)

    return data


def main():
    parser = argparse.ArgumentParser(
        description="Bulk import process hashes into greycode"
    )
    parser.add_argument(
        "json_file",
        help="Path to JSON file containing process events",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"Greycode API URL (default: {DEFAULT_URL})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="HTTP timeout in seconds",
    )

    args = parser.parse_args()

    events = load_events(args.json_file)

    print(f"[INFO] Importing {len(events)} events to {args.url}")

    for idx, event in enumerate(events, start=1):
        try:
            resp = requests.post(
                args.url,
                json=event,
                timeout=args.timeout,
            )
        except requests.RequestException as e:
            print(f"[ERROR] [{idx}] Request failed: {e}")
            continue

        if resp.status_code != 200:
            print(
                f"[ERROR] [{idx}] HTTP {resp.status_code}: {resp.text}"
            )
            continue

        result = resp.json()
        print(
            f"[OK] [{idx}] {event['sha256']} → "
            f"{result.get('status')} ({result.get('source')})"
        )


if __name__ == "__main__":
    main()
