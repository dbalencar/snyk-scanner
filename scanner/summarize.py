#!/usr/bin/env python3
"""Reduces a raw snyk --json output file to a small severity-count summary
so the RabbitMQ result message doesn't have to carry the full payload."""
import argparse
import json

SEVERITIES = ("critical", "high", "medium", "low")


def summarize_sca_or_iac(data: dict) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for vuln in data.get("vulnerabilities", []):
        sev = vuln.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts


def summarize_sast(data: dict) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for run in data.get("runs", []):
        for result in run.get("results", []):
            sev = (result.get("properties", {}) or {}).get("priorityScore")
            level = result.get("level")
            # SARIF level->severity is a rough mapping; sast results use SARIF.
            mapped = {"error": "high", "warning": "medium", "note": "low"}.get(level)
            if mapped:
                counts[mapped] += 1
    return counts


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--file", required=True)
    p.add_argument("--scan-type", required=True)
    args = p.parse_args()

    try:
        with open(args.file) as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        print(json.dumps({s: 0 for s in SEVERITIES}))
        return

    if args.scan_type == "sast":
        summary = summarize_sast(data)
    else:
        summary = summarize_sca_or_iac(data)

    print(json.dumps(summary))


if __name__ == "__main__":
    main()
