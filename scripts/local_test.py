#!/usr/bin/env python3
"""
local_test.py
-------------
Test drift detection locally with sample CloudTrail events.
No AWS account needed for analysis testing.

Usage:
    python scripts/local_test.py
    python scripts/local_test.py events/sample_iam_event.json
"""

import json
import sys
from pathlib import Path

# Add Lambda code to Python path
LAMBDA_DIR = Path(__file__).resolve().parent.parent / "lambda" / "drift_detector"
sys.path.insert(0, str(LAMBDA_DIR))

from analyzers.iam_analyzer import analyze_iam_event
from analyzers.s3_analyzer import analyze_s3_event
from analyzers.sg_analyzer import analyze_sg_event

ANALYZERS = {
    "iam.amazonaws.com": ("IAM", analyze_iam_event),
    "s3.amazonaws.com": ("S3", analyze_s3_event),
    "ec2.amazonaws.com": ("Security Groups", analyze_sg_event),
}


def run_test(event_file: Path) -> None:
    """Run drift analysis on a sample event file."""
    with open(event_file, encoding="utf-8") as f:
        event = json.load(f)

    detail = event.get("detail", event)
    source = detail.get("eventSource", "")

    print("=" * 60)
    print(f"  Testing: {event_file.name}")
    print(f"  Event:   {detail.get('eventName')}")
    print(f"  Source:  {source}")
    print("=" * 60)

    analyzer_info = ANALYZERS.get(source)
    if not analyzer_info:
        print(f"  No analyzer for source: {source}")
        return

    service_name, analyzer = analyzer_info
    findings = analyzer(detail)

    if not findings:
        print(f"\n  ✅ No security drift detected.\n")
        return

    print(f"\n  ⚠️  {len(findings)} FINDING(S) DETECTED:\n")
    for idx, f in enumerate(findings, 1):
        print(f"  {idx}. [{f['severity']}] {f['title']}")
        print(f"     Resource: {f['resource_id']}")
        print(f"     Details:  {f['description']}")
        print(f"     Fix:      {f['recommendation']}")
        print()


def main():
    project_dir = Path(__file__).resolve().parent.parent
    events_dir = project_dir / "events"

    if len(sys.argv) > 1:
        files = [Path(sys.argv[1])]
    else:
        files = sorted(events_dir.glob("sample_*.json"))

    if not files:
        print("No sample event files found in events/")
        sys.exit(1)

    print("\n🔍 AWS Cloud Security Drift Detective — Local Test\n")

    for event_file in files:
        run_test(event_file)

    print("=" * 60)
    print("  Local test complete. Deploy to AWS for live monitoring.")
    print("=" * 60)


if __name__ == "__main__":
    main()
