"""
alert_manager.py
----------------
Sends SNS alerts and stores findings in S3 for reporting.
"""

import json
import os
from datetime import datetime

import boto3


def send_sns_alert(findings: list[dict], event_detail: dict) -> dict:
    """
    Publish security findings to SNS topic.

    Args:
        findings: List of detected security findings.
        event_detail: Original CloudTrail event detail.

    Returns:
        SNS publish response or status dict.
    """
    topic_arn = os.environ.get("SNS_TOPIC_ARN")
    if not topic_arn:
        return {"status": "skipped", "reason": "SNS_TOPIC_ARN not configured"}

    subject = _build_subject(findings)
    message = _build_message(findings, event_detail)

    sns = boto3.client("sns")
    response = sns.publish(
        TopicArn=topic_arn,
        Subject=subject[:100],  # SNS subject max 100 chars
        Message=message,
    )

    return {"status": "sent", "message_id": response.get("MessageId")}


def save_report(findings: list[dict], event_detail: dict) -> dict:
    """
    Save a JSON security report to S3 for audit trail.

    Args:
        findings: Detected findings.
        event_detail: Original CloudTrail event.

    Returns:
        S3 put status dict.
    """
    bucket = os.environ.get("REPORTS_BUCKET")
    if not bucket:
        return {"status": "skipped", "reason": "REPORTS_BUCKET not configured"}

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    event_name = event_detail.get("eventName", "unknown")
    key = f"drift-reports/{timestamp}_{event_name}.json"

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "account_id": event_detail.get("recipientAccountId", "unknown"),
        "region": event_detail.get("awsRegion", "unknown"),
        "event_name": event_name,
        "event_time": event_detail.get("eventTime"),
        "actor": event_detail.get("userIdentity", {}).get("arn"),
        "total_findings": len(findings),
        "findings": findings,
    }

    s3 = boto3.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(report, indent=2),
        ContentType="application/json",
    )

    return {"status": "saved", "bucket": bucket, "key": key}


def _build_subject(findings: list[dict]) -> str:
    """Create SNS email subject line from findings."""
    severities = [f.get("severity", "Low") for f in findings]
    highest = "Low"
    for level in ("Critical", "High", "Medium", "Low"):
        if level in severities:
            highest = level
            break

    return (
        f"[{highest}] AWS Security Drift Detected — "
        f"{len(findings)} finding(s)"
    )


def _build_message(findings: list[dict], event_detail: dict) -> str:
    """Format SNS alert message with findings and remediation steps."""
    lines = [
        "=" * 60,
        "AWS CLOUD SECURITY DRIFT DETECTIVE — ALERT",
        "=" * 60,
        "",
        f"Event:      {event_detail.get('eventName', 'N/A')}",
        f"Time:       {event_detail.get('eventTime', 'N/A')}",
        f"Region:     {event_detail.get('awsRegion', 'N/A')}",
        f"Account:    {event_detail.get('recipientAccountId', 'N/A')}",
        f"Actor:      {event_detail.get('userIdentity', {}).get('arn', 'N/A')}",
        "",
        f"FINDINGS ({len(findings)}):",
        "-" * 60,
    ]

    for idx, finding in enumerate(findings, 1):
        lines.extend([
            f"",
            f"{idx}. [{finding.get('severity')}] {finding.get('title')}",
            f"   Service:    {finding.get('service')}",
            f"   Resource:   {finding.get('resource_id')}",
            f"   Details:    {finding.get('description')}",
            f"   Fix:        {finding.get('recommendation')}",
        ])

    lines.extend([
        "",
        "=" * 60,
        "Review the full report in the S3 reports bucket.",
        "AWS Cloud Security Drift Detective",
    ])

    return "\n".join(lines)
