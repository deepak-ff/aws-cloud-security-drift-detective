"""
handler.py
----------
AWS Lambda entry point — receives CloudTrail events from EventBridge,
analyzes them for security drift, sends SNS alerts, and saves reports.
"""

import json
import logging

from alert_manager import save_report, send_sns_alert
from analyzers.iam_analyzer import analyze_iam_event
from analyzers.s3_analyzer import analyze_s3_event
from analyzers.sg_analyzer import analyze_sg_event

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Map AWS event sources to analyzer functions
ANALYZERS = {
    "iam.amazonaws.com": analyze_iam_event,
    "s3.amazonaws.com": analyze_s3_event,
    "ec2.amazonaws.com": analyze_sg_event,
}


def lambda_handler(event, context):
    """
    Main Lambda handler triggered by EventBridge CloudTrail events.

    Args:
        event: EventBridge event containing CloudTrail detail.
        context: Lambda runtime context.

    Returns:
        dict with status and findings count.
    """
    logger.info("Received event: %s", json.dumps(event))

    # EventBridge wraps CloudTrail data in 'detail'
    detail = event.get("detail", event)
    event_source = detail.get("eventSource", "")

    analyzer = ANALYZERS.get(event_source)
    if not analyzer:
        logger.info("No analyzer for event source: %s", event_source)
        return {"status": "ignored", "reason": f"Unhandled source: {event_source}"}

    # Run the appropriate security analyzer
    findings = analyzer(detail)

    if not findings:
        logger.info("No security drift detected for %s", detail.get("eventName"))
        return {"status": "clean", "findings": 0}

    logger.warning("Detected %d security finding(s)!", len(findings))

    # Send SNS alert
    sns_result = send_sns_alert(findings, detail)
    logger.info("SNS result: %s", sns_result)

    # Save JSON report to S3
    report_result = save_report(findings, detail)
    logger.info("Report result: %s", report_result)

    return {
        "status": "alert_sent",
        "findings": len(findings),
        "severities": [f["severity"] for f in findings],
        "sns": sns_result,
        "report": report_result,
    }
