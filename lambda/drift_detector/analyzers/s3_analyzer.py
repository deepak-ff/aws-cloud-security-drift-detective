"""
s3_analyzer.py
--------------
Detects risky S3 configuration changes from CloudTrail events.
"""

S3_RISKY_EVENTS = {
    "PutBucketAcl",
    "PutBucketPolicy",
    "DeletePublicAccessBlock",
    "PutBucketPublicAccessBlock",
    "DeleteBucketEncryption",
    "PutBucketEncryption",
}


def analyze_s3_event(detail: dict) -> list[dict]:
    """
    Analyze a CloudTrail S3 event and return security findings.

    Args:
        detail: CloudTrail event detail object from EventBridge.

    Returns:
        List of finding dicts.
    """
    event_name = detail.get("eventName", "")
    if event_name not in S3_RISKY_EVENTS:
        return []

    findings = []
    request_params = detail.get("requestParameters", {}) or {}
    event_time = detail.get("eventTime", "unknown")
    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn", "unknown")

    bucket_name = (
        request_params.get("bucketName")
        or request_params.get("Bucket")
        or "unknown-bucket"
    )

    # Public ACL change
    if event_name == "PutBucketAcl":
        acl = str(request_params.get("AccessControlPolicy", request_params))
        if "AllUsers" in acl or "AuthenticatedUsers" in acl:
            findings.append(_finding(
                service="S3",
                severity="Critical",
                title="S3 Bucket Made Public (ACL)",
                resource_id=bucket_name,
                description=(
                    f"Bucket '{bucket_name}' ACL changed to allow public access "
                    f"by '{actor}'."
                ),
                recommendation=(
                    "Enable S3 Block Public Access and remove public ACL grants."
                ),
                event_name=event_name,
                event_time=event_time,
            ))

    # Public bucket policy
    if event_name == "PutBucketPolicy":
        policy = str(request_params.get("bucketPolicy", request_params))
        if '"Principal":"*"' in policy.replace(" ", "") or '"Principal": "*"' in policy:
            findings.append(_finding(
                service="S3",
                severity="Critical",
                title="S3 Bucket Public Policy Applied",
                resource_id=bucket_name,
                description=(
                    f"Public bucket policy applied to '{bucket_name}' by '{actor}'."
                ),
                recommendation="Remove public Principal:* from bucket policy immediately.",
                event_name=event_name,
                event_time=event_time,
            ))

    # Block Public Access disabled
    if event_name == "DeletePublicAccessBlock":
        findings.append(_finding(
            service="S3",
            severity="High",
            title="S3 Block Public Access Removed",
            resource_id=bucket_name,
            description=(
                f"Block Public Access settings removed from '{bucket_name}' "
                f"by '{actor}'."
            ),
            recommendation="Re-enable S3 Block Public Access on this bucket and account.",
            event_name=event_name,
            event_time=event_time,
        ))

    if event_name == "PutBucketPublicAccessBlock":
        config = request_params.get("publicAccessBlockConfiguration", {})
        if not config.get("BlockPublicAcls", True):
            findings.append(_finding(
                service="S3",
                severity="High",
                title="S3 Public Access Block Weakened",
                resource_id=bucket_name,
                description=f"Public access block settings weakened on '{bucket_name}'.",
                recommendation="Set all Block Public Access options to true.",
                event_name=event_name,
                event_time=event_time,
            ))

    # Encryption removed
    if event_name == "DeleteBucketEncryption":
        findings.append(_finding(
            service="S3",
            severity="Medium",
            title="S3 Bucket Encryption Removed",
            resource_id=bucket_name,
            description=f"Default encryption removed from '{bucket_name}' by '{actor}'.",
            recommendation="Re-enable SSE-S3 or SSE-KMS default encryption.",
            event_name=event_name,
            event_time=event_time,
        ))

    return findings


def _finding(service, severity, title, resource_id, description,
             recommendation, event_name, event_time) -> dict:
    return {
        "service": service,
        "severity": severity,
        "title": title,
        "resource_id": resource_id,
        "description": description,
        "recommendation": recommendation,
        "event_name": event_name,
        "event_time": event_time,
    }
