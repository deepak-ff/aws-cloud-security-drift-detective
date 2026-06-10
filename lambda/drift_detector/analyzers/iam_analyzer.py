"""
iam_analyzer.py
---------------
Detects risky IAM configuration changes from CloudTrail events.
"""

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

# CloudTrail event names we monitor
IAM_RISKY_EVENTS = {
    "AttachUserPolicy",
    "AttachGroupPolicy",
    "PutUserPolicy",
    "PutGroupPolicy",
    "CreateUser",
    "DeactivateMFADevice",
    "DeleteVirtualMFADevice",
    "CreateAccessKey",
}


def analyze_iam_event(detail: dict) -> list[dict]:
    """
    Analyze a CloudTrail IAM event and return security findings.

    Args:
        detail: CloudTrail event detail object from EventBridge.

    Returns:
        List of finding dicts (empty if no risk detected).
    """
    event_name = detail.get("eventName", "")
    if event_name not in IAM_RISKY_EVENTS:
        return []

    findings = []
    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn", "unknown")
    request_params = detail.get("requestParameters", {}) or {}
    event_time = detail.get("eventTime", "unknown")

    # AdministratorAccess attached to user or group
    if event_name in ("AttachUserPolicy", "AttachGroupPolicy"):
        policy_arn = request_params.get("policyArn", "")
        target = request_params.get("userName") or request_params.get("groupName", "unknown")

        if policy_arn == ADMIN_POLICY_ARN or "AdministratorAccess" in policy_arn:
            findings.append(_finding(
                service="IAM",
                severity="Critical",
                title="AdministratorAccess Policy Attached",
                resource_id=target,
                description=(
                    f"Actor '{actor}' attached AdministratorAccess to '{target}' "
                    f"via {event_name}."
                ),
                recommendation=(
                    "Remove AdministratorAccess. Use least-privilege IAM policies "
                    "and permission boundaries."
                ),
                event_name=event_name,
                event_time=event_time,
            ))

    # Inline admin policy on user/group
    if event_name in ("PutUserPolicy", "PutGroupPolicy"):
        policy_doc = str(request_params.get("policyDocument", ""))
        target = request_params.get("userName") or request_params.get("groupName", "unknown")

        if '"Action":"*"' in policy_doc.replace(" ", "") or '"Action": "*"' in policy_doc:
            findings.append(_finding(
                service="IAM",
                severity="High",
                title="Overly Permissive Inline IAM Policy",
                resource_id=target,
                description=f"Inline policy with Action:* applied to '{target}'.",
                recommendation="Replace wildcard actions with specific required permissions.",
                event_name=event_name,
                event_time=event_time,
            ))

    # MFA device removed
    if event_name in ("DeactivateMFADevice", "DeleteVirtualMFADevice"):
        username = request_params.get("userName", "unknown")
        findings.append(_finding(
            service="IAM",
            severity="High",
            title="MFA Device Removed",
            resource_id=username,
            description=f"MFA was removed for IAM user '{username}' by '{actor}'.",
            recommendation="Re-enable MFA immediately and investigate unauthorized access.",
            event_name=event_name,
            event_time=event_time,
        ))

    # New IAM user created
    if event_name == "CreateUser":
        username = request_params.get("userName", "unknown")
        findings.append(_finding(
            service="IAM",
            severity="Medium",
            title="New IAM User Created",
            resource_id=username,
            description=f"New IAM user '{username}' created by '{actor}'.",
            recommendation="Verify this user is authorized. Enforce MFA and least privilege.",
            event_name=event_name,
            event_time=event_time,
        ))

    # New access key created
    if event_name == "CreateAccessKey":
        username = request_params.get("userName", "unknown")
        findings.append(_finding(
            service="IAM",
            severity="Medium",
            title="New IAM Access Key Created",
            resource_id=username,
            description=f"New access key created for user '{username}' by '{actor}'.",
            recommendation="Rotate keys regularly. Prefer IAM roles over long-lived access keys.",
            event_name=event_name,
            event_time=event_time,
        ))

    return findings


def _finding(service, severity, title, resource_id, description,
             recommendation, event_name, event_time) -> dict:
    """Build a standardized finding dictionary."""
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
