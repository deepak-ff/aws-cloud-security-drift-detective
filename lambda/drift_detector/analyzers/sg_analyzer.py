"""
sg_analyzer.py
--------------
Detects risky Security Group changes from CloudTrail EC2 events.
"""

SG_RISKY_EVENTS = {
    "AuthorizeSecurityGroupIngress",
    "ModifySecurityGroupRules",
    "CreateSecurityGroup",
}


def analyze_sg_event(detail: dict) -> list[dict]:
    """
    Analyze a CloudTrail EC2 Security Group event.

    Args:
        detail: CloudTrail event detail object from EventBridge.

    Returns:
        List of finding dicts.
    """
    event_name = detail.get("eventName", "")
    if event_name not in SG_RISKY_EVENTS:
        return []

    findings = []
    request_params = detail.get("requestParameters", {}) or {}
    event_time = detail.get("eventTime", "unknown")
    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn", "unknown")

    group_id = request_params.get("groupId", "unknown-sg")
    group_name = request_params.get("groupName", group_id)

    # Check ipPermissions in AuthorizeSecurityGroupIngress
    permissions = request_params.get("ipPermissions", [])
    if not permissions and "ipPermissions" in request_params:
        permissions = [request_params["ipPermissions"]]

    # Handle items wrapper format from some CloudTrail events
    if isinstance(permissions, dict) and "items" in permissions:
        permissions = permissions["items"]

    if not isinstance(permissions, list):
        permissions = [permissions] if permissions else []

    for rule in permissions:
        if not isinstance(rule, dict):
            continue

        ip_protocol = rule.get("ipProtocol", "")
        from_port = _to_int(rule.get("fromPort"))
        to_port = _to_int(rule.get("toPort"))

        cidrs = _extract_cidrs(rule)

        for cidr in cidrs:
            if cidr not in ("0.0.0.0/0", "::/0"):
                continue

            # All traffic open
            if ip_protocol == "-1":
                findings.append(_finding(
                    service="EC2",
                    severity="Critical",
                    title="Security Group Open to Internet (All Traffic)",
                    resource_id=group_id,
                    description=(
                        f"SG '{group_name}' ({group_id}) allows ALL traffic from "
                        f"{cidr}. Changed by '{actor}'."
                    ),
                    recommendation="Restrict to required ports and trusted IP ranges only.",
                    event_name=event_name,
                    event_time=event_time,
                ))
                continue

            # SSH open
            if from_port is not None and to_port is not None:
                if from_port <= 22 <= to_port:
                    findings.append(_finding(
                        service="EC2",
                        severity="High",
                        title="SSH Open to Internet (Port 22)",
                        resource_id=group_id,
                        description=(
                            f"SG '{group_name}' allows SSH from {cidr}. "
                            f"Changed by '{actor}'."
                        ),
                        recommendation=(
                            "Restrict SSH to VPN/bastion IPs or use SSM Session Manager."
                        ),
                        event_name=event_name,
                        event_time=event_time,
                    ))

                # RDP open
                if from_port <= 3389 <= to_port:
                    findings.append(_finding(
                        service="EC2",
                        severity="High",
                        title="RDP Open to Internet (Port 3389)",
                        resource_id=group_id,
                        description=(
                            f"SG '{group_name}' allows RDP from {cidr}. "
                            f"Changed by '{actor}'."
                        ),
                        recommendation="Restrict RDP to corporate VPN IP ranges only.",
                        event_name=event_name,
                        event_time=event_time,
                    ))

    return findings


def _extract_cidrs(rule: dict) -> list[str]:
    """Extract IPv4/IPv6 CIDR blocks from a security group rule."""
    cidrs = []

    for key in ("ipRanges", "ipv6Ranges", "IpRanges", "Ipv6Ranges"):
        ranges = rule.get(key, {})
        if isinstance(ranges, dict) and "items" in ranges:
            ranges = ranges["items"]
        if not isinstance(ranges, list):
            ranges = [ranges] if ranges else []

        for item in ranges:
            if isinstance(item, dict):
                cidrs.append(item.get("cidrIp") or item.get("cidrIpv6") or "")
            elif isinstance(item, str):
                cidrs.append(item)

    return [c for c in cidrs if c]


def _to_int(value) -> int | None:
    """Safely convert port values to int."""
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


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
