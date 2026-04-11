import boto3
from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from datetime import datetime, timezone

console = Console()


def scan_mock_aws():
    """
    Returns mock scanner findings for testing the pipeline without AWS costs.
    Uses the same dict format as the real scanners.
    """
    console.print("[bold blue]Scanning Mock AWS Environment...[/bold blue]")
    mock_findings = [
        {
            "service": "S3",
            "resource_name": "s3-bucket-customer-data",
            "issue": "Public Read Access Enabled",
            "severity": "Critical",
            "details": "Bucket policy allows public GetObject.",
        },
        {
            "service": "S3",
            "resource_name": "s3-logs-archive",
            "issue": "No default encryption",
            "severity": "High",
            "details": "SSE is not enabled on this bucket.",
        },
        {
            "service": "IAM",
            "resource_name": "User: dev-intern",
            "issue": "MFA Not Enabled",
            "severity": "High",
            "details": "No hardware or virtual MFA device configured.",
        },
        {
            "service": "EC2/VPC",
            "resource_name": "sg-web-server (sg-0abc123)",
            "issue": "Open to world (Port(s) 22-22)",
            "severity": "Critical",
            "details": "Rule allows traffic from 0.0.0.0/0 for SSH.",
        },
        {
            "service": "S3",
            "resource_name": "s3-backup-prod",
            "issue": "Versioning not enabled",
            "severity": "Medium",
            "details": "Status: Suspended",
        },
    ]
    console.print(
        f"[bold green]Found {len(mock_findings)} potential misconfigurations "
        f"in mock data.[/bold green]"
    )
    return mock_findings


def scan_s3_buckets(session):
    """
    Scans all S3 buckets for:
      - Public access block settings
      - Default encryption (SSE)
      - Versioning status
    """
    console.print("[bold blue]Scanning S3 Buckets...[/bold blue]")
    try:
        s3_client = session.client("s3")
        buckets = s3_client.list_buckets().get("Buckets", [])

        findings = []
        table = Table(title="S3 Bucket Misconfigurations")
        table.add_column("Service", style="cyan")
        table.add_column("Resource", style="green")
        table.add_column("Issue", style="cyan")
        table.add_column("Severity")

        for bucket in buckets:
            bucket_name = bucket["Name"]

            # --- Public Access Block ---
            try:
                pab = s3_client.get_public_access_block(Bucket=bucket_name)
                conf = pab.get("PublicAccessBlockConfiguration", {})
                is_blocked = all(
                    [
                        conf.get("BlockPublicAcls"),
                        conf.get("IgnorePublicAcls"),
                        conf.get("BlockPublicPolicy"),
                        conf.get("RestrictPublicBuckets"),
                    ]
                )
                if not is_blocked:
                    findings.append(
                        {
                            "service": "S3",
                            "resource_name": bucket_name,
                            "issue": "Public access not fully blocked",
                            "severity": "Critical",
                            "details": "One or more BlockPublicAccess settings are False.",
                        }
                    )
                    table.add_row(
                        "S3", bucket_name,
                        "Public access not fully blocked",
                        "[bold red]Critical[/bold red]",
                    )
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    findings.append(
                        {
                            "service": "S3",
                            "resource_name": bucket_name,
                            "issue": "No Public Access Block configured",
                            "severity": "Critical",
                            "details": "PublicAccessBlock is not set at all.",
                        }
                    )
                    table.add_row(
                        "S3", bucket_name,
                        "No Public Access Block configured",
                        "[bold red]Critical[/bold red]",
                    )

            # --- Default Encryption ---
            try:
                s3_client.get_bucket_encryption(Bucket=bucket_name)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    findings.append(
                        {
                            "service": "S3",
                            "resource_name": bucket_name,
                            "issue": "No default encryption",
                            "severity": "High",
                            "details": "SSE is not enabled.",
                        }
                    )
                    table.add_row(
                        "S3", bucket_name,
                        "No default encryption",
                        "[bold yellow]High[/bold yellow]",
                    )

            # --- Versioning ---
            try:
                ver = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if ver.get("Status") != "Enabled":
                    status = ver.get("Status", "Not set")
                    findings.append(
                        {
                            "service": "S3",
                            "resource_name": bucket_name,
                            "issue": "Versioning not enabled",
                            "severity": "Medium",
                            "details": f"Versioning status: {status}",
                        }
                    )
                    table.add_row(
                        "S3", bucket_name,
                        "Versioning not enabled",
                        "[bright_yellow]Medium[/bright_yellow]",
                    )
            except ClientError:
                pass  # AccessDenied or other - skip silently

        if table.row_count > 0:
            console.print(table)
        else:
            console.print("[bold green]No S3 misconfigurations found![/bold green]")

        return findings

    except Exception as e:
        console.print(f"[bold red]Failed to scan S3 buckets: {e}[/bold red]")
        return []


def scan_security_groups(session):
    """
    Scans EC2 security groups for inbound rules open to 0.0.0.0/0 or ::/0.
    Critical if port 22 (SSH) or 3389 (RDP); High otherwise.
    """
    console.print("[bold blue]Scanning Security Groups...[/bold blue]")
    try:
        ec2_client = session.client("ec2")
        sgs = ec2_client.describe_security_groups().get("SecurityGroups", [])

        findings = []
        table = Table(title="Security Group Misconfigurations")
        table.add_column("Service", style="cyan")
        table.add_column("Resource", style="green")
        table.add_column("Issue", style="cyan")
        table.add_column("Severity")

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg["GroupName"]
            resource_label = f"{sg_name} ({sg_id})"

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                protocol = rule.get("IpProtocol", "-1")

                # Check if the rule is open to the world
                open_cidrs = [
                    r for r in rule.get("IpRanges", [])
                    if r.get("CidrIp") == "0.0.0.0/0"
                ]
                open_ipv6 = [
                    r for r in rule.get("Ipv6Ranges", [])
                    if r.get("CidrIpv6") == "::/0"
                ]

                if not (open_cidrs or open_ipv6):
                    continue

                # Determine severity
                is_critical = False
                if protocol == "-1":
                    is_critical = True  # All traffic
                elif from_port is not None and to_port is not None:
                    if from_port <= 22 <= to_port or from_port <= 3389 <= to_port:
                        is_critical = True

                severity = "Critical" if is_critical else "High"
                sev_style = (
                    "[bold red]Critical[/bold red]"
                    if is_critical
                    else "[bold yellow]High[/bold yellow]"
                )

                port_str = (
                    "All Ports" if protocol == "-1" else f"Port(s) {from_port}-{to_port}"
                )
                issue_desc = f"Open to world ({port_str})"

                findings.append(
                    {
                        "service": "EC2/VPC",
                        "resource_name": resource_label,
                        "issue": issue_desc,
                        "severity": severity,
                        "details": f"Inbound rule allows 0.0.0.0/0 or ::/0 on {port_str}",
                    }
                )
                table.add_row("EC2/VPC", resource_label, issue_desc, sev_style)

        if table.row_count > 0:
            console.print(table)
        else:
            console.print(
                "[bold green]No Security Group misconfigurations found![/bold green]"
            )

        return findings

    except Exception as e:
        console.print(f"[bold red]Failed to scan Security Groups: {e}[/bold red]")
        return []


def scan_iam(session):
    """
    Scans IAM for:
      - Root account MFA status (Critical)
      - Users without MFA (High)
      - Access keys older than 90 days (High)
      - Users with AdministratorAccess directly attached (Critical)
    """
    console.print("[bold blue]Scanning IAM...[/bold blue]")
    try:
        iam_client = session.client("iam")
        findings = []
        table = Table(title="IAM Misconfigurations")
        table.add_column("Service", style="cyan")
        table.add_column("Resource", style="green")
        table.add_column("Issue", style="cyan")
        table.add_column("Severity")

        # --- Root MFA ---
        try:
            summary = iam_client.get_account_summary()
            if summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0) == 0:
                findings.append(
                    {
                        "service": "IAM",
                        "resource_name": "Root Account",
                        "issue": "Root MFA not enabled",
                        "severity": "Critical",
                        "details": "The root account does not have MFA configured.",
                    }
                )
                table.add_row(
                    "IAM", "Root Account",
                    "Root MFA not enabled",
                    "[bold red]Critical[/bold red]",
                )
        except ClientError as e:
            console.print(f"[yellow]Skipping root MFA check: {e}[/yellow]")

        # --- Per-user checks ---
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]

                # MFA check
                mfa_devices = iam_client.list_mfa_devices(UserName=username).get(
                    "MFADevices", []
                )
                if not mfa_devices:
                    findings.append(
                        {
                            "service": "IAM",
                            "resource_name": f"User: {username}",
                            "issue": "MFA not enabled",
                            "severity": "High",
                            "details": "No MFA device configured for this user.",
                        }
                    )
                    table.add_row(
                        "IAM", username,
                        "MFA not enabled",
                        "[bold yellow]High[/bold yellow]",
                    )

                # Access key age
                keys = iam_client.list_access_keys(UserName=username).get(
                    "AccessKeyMetadata", []
                )
                now = datetime.now(timezone.utc)
                for key in keys:
                    create_date = key["CreateDate"]
                    # boto3 returns timezone-aware datetimes
                    age_days = (now - create_date).days
                    if age_days > 90:
                        key_id = key["AccessKeyId"]
                        findings.append(
                            {
                                "service": "IAM",
                                "resource_name": f"Key: {key_id} ({username})",
                                "issue": "Access key older than 90 days",
                                "severity": "High",
                                "details": f"Key is {age_days} days old.",
                            }
                        )
                        table.add_row(
                            "IAM", f"{username} / {key_id}",
                            f"Access key > 90 days ({age_days}d)",
                            "[bold yellow]High[/bold yellow]",
                        )

                # AdministratorAccess check
                attached = iam_client.list_attached_user_policies(
                    UserName=username
                ).get("AttachedPolicies", [])
                for policy in attached:
                    if policy.get("PolicyName") == "AdministratorAccess":
                        findings.append(
                            {
                                "service": "IAM",
                                "resource_name": f"User: {username}",
                                "issue": "AdministratorAccess attached directly",
                                "severity": "Critical",
                                "details": "User has full admin privileges via direct policy attachment.",
                            }
                        )
                        table.add_row(
                            "IAM", username,
                            "AdministratorAccess attached",
                            "[bold red]Critical[/bold red]",
                        )

        if table.row_count > 0:
            console.print(table)
        else:
            console.print("[bold green]No IAM misconfigurations found![/bold green]")

        return findings

    except Exception as e:
        console.print(f"[bold red]Failed to scan IAM: {e}[/bold red]")
        return []


def connect_aws():
    """
    Creates a boto3 session and tests connectivity.
    Returns:
      - A real boto3.Session when AWS credentials are available.
      - A mock dict {"status": "connected", "mock": True} as fallback.
    """
    console.print("[bold blue]Connecting to AWS...[/bold blue]")
    try:
        session = boto3.Session()
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        console.print(
            f"[bold green]Connected to AWS account {account_id}[/bold green]"
        )
        return session
    except Exception:
        console.print(
            "[bold yellow]AWS credentials not found. Falling back to mock mode.[/bold yellow]"
        )
        return {"status": "connected", "mock": True}


if __name__ == "__main__":
    session = connect_aws()
    if isinstance(session, dict) and session.get("mock"):
        scan_mock_aws()
    else:
        scan_s3_buckets(session)
        scan_security_groups(session)
        scan_iam(session)
