import boto3
from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime, timezone
import csv
import io

console = Console()

# ── Compliance Mapping ──────────────────────────────────────────
# Maps security issues to industry standard controls (CIS, SOC 2, NIST)
COMPLIANCE_MAP = {
    "public read": ["CIS AWS 2.1.1", "SOC 2 CC6.1"],
    "encryption": ["CIS AWS 2.1.2", "NIST 800-53 SC-28"],
    "mfa not enabled": ["CIS AWS 1.2", "SOC 2 CC6.1"],
    "root mfa": ["CIS AWS 1.1", "SOC 2 CC6.1"],
    "open to world": ["CIS AWS 4.1", "PCI-DSS 1.2.1"],
    "versioning not enabled": ["NIST 800-53 CP-9"],
    "root account used": ["CIS AWS 1.1"],
    "access key older": ["CIS AWS 1.14"],
    "access key unused": ["CIS AWS 1.13"],
    "administratoraccess": ["CIS AWS 1.16"],
    "password length": ["CIS AWS 1.8"],
    "symbols not required": ["CIS AWS 1.9"],
}

def add_compliance_tags(findings: list[dict]) -> list[dict]:
    """
    Enriches findings with compliance metadata tags.
    """
    for f in findings:
        issue = f.get("issue", "").lower()
        tags = []
        for key, val in COMPLIANCE_MAP.items():
            if key in issue:
                tags.extend(val)
        
        if tags:
            f["compliance"] = sorted(list(set(tags)))
    return findings



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
            "region": "us-east-1",
            "issue": "Public Read Access Enabled",
            "severity": "Critical",
            "details": "Bucket policy allows public GetObject.",
        },
        {
            "service": "S3",
            "resource_name": "s3-logs-archive",
            "region": "us-east-1",
            "issue": "No default encryption",
            "severity": "High",
            "details": "SSE is not enabled on this bucket.",
        },
        {
            "service": "IAM",
            "resource_name": "User: dev-intern",
            "region": "global",
            "issue": "MFA Not Enabled",
            "severity": "High",
            "details": "No hardware or virtual MFA device configured.",
        },
        {
            "service": "EC2/VPC",
            "resource_name": "sg-web-server (sg-0abc123)",
            "region": "us-east-1",
            "issue": "Open to world (Port(s) 22-22)",
            "severity": "Critical",
            "details": "Rule allows traffic from 0.0.0.0/0 for SSH.",
        },
        {
            "service": "S3",
            "resource_name": "s3-backup-prod",
            "region": "us-east-1",
            "issue": "Versioning not enabled",
            "severity": "Medium",
            "details": "Status: Suspended",
        },
    ]

    # Show mock findings in a table
    table = Table(title="Mock Findings (Simulated)", border_style="yellow")
    table.add_column("Service", style="cyan")
    table.add_column("Resource", style="green")
    table.add_column("Issue", style="cyan")
    table.add_column("Severity")

    sev_styles = {
        "Critical": "[bold red]Critical[/bold red]",
        "High": "[bold yellow]High[/bold yellow]",
        "Medium": "[bright_yellow]Medium[/bright_yellow]",
        "Low": "[green]Low[/green]",
    }

    for f in mock_findings:
        table.add_row(
            f["service"],
            f["resource_name"],
            f["issue"],
            sev_styles.get(f["severity"], f["severity"]),
        )

    console.print(table)
    console.print(
        f"[bold green]Found {len(mock_findings)} potential misconfigurations "
        f"in mock data.[/bold green]"
    )
    return add_compliance_tags(mock_findings)


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

        # Add region: global to all S3 findings
        for f in findings:
            f["region"] = "global"

        if table.row_count > 0:
            console.print(table)
        else:
            console.print("[bold green]No S3 misconfigurations found![/bold green]")

        return findings

    except Exception as e:
        console.print(f"[bold red]Failed to scan S3 buckets: {e}[/bold red]")
        return []


def get_active_regions(session) -> list[str]:
    """
    Returns a list of active (opted-in) AWS regions.
    Falls back to [us-east-1] if it cannot describe regions.
    """
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        regions = ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )
        return [r["RegionName"] for r in regions["Regions"]]
    except Exception as e:
        console.print(f"[yellow]Warning: Could not fetch regions, defaulting to us-east-1: {e}[/yellow]")
        return ["us-east-1"]


def scan_security_groups(session, region: str = None):
    """
    Scans EC2 security groups for inbound rules open to 0.0.0.0/0 or ::/0.
    Critical if port 22 (SSH) or 3389 (RDP); High otherwise.
    """
    display_region = region if region else "default region"
    console.print(f"[bold blue]Scanning Security Groups ({display_region})...[/bold blue]")
    try:
        ec2_client = session.client("ec2", region_name=region) if region else session.client("ec2")

        # Use paginator to handle accounts with 1000+ security groups
        sgs = []
        paginator = ec2_client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            sgs.extend(page.get("SecurityGroups", []))

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
                        "region": region or "unknown",
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

        # --- Root MFA & Usage (CIS 1.7) ---
        try:
            summary = iam_client.get_account_summary()
            if summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0) == 0:
                findings.append(
                    {
                        "service": "IAM",
                        "resource_name": "Root Account",
                        "region": "global",
                        "issue": "Root MFA not enabled",
                        "severity": "Critical",
                        "details": "The root account does not have MFA configured.",
                    }
                )
                table.add_row("IAM", "Root Account", "Root MFA not enabled", "[bold red]Critical[/bold red]")

            # Root Usage Check (Credential Report)
            iam_client.generate_credential_report()
            report = iam_client.get_credential_report()
            content = report["Content"].decode("utf-8")
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                if row["user"] == "<root_account>":
                    last_used = row["password_last_used"]
                    if last_used and last_used != "not_supported":
                        # Simplistic check: if it was used at all recently
                        findings.append(
                            {
                                "service": "IAM",
                                "resource_name": "Root Account",
                                "region": "global",
                                "issue": "Root account used recently",
                                "severity": "High",
                                "details": f"Root password last used on {last_used}. Best practice is to use IAM users.",
                            }
                        )
                        table.add_row("IAM", "Root Account", "Root account used recently", "[bold yellow]High[/bold yellow]")
                    break
        except Exception as e:
            console.print(f"[yellow]Skipping root checks: {e}[/yellow]")

        # --- Password Policy (CIS 1.8, 1.9) ---
        try:
            policy = iam_client.get_account_password_policy().get("PasswordPolicy", {})
            if policy.get("MinimumPasswordLength", 0) < 14:
                findings.append(
                    {
                        "service": "IAM",
                        "resource_name": "Account Password Policy",
                        "region": "global",
                        "issue": "Weak password length (< 14)",
                        "severity": "High",
                        "details": f"Current minimum length: {policy.get('MinimumPasswordLength', 'None')}",
                    }
                )
                table.add_row("IAM", "Password Policy", "Weak length (< 14)", "[bold yellow]High[/bold yellow]")
            
            if not policy.get("RequireSymbols", False):
                findings.append(
                    {
                        "service": "IAM",
                        "resource_name": "Account Password Policy",
                        "region": "global",
                        "issue": "Symbols not required in passwords",
                        "severity": "Medium",
                        "details": "CIS Benchmarks recommend requiring at least one symbol.",
                    }
                )
                table.add_row("IAM", "Password Policy", "Symbols not required", "[bright_yellow]Medium[/bright_yellow]")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                findings.append(
                    {
                        "service": "IAM",
                        "resource_name": "Account Password Policy",
                        "region": "global",
                        "issue": "No password policy defined",
                        "severity": "High",
                        "details": "Account is using default (weak) AWS password settings.",
                    }
                )
                table.add_row("IAM", "Password Policy", "No policy defined", "[bold yellow]High[/bold yellow]")

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
                            "region": "global",
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
                                "region": "global",
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

                        # Check last used (CIS 1.13)
                        try:
                            last_used_info = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                            last_used_date = last_used_info.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                            if last_used_date:
                                inactive_days = (now - last_used_date).days
                                if inactive_days > 90:
                                    findings.append(
                                        {
                                            "service": "IAM",
                                            "resource_name": f"Key: {key_id} ({username})",
                                            "region": "global",
                                            "issue": "Access key unused > 90 days",
                                            "severity": "Medium",
                                            "details": f"Key has not been used for {inactive_days} days.",
                                        }
                                    )
                                    table.add_row("IAM", key_id, "Unused > 90 days", "[bright_yellow]Medium[/bright_yellow]")
                        except Exception:
                            pass

                # AdministratorAccess check — direct user policies
                attached = iam_client.list_attached_user_policies(
                    UserName=username
                ).get("AttachedPolicies", [])
                for policy in attached:
                    if policy.get("PolicyName") == "AdministratorAccess":
                        findings.append(
                            {
                                "service": "IAM",
                                "resource_name": f"User: {username}",
                                "region": "global",
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

                # Bug #3 fix: AdministratorAccess via IAM Groups
                try:
                    groups = iam_client.list_groups_for_user(
                        UserName=username
                    ).get("Groups", [])
                    for group in groups:
                        group_name = group["GroupName"]
                        group_policies = iam_client.list_attached_group_policies(
                            GroupName=group_name
                        ).get("AttachedPolicies", [])
                        for gp in group_policies:
                            if gp.get("PolicyName") == "AdministratorAccess":
                                findings.append(
                                    {
                                        "service": "IAM",
                                        "resource_name": f"User: {username}",
                                        "region": "global",
                                        "issue": f"AdministratorAccess via group '{group_name}'",
                                        "severity": "Critical",
                                        "details": (
                                            f"User inherits full admin from IAM group "
                                            f"'{group_name}'."
                                        ),
                                    }
                                )
                                table.add_row(
                                    "IAM", username,
                                    f"Admin via group '{group_name}'",
                                    "[bold red]Critical[/bold red]",
                                )
                except ClientError:
                    pass  # May lack permissions to inspect groups

                # Bug #3 fix: Flag inline policies (hard to audit)
                try:
                    inline_policies = iam_client.list_user_policies(
                        UserName=username
                    ).get("PolicyNames", [])
                    if inline_policies:
                        findings.append(
                            {
                                "service": "IAM",
                                "resource_name": f"User: {username}",
                                "region": "global",
                                "issue": f"Has {len(inline_policies)} inline policy(ies)",
                                "severity": "Medium",
                                "details": (
                                    f"Inline policies ({', '.join(inline_policies)}) "
                                    f"bypass centralized management and are hard to audit."
                                ),
                            }
                        )
                        table.add_row(
                            "IAM", username,
                            f"{len(inline_policies)} inline policy(ies)",
                            "[bright_yellow]Medium[/bright_yellow]",
                        )
                except ClientError:
                    pass  # May lack permissions to list inline policies

        if table.row_count > 0:
            console.print(table)
        else:
            console.print("[bold green]No IAM misconfigurations found![/bold green]")

        return findings

    except Exception as e:
        console.print(f"[bold red]Failed to scan IAM: {e}[/bold red]")
        return []


def scan_all_regions(session) -> list[dict]:
    """
    Master orchestrator:
      1. Scans Global services (S3, IAM)
      2. Scans Regional services (Security Groups) for every active region
    Returns a combined list of findings.
    """
    all_findings = []

    # 1. Global Scans
    all_findings.extend(scan_s3_buckets(session))
    all_findings.extend(scan_iam(session))

    # 2. Regional Scans
    regions = get_active_regions(session)
    console.print(f"\n[bold cyan]Discovered {len(regions)} active regions: {', '.join(regions)}[/bold cyan]")
    
    for region in regions:
        try:
            all_findings.extend(scan_security_groups(session, region))
        except Exception as e:
            console.print(f"[red]Skipping region {region} due to error: {e}[/red]")

    return add_compliance_tags(all_findings)


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
        region = session.region_name or "us-east-1"
        arn = identity.get("Arn", "Unknown")
        console.print(
            Panel(
                f"[bold green]Connected[/bold green]\n\n"
                f"  [bold]Account:[/bold]  {account_id}\n"
                f"  [bold]Region:[/bold]   {region}\n"
                f"  [bold]Identity:[/bold] {arn}",
                title="[bold cyan]AWS Connection[/bold cyan]",
                border_style="green",
                padding=(0, 2),
            )
        )
        return session
    except Exception:
        console.print(
            Panel(
                "[bold yellow]AWS credentials not found[/bold yellow]\n"
                "[dim]Falling back to mock mode (simulated findings).[/dim]",
                title="[bold yellow]Mock Mode[/bold yellow]",
                border_style="yellow",
                padding=(0, 2),
            )
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
