#!/usr/bin/env python3
# cybermonitor/cli.py
"""
CyberMonitor CLI - Command-line interface for cloud security scanning.

Usage:
    cybermonitor scan aws          Scan AWS resources
    cybermonitor scan azure        Scan Azure resources
    cybermonitor scan terraform    Scan Terraform files
    cybermonitor scan all          Run all scans
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List

from cybermonitor import __version__
from cybermonitor.config import Config
from cybermonitor.scanners.aws_scanner import AWSScanner, Finding
from cybermonitor.scanners.azure_scanner import AzureScanner
from cybermonitor.scanners.terraform_scanner import TerraformScanner
from cybermonitor.alerting.alert_manager import AlertManager
from cybermonitor.utils.formatters import format_findings_table, format_summary, format_json_report


def setup_logging(verbose: bool = False):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def scan_aws(args) -> List[Finding]:
    """Run AWS security scan."""
    print("\n[*] Starting AWS Security Scan...")
    try:
        scanner = AWSScanner()
        findings = scanner.scan_all()
        print(format_findings_table(findings))
        print(format_summary(scanner.get_summary()))
        return findings
    except ImportError as e:
        print(f"[!] AWS scanning requires boto3. Install with: pip install boto3")
        print(f"    Error: {e}")
        return []
    except Exception as e:
        print(f"[!] AWS scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return []


def scan_azure(args) -> List[Finding]:
    """Run Azure security scan."""
    print("\n[*] Starting Azure Security Scan...")

    config = Config()
    if not config.azure.subscription_id:
        print("[!] Azure subscription ID not configured.")
        print("    Set AZURE_SUBSCRIPTION_ID environment variable.")
        return []

    try:
        scanner = AzureScanner(subscription_id=config.azure.subscription_id)
        findings = scanner.scan_all()
        print(format_findings_table(findings))
        print(format_summary(scanner.get_summary()))
        return findings
    except ImportError as e:
        print(f"[!] Azure scanning requires azure-identity and azure-mgmt-storage.")
        print(f"    Install with: pip install azure-identity azure-mgmt-storage")
        print(f"    Error: {e}")
        return []
    except Exception as e:
        print(f"[!] Azure scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return []


def scan_terraform(args) -> List[Finding]:
    """Run Terraform security scan."""
    path = args.path or "."
    print(f"\n[*] Starting Terraform Security Scan in: {path}")

    try:
        scanner = TerraformScanner()

        path_obj = Path(path)
        if path_obj.is_file():
            findings = scanner.scan_file(path_obj)
        else:
            findings = scanner.scan_directory(path_obj)

        print(format_findings_table(findings))
        print(format_summary(scanner.get_summary()))
        return findings
    except ImportError as e:
        print(f"[!] Terraform scanning requires python-hcl2.")
        print(f"    Install with: pip install python-hcl2")
        print(f"    Error: {e}")
        return []
    except Exception as e:
        print(f"[!] Terraform scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return []


def scan_all(args) -> List[Finding]:
    """Run all available scans."""
    all_findings = []

    all_findings.extend(scan_aws(args))
    all_findings.extend(scan_azure(args))
    all_findings.extend(scan_terraform(args))

    print("\n" + "=" * 60)
    print("COMBINED SCAN RESULTS")
    print("=" * 60)
    print(f"Total findings across all scans: {len(all_findings)}")

    return all_findings


def send_alerts(findings: List[Finding], args):
    """Send alerts for findings if configured."""
    config = Config()

    if not args.alert:
        return

    print("\n[*] Sending alerts...")

    alert_manager = AlertManager(
        sns_topic_arn=config.aws.sns_topic_arn,
        slack_webhook_url=config.alerts.slack_webhook_url,
        enable_sns=config.alerts.enable_sns,
        enable_slack=config.alerts.enable_slack
    )

    results = alert_manager.send_batch_alert(findings, "CyberMonitor Security Scan")
    print(f"    Alerts sent: {results}")


def output_results(findings: List[Finding], args):
    """Output results in requested format."""
    if args.output:
        output_path = Path(args.output)

        if args.format == "json":
            report = format_json_report(findings)
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[*] JSON report saved to: {output_path}")

        elif args.format == "text":
            with open(output_path, 'w') as f:
                f.write(format_findings_table(findings))
            print(f"\n[*] Text report saved to: {output_path}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="CyberMonitor - Cloud Security Scanning Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cybermonitor scan aws                     Scan AWS resources
  cybermonitor scan terraform --path ./tf   Scan Terraform files
  cybermonitor scan all --output report.json --format json
  cybermonitor scan aws --alert             Scan and send alerts
        """
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'CyberMonitor {__version__}'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run security scans')
    scan_parser.add_argument(
        'target',
        choices=['aws', 'azure', 'terraform', 'all'],
        help='Scan target (aws, azure, terraform, or all)'
    )
    scan_parser.add_argument(
        '--path',
        help='Path for Terraform scanning (file or directory)'
    )
    scan_parser.add_argument(
        '--output', '-o',
        help='Output file path'
    )
    scan_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    scan_parser.add_argument(
        '--alert',
        action='store_true',
        help='Send alerts for findings'
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    setup_logging(args.verbose)

    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║  CyberMonitor v{__version__:<46}  ║
║  Cloud Security Scanning Tool                                 ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    findings = []

    if args.command == 'scan':
        if args.target == 'aws':
            findings = scan_aws(args)
        elif args.target == 'azure':
            findings = scan_azure(args)
        elif args.target == 'terraform':
            findings = scan_terraform(args)
        elif args.target == 'all':
            findings = scan_all(args)

        output_results(findings, args)
        send_alerts(findings, args)

    # Exit with error code if critical/high findings
    critical_high = sum(1 for f in findings if f.severity.value in ('critical', 'high'))
    if critical_high > 0:
        print(f"\n[!] Found {critical_high} critical/high severity issues!")
        sys.exit(1)

    print("\n[+] Scan complete!")
    sys.exit(0)


if __name__ == "__main__":
    main()
