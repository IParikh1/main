# cybermonitor/utils/formatters.py
"""
Output formatting utilities for CyberMonitor.
"""

from typing import List, Dict, Any


def format_findings_table(findings: List, max_width: int = 100) -> str:
    """
    Format findings as a text table for CLI output.

    Args:
        findings: List of Finding objects
        max_width: Maximum width for description column

    Returns:
        Formatted table string
    """
    if not findings:
        return "No findings detected."

    lines = []
    lines.append("=" * 80)
    lines.append("SECURITY FINDINGS")
    lines.append("=" * 80)
    lines.append("")

    # Group by severity
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        by_severity[f.severity.value].append(f)

    for severity in ["critical", "high", "medium", "low", "info"]:
        severity_findings = by_severity[severity]
        if not severity_findings:
            continue

        lines.append(f"\n[{severity.upper()}] ({len(severity_findings)} findings)")
        lines.append("-" * 40)

        for f in severity_findings:
            lines.append(f"  * {f.title}")
            lines.append(f"    Resource: {f.resource_id}")
            desc = f.description[:max_width] + "..." if len(f.description) > max_width else f.description
            lines.append(f"    {desc}")
            lines.append(f"    Remediation: {f.remediation[:max_width]}")
            lines.append("")

    return "\n".join(lines)


def format_summary(summary: Dict[str, Any]) -> str:
    """
    Format a scan summary for CLI output.

    Args:
        summary: Summary dictionary from scanner

    Returns:
        Formatted summary string
    """
    lines = []
    lines.append("")
    lines.append("=" * 50)
    lines.append("SCAN SUMMARY")
    lines.append("=" * 50)
    lines.append(f"Total Findings: {summary.get('total', 0)}")
    lines.append("")

    by_severity = summary.get('by_severity', {})
    lines.append("By Severity:")
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = by_severity.get(severity, 0)
        if count > 0:
            lines.append(f"  {severity.upper()}: {count}")

    by_resource = summary.get('by_resource_type', {})
    if by_resource:
        lines.append("")
        lines.append("By Resource Type:")
        for resource_type, count in by_resource.items():
            short_type = resource_type.split("::")[-1]
            lines.append(f"  {short_type}: {count}")

    lines.append("=" * 50)
    return "\n".join(lines)


def format_json_report(findings: List) -> Dict[str, Any]:
    """
    Format findings as a JSON-serializable report.

    Args:
        findings: List of Finding objects

    Returns:
        Dictionary suitable for JSON serialization
    """
    return {
        "report_version": "1.0",
        "total_findings": len(findings),
        "findings": [
            {
                "resource_type": f.resource_type,
                "resource_id": f.resource_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "remediation": f.remediation,
                "metadata": f.metadata
            }
            for f in findings
        ],
        "summary": {
            "critical": sum(1 for f in findings if f.severity.value == "critical"),
            "high": sum(1 for f in findings if f.severity.value == "high"),
            "medium": sum(1 for f in findings if f.severity.value == "medium"),
            "low": sum(1 for f in findings if f.severity.value == "low"),
            "info": sum(1 for f in findings if f.severity.value == "info")
        }
    }
