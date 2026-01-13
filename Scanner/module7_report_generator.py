# module7_report_generator.py

from datetime import datetime
import json
import os
import tempfile


# ------------------------------------------------s--
# Recommendations
# --------------------------------------------------

def add_recommendations(finding):
    severity = (finding.get("final_severity") or "low").lower()
    issues = " ".join(finding.get("detected_issues", [])).lower()

    actions = []

    if "fake extension" in issues:
        actions.append("Delete the file immediately")

    if "obfuscation" in issues:
        actions.append("Inspect script in a safe text editor")

    if "payload_download" in issues:
        actions.append("Disconnect from network and delete file")

    if "high-risk directory" in issues:
        actions.append("Move file out of Downloads directory")

    if not actions:
        if severity in ("high", "critical"):
            actions.append("Quarantine or remove the file")
        elif severity == "medium":
            actions.append("Review file manually")
        else:
            actions.append("No immediate action required")

    urgency = (
        "high" if severity in ("high", "critical")
        else "medium" if severity == "medium"
        else "low"
    )

    return {
        "urgency": urgency,
        "actions": actions
    }



# --------------------------------------------------
# TEXT REPORT
# --------------------------------------------------

def generate_text_report(scan_result):
    lines = []

    lines.append("LOCAL SECURITY SCAN REPORT")
    lines.append("=" * 30)
    lines.append(f"Scan started at : {scan_result.get('started_at')}")
    lines.append(f"Scan ended at   : {scan_result.get('ended_at')}")
    lines.append("")
    
    # ------------- add folder name
        # ---- Scan Targets ----
    lines.append("SCAN TARGETS")
    lines.append("-" * 12)

    scan_paths = scan_result.get("scan_config", {}).get("scan_paths", [])

    if not scan_paths:
        lines.append("No scan paths specified.")
    else:
        for p in scan_paths:
            lines.append(f"- {p}")

    lines.append("")


    # ---- Summary ----
    lines.append("SUMMARY")
    lines.append("-" * 10)
    lines.append(scan_result.get("summary", "No summary available."))
    lines.append("")

    # ---- Statistics ----
    stats = scan_result.get("statistics", {})
    lines.append("STATISTICS")
    lines.append("-" * 10)
    lines.append(f"Total findings        : {stats.get('total_findings', 0)}")
    lines.append(f"File-based findings   : {stats.get('total_file_findings', 0)}")
    lines.append(f"Software findings     : {stats.get('total_software_findings', 0)}")

    for sev, count in stats.get("severity_counts", {}).items():
        lines.append(f"{sev.capitalize():<15}: {count}")

    lines.append("")

    # ---- Detailed Findings ----
    lines.append("DETAILED FINDINGS")
    lines.append("-" * 16)

    findings = scan_result.get("aggregated_findings", [])

    if not findings:
        lines.append("No security issues detected.")
    else:
        for idx, item in enumerate(findings, start=1):
            lines.append(f"[{idx}] Type     : {item.get('entity_type')}")
            lines.append(f"    Name     : {item.get('name')}")
            lines.append(f"    Severity : {item.get('final_severity')}")
            lines.append("")

            # ---- Causes ----
            issues = item.get("detected_issues", [])
            if issues:
                lines.append("    Causes:")
                for issue in issues:
                    lines.append(f"      - {issue}")
                lines.append("")

            # ---- Recommendations ----
            rec = add_recommendations(item)
            if rec:
                lines.append("    Recommended Actions:")
                for action in rec.get("actions", []):
                    lines.append(f"      - {action}")
                lines.append(f"    Urgency : {rec.get('urgency')}")
                lines.append("")

    return "\n".join(lines)



# --------------------------------------------------
# generate summary
# --------------------------------------------------

def generate_summary(aggregated_findings, statistics):
    """
    Generate a human-readable summary from merged findings and statistics.
    This function must NOT re-scan, re-count, or reinterpret data.
    """

    total = statistics.get("total_findings", 0)

    if total == 0:
        return "Scan completed successfully. No security issues were detected."

    severity_counts = statistics.get("severity_counts", {})

    high = severity_counts.get("high", 0)
    critical = severity_counts.get("critical", 0)
    medium = severity_counts.get("medium", 0)
    low = severity_counts.get("low", 0)

    parts = []

    if critical:
        parts.append(f"{critical} critical")
    if high:
        parts.append(f"{high} high")
    if medium:
        parts.append(f"{medium} medium")
    if low:
        parts.append(f"{low} low")

    severity_summary = ", ".join(parts)

    return (
        f"Scan completed. {total} issue(s) detected "
        f"({severity_summary} severity)."
    )


# --------------------------------------------------
# SAVE REPORT
# --------------------------------------------------

def save_report(report_data, filepath):
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

    mode = "w"
    data = report_data

    if isinstance(report_data, dict):
        data = json.dumps(report_data, indent=2)
    elif isinstance(report_data, bytes):
        mode = "wb"

    fd, tmp = tempfile.mkstemp()
    with os.fdopen(fd, mode) as f:
        f.write(data)

    os.replace(tmp, filepath)
    return True
