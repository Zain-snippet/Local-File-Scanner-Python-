# module6_analysis_engine

from module2_file_scanner import scan_directory
from module3_script_analyzer import analyze_script
from module4_software_inventory import build_software_inventory
from module5_vulnerability_manager import evaluate_all_software, load_vulnerability_database
from module7_report_generator import generate_summary
from module8_config_manager import get_scan_paths, get_excluded_paths
from module10_shared_utils import log_message, format_timestamp
from module_executable_detector import detect_fake_extension, detect_suspicious_location, detect_executable_type_mismatch


from datetime import datetime
from collections import Counter
import unittest
#import os

#=====================================
#       Aggregate FIndings
#=====================================

def aggregate_findings(merged_findings):
    """
    Deduplicate and aggregate findings referring to the same entity.
    Produces FINAL entities consumed by Module 7.
    """

    aggregated = {}

    # Severity precedence (max wins)
    severity_order = ["None", "Low", "Medium", "High", "Critical"]

    SCRIPT_EXTENSIONS = (".ps1", ".bat", ".cmd", ".js", ".vbs", ".sh", ".py")

    for item in merged_findings:
        item_type = item.get("type")

        # ================= FILE FINDINGS =================
        if item_type in ("script", "executable"):
            key = item.get("path")  # absolute path = identity

            if key not in aggregated:
                aggregated[key] = {
                    "entity_type": "file",
                    "path": item.get("path"),
                    "name": item.get("name"),
                    "final_severity": item.get("severity"),
                    "final_risk_score": item.get("risk_score"),
                    "categories": {item_type},
                    "detected_issues": set(item.get("issues", [])),
                    "evidence": [item]
                }
            else:
                entry = aggregated[key]

                # ---- Severity (max wins) ----
                curr_sev = entry["final_severity"]
                new_sev = item.get("severity")

                if (
                    new_sev in severity_order and
                    curr_sev in severity_order and
                    severity_order.index(new_sev) > severity_order.index(curr_sev)
                ):
                    entry["final_severity"] = new_sev

                # ---- Risk score (max wins) ----
                new_score = item.get("risk_score")
                if new_score is not None:
                    if (
                        entry["final_risk_score"] is None or
                        new_score > entry["final_risk_score"]
                    ):
                        entry["final_risk_score"] = new_score

                # ---- Categories ----
                entry["categories"].add(item_type)

                # ---- Issues ----
                entry["detected_issues"].update(item.get("issues", []))

                # ---- Evidence ----
                entry["evidence"].append(item)

        # ================= SOFTWARE FINDINGS =================
        elif item_type == "software":
            software_name = item.get("name")
            version = item.get("installed_version")
            key = f"{software_name}::{version}"

            if key not in aggregated:
                aggregated[key] = {
                    "entity_type": "software",
                    "name": software_name,
                    "installed_version": version,
                    "final_severity": item.get("severity"),
                    "final_risk_score": None,
                    "vulnerability_count": item.get("vulnerability_count", 0),
                    "evidence": [item]
                }
            else:
                entry = aggregated[key]

                # ---- Severity (max wins) ----
                curr_sev = entry["final_severity"]
                new_sev = item.get("severity")

                if (
                    new_sev in severity_order and
                    curr_sev in severity_order and
                    severity_order.index(new_sev) > severity_order.index(curr_sev)
                ):
                    entry["final_severity"] = new_sev

                # ---- Vulnerability count ----
                entry["vulnerability_count"] += item.get("vulnerability_count", 0)

                # ---- Evidence ----
                entry["evidence"].append(item)

    # ================= POLICY TWEAKS (POST-AGGREGATION) =================
    for entry in aggregated.values():
        if entry["entity_type"] != "file":
            continue

        file_name = (entry.get("name") or "").lower()

        is_script_file = file_name.endswith(SCRIPT_EXTENSIONS)

        has_script_intent = any(
            "script" in issue.lower()
            for issue in entry.get("detected_issues", [])
        )

        # Cap severity for benign scripts flagged only by location / extension
        if is_script_file and not has_script_intent:
            entry["final_severity"] = "Low"
            entry["final_risk_score"] = min(entry.get("final_risk_score") or 0, 20)

    # ================= FINAL NORMALIZATION =================
    results = []

    for entry in aggregated.values():
        if entry["entity_type"] == "file":
            entry["categories"] = sorted(entry["categories"])
            entry["detected_issues"] = sorted(entry["detected_issues"])

        results.append(entry)

    return results


# --------------------------------------------------
# File Dispatch
# --------------------------------------------------

def dispatch_file_to_detectors(filepath, command_db=None):
    """
    Decide which detectors apply to a file and run them.
    Returns a list of findings.
    """

    if command_db is None:
        command_db = {}

    findings = []

    # ---------------- Executable Detectors ----------------
    fake_ext = detect_fake_extension(filepath)
    if fake_ext:
        findings.append(fake_ext)

    suspicious_loc = detect_suspicious_location(filepath)
    if suspicious_loc:
        findings.append(suspicious_loc)

    type_mismatch = detect_executable_type_mismatch(filepath)
    if type_mismatch:
        findings.append(type_mismatch)

    # ---------------- Script Detector ----------------
    script_result = analyze_script(filepath, command_db)
    if script_result:
        findings.append(script_result)

    return findings



# --------------------------------------------------
# Core Scan Orchestration
# --------------------------------------------------



def run_full_scan(config, command_db=None):
    """
    Master pipeline controller.
    Orchestrates scanning, analysis, merging, statistics, and summary generation.
    """

    if command_db is None:
        command_db = {}

    started_at = format_timestamp(datetime.now())

    # ---------------- Resolve Config ----------------
    scan_paths = get_scan_paths(config)
    excluded_paths = set(get_excluded_paths(config))

    # ---------------- File System Scan ----------------
    log_message("INFO", "Starting file system scan")
    all_files = []

    for path in scan_paths:
        if path in excluded_paths:
            continue
        try:
            all_files.extend(scan_directory(path))
        except Exception as e:
            log_message("WARNING", f"Failed scanning {path}: {e}")

    log_message("DEBUG", f"Discovered {len(all_files)} files")

    # ---------------- File Analysis ----------------
    log_message("INFO", "Analyzing files")
    file_findings = []

    for file_path in all_files:
        try:
            findings = dispatch_file_to_detectors(file_path, command_db)
            if findings:
                file_findings.extend(findings)
        except Exception as e:
            log_message("WARNING", f"Failed analyzing {file_path}: {e}")

    # ---------------- Software Inventory ----------------
    log_message("INFO", "Building software inventory")
    try:
        software_list = build_software_inventory()
        log_message("DEBUG", f"Installed software count: {len(software_list)}")


    except Exception as e:
        log_message("ERROR", f"Failed to build software inventory: {e}")
        software_list = []

    # ---------------- Vulnerability Database ----------------
    vuln_db = None
    vuln_db_path = config.get("vulnerability_db_path")
    

    if vuln_db_path:
        try:
            vuln_db = load_vulnerability_database(vuln_db_path)
        except Exception as e:
            log_message("ERROR", f"Failed to load vulnerability DB: {e}")
            vuln_db = None
            
    if not vuln_db_path:
        log_message(
            "ERROR",
            "[FOCUS3] vulnerability_db_path missing in config — software vulnerability scan DISABLED"
        )
        

    # ---------------- Software Vulnerability Evaluation ----------------
    log_message("INFO", "Evaluating software vulnerabilities")

    if not vuln_db or not vuln_db.get("loaded"):
        log_message(
            "ERROR",
            "[FOCUS3] Vulnerability DB not loaded — skipping software vulnerability scan"
        )
        software_results = {
            "vulnerable": [],
            "safe": [],
            "unknown": []
        }
    else:
        software_results = evaluate_all_software(software_list, vuln_db)

    # ---- FOCUS 3 DEBUG OUTPUT ----
    log_message(
        "DEBUG",
        f" Vulnerable software count: "  
    )

    # ---------------- Merge Findings ----------------
    merged_findings = merge_results(file_findings, software_results)

    # ---------------- Aggregate Findings ----------------
    aggregated_findings = aggregate_findings(merged_findings)

    # ---------------- Statistics ----------------
    statistics = generate_statistics(aggregated_findings)

    # ---------------- Summary ----------------
    summary = generate_summary(aggregated_findings, statistics)

    ended_at = format_timestamp(datetime.now())

    # ---------------- Assemble ScanResult ----------------
    scan_result = {
        "scan_config": config,
        "started_at": started_at,
        "ended_at": ended_at,

        # raw
        "file_findings": file_findings,
        "software_results": software_results,
        "merged_findings": merged_findings,

        # final
        "aggregated_findings": aggregated_findings,
        "statistics": statistics,
        "summary": summary
    }

    log_message("INFO", "Scan completed successfully")
    return scan_result


# --------------------------------------------------
# Merge Logic
# --------------------------------------------------

def merge_results(file_findings, software_results):
    """
    Merge file-based findings (scripts + executables)
    and software vulnerability results into a unified list.
    """

    merged = []

    # ---------------- File Findings ----------------
    for f in file_findings:
        merged.append({
            "type": f.get("type"),              # script / executable
            "path": f.get("path"),
            "name": f.get("name"),
            "severity": f.get("severity"),
            "risk_score": f.get("risk_score"),
            "timestamp": f.get("timestamp"),
            "issues": f.get("issues", []),
            "raw": f
        })

    # ---------------- Software Vulnerabilities ONLY ----------------
    for item in software_results.get("vulnerable", []):
        software = item.get("software", {})
        vulnerabilities = item.get("vulnerabilities", [])

    # Determine highest severity
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        max_severity = "LOW"

    for v in vulnerabilities:
        sev = v.get("severity")
        if sev in severity_order:
            if severity_order.index(sev) > severity_order.index(max_severity):
                max_severity = sev

    merged.append({
        "type": "software",
        "name": software.get("name"),
        "installed_version": software.get("version"),
        "severity": max_severity,
        "risk_score": None,
        "vulnerability_count": len(vulnerabilities),
        "raw": item
    })


    return merged


# --------------------------------------------------
# Prioritization
# --------------------------------------------------

def prioritize_threats(findings):
    severity_rank = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1
    }

    def rank(f):
        sev = str(f.get("severity", "")).lower()
        score = f.get("risk_score", 0)
        return (
            -severity_rank.get(sev, 0),
            -score
        )

    return sorted(findings, key=rank)


# --------------------------------------------------
# Statistics
# --------------------------------------------------


def generate_statistics(aggregated_findings):
    sev_counter = Counter()
    file_count = 0
    software_count = 0

    for item in aggregated_findings:
        severity = item.get("final_severity", "unknown")
        sev_counter[str(severity).lower()] += 1

        if item.get("entity_type") == "file":
            file_count += 1
        elif item.get("entity_type") == "software":
            software_count += 1

    return {
        "total_findings": len(aggregated_findings),
        "total_file_findings": file_count,
        "total_software_findings": software_count,
        "severity_counts": dict(sev_counter)
    }

#=============================================

class TestAggregateFindings(unittest.TestCase):
    def test_aggregation_logic(self):
        sample_findings = [
            # File finding 1 (Medium)
            {
                "type": "script",
                "path": "/etc/shadow",
                "name": "shadow",
                "severity": "Medium",
                "risk_score": 5.0,
                "issues": ["Insecure Permissions"]
            },
            # File finding 2 (Elevates finding 1 to High)
            {
                "type": "executable",
                "path": "/etc/shadow",
                "name": "shadow",
                "severity": "High",
                "risk_score": 8.5,
                "issues": ["Sensitive Data Exposed"]
            },
            # Software finding
            {
                "type": "software",
                "name": "OpenSSL",
                "installed_version": "1.1.1",
                "severity": "Low",
                "vulnerability_count": 2
            },
            # Software finding (Duplicate, updates count)
            {
                "type": "software",
                "name": "OpenSSL",
                "installed_version": "1.1.1",
                "severity": "Critical",
                "vulnerability_count": 1
            }
        ]

        results = aggregate_findings(sample_findings)
        
        
        # # Turn results into a dict for easier lookup in tests
        results_dict = {r.get("path") or f"{r.get('name')}::{r.get('installed_version')}": r for r in results}

        print(results_dict)
        
