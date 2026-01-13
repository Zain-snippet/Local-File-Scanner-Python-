# main.py

from module6_analysis_engine import run_full_scan
from module7_report_generator import (
    generate_text_report,
    save_report
)
from module8_config_manager import load_config
from module10_shared_utils import log_message

import os
from datetime import datetime


def main():

    print(">>> main() started")
    log_message("INFO", "Starting Local Security Vulnerability Scanner")

    # --------------------------------------------------
    # 1. Load configuration (STATIC, SAFE)
    # --------------------------------------------------
    CONFIG_PATH = "C:\\Users\\jahan\\Downloads\\Scanner\\config.json"
    
    config_path = "config.json"

    if not os.path.exists(config_path):
        log_message(
        "ERROR",
        "Config.json path not discovered. "
        "Please check the path according to your PC."
        )
        return

    config = load_config(config_path)

    
    config = load_config(CONFIG_PATH)

    log_message("INFO", f"Loaded config: {config}")

    # --------------------------------------------------
    # 2. Run full scan (CORE PIPELINE)
    # --------------------------------------------------
    COMMAND_DB = [
        "powershell -enc",
        "invoke-webrequest",
        "wget",
        "curl",
        "bitsadmin"
    ]

    try:
        scan_result = run_full_scan(config, COMMAND_DB)
    except Exception as e:
        log_message("ERROR", f"Scan failed: {e}")
        return

    log_message("INFO", "Scan completed successfully")

    # --------------------------------------------------
    # 3. Generate TEXT report ONLY
    # --------------------------------------------------
    report_data = generate_text_report(scan_result)
    ext = "txt"

    # --------------------------------------------------
    # 4. Save report
    # --------------------------------------------------
    timestamp = datetime.now().strftime("%d%m%Y_%H%M%S")
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)

    scan_paths = scan_result.get("scan_config", {}).get("scan_paths", [])

    if len(scan_paths) == 1:
        base = os.path.basename(os.path.normpath(scan_paths[0])) or "scan"
    else:
        base = "multi-path"

    report_filename = f"{base}_scan_{timestamp}.{ext}"
    report_path = os.path.join(report_dir, report_filename)

    if save_report(report_data, report_path):
        log_message("INFO", f"Report saved at: {report_path}")
    else:
        log_message("ERROR", "Failed to save report")

    # --------------------------------------------------
    # 5. Console summary
    # --------------------------------------------------
    print("\n=== SCAN SUMMARY ===")
    print(scan_result.get("summary", "No summary available"))
    print("====================\n")


if __name__ == "__main__":
    main()
