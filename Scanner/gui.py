import tkinter as tk
from tkinter import filedialog, messagebox
import os
from datetime import datetime

from module6_analysis_engine import run_full_scan
from module7_report_generator import generate_text_report, save_report
from module8_config_manager import load_config


COMMAND_DB = [
    "powershell -enc",
    "invoke-webrequest",
    "wget",
    "curl",
    "bitsadmin"
]

CONFIG_PATH = "config.json"


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Local Security Vulnerability Scanner")
        self.root.geometry("800x520")

        self.selected_path = None
        self.status_var = tk.StringVar(value="Status: Idle")

        # ---- Select Folder ----
        tk.Button(
            root,
            text="Select Folder",
            command=self.select_folder
        ).pack(pady=5)

        # ---- Selected Path Display ----
        self.path_label = tk.Label(
            root,
            text="No folder selected",
            fg="gray"
        )
        self.path_label.pack(pady=3)

        # ---- Run Scan ----
        self.scan_btn = tk.Button(
            root,
            text="Run Scan",
            command=self.run_scan
        )
        self.scan_btn.pack(pady=5)

        # ---- Status ----
        tk.Label(
            root,
            textvariable=self.status_var
        ).pack(pady=5)

        # ---- Output ----
        self.output = tk.Text(root, height=20, width=90)
        self.output.pack(padx=10, pady=10)

    # --------------------------------------------------

    def select_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.selected_path = path
            self.path_label.config(text=f"Selected: {path}", fg="black")
            self.output.insert(tk.END, f"Selected path: {path}\n")

    # --------------------------------------------------

    def run_scan(self):
        if not self.selected_path:
            messagebox.showwarning("Missing input", "Please select a folder to scan.")
            return

        # ---- UI LOCK ----
        self.scan_btn.config(state=tk.DISABLED)
        self.status_var.set("Status: Scanning...")
        self.output.insert(tk.END, "Starting scan...\n")
        self.root.update()

        try:
            # ---- Load config ----
            config = load_config(CONFIG_PATH)
            config["scan_paths"] = [self.selected_path]

            # ---- Run scan ----
            scan_result = run_full_scan(config, COMMAND_DB)

            # ---- Generate TEXT report only ----
            report = generate_text_report(scan_result)

            # ---- Display report ----
            self.output.insert(tk.END, "\n=== SCAN RESULT ===\n")
            self.output.insert(tk.END, report + "\n")

            # ---- Save report ----
            os.makedirs("reports", exist_ok=True)

            folder_name = os.path.basename(os.path.normpath(self.selected_path))
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{folder_name}_scan_{timestamp}.txt"
            filepath = os.path.join("reports", filename)

            save_report(report, filepath)

            self.output.insert(
                tk.END,
                f"\n[Report saved to: {filepath}]\n"
            )

            self.status_var.set("Status: Completed")

        except Exception as e:
            self.output.insert(tk.END, f"\n[ERROR] {e}\n")
            self.status_var.set("Status: Failed")

        finally:
            self.scan_btn.config(state=tk.NORMAL)


# --------------------------------------------------

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()
