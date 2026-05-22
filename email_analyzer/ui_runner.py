"""
UI Runner (Enhanced WITHOUT removing existing features)

Added:
- Report preview panel
- IOC table view
- Highlight suspicious IOCs
- Open latest report in Notepad
"""

import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
import logging
import subprocess
import json

from .watcher import run_cycle
from .main import setup_logging


DT_FMT = "%Y-%m-%d %H:%M"


# ----------------------------
# UI Log Handler (EXISTING FEATURE)
# ----------------------------
class TextBoxHandler(logging.Handler):
    """
    Sends logs to UI textbox (existing feature preserved)
    """
    def __init__(self, textbox):
        super().__init__()
        self.textbox = textbox

    def emit(self, record):
        msg = self.format(record)
        self.textbox.after(0, self._append, msg)

    def _append(self, msg):
        self.textbox.insert(tk.END, msg + "\n")
        self.textbox.see(tk.END)


class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Email Analyzer - UI Runner")
        self.geometry("1000x700")

        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        self.inbox_var = tk.StringVar(value=os.path.join(self.project_root, "data", "Sample Email"))
        self.reports_var = tk.StringVar(value=os.path.join(self.project_root, "reports"))

        self.mode_var = tk.StringVar(value="all")
        self.from_var = tk.StringVar()
        self.to_var = tk.StringVar()

        self._build()

    # ----------------------------
    # UI Layout (ALL EXISTING + NEW ADDED BELOW)
    # ----------------------------
    def _build(self):
        pad = {"padx": 8, "pady": 5}

        # ----------------------------
        # Project Title (CENTER)
        # ----------------------------
        title_label = ttk.Label(
            self,
            text="Email Analyzer - SOC Security Tool",
            font=("Arial", 16, "bold"),
            anchor="center"
        )

        title_label.grid(row=0, column=0, columnspan=3, pady=10)

        # EXISTING UI (UNCHANGED)
        ttk.Label(self, text="Inbox Folder").grid(row=0, column=0, **pad)
        ttk.Entry(self, textvariable=self.inbox_var, width=60).grid(row=0, column=1, **pad)
        ttk.Button(self, text="Browse", command=self.browse_inbox).grid(row=0, column=2)

        ttk.Label(self, text="Reports Folder").grid(row=1, column=0, **pad)
        ttk.Entry(self, textvariable=self.reports_var, width=60).grid(row=1, column=1, **pad)
        ttk.Button(self, text="Browse", command=self.browse_reports).grid(row=1, column=2)

        # ----------------------------
        # Mode Selection (ADD HERE)
        # ----------------------------
        ttk.Label(self, text="Mode").grid(row=2, column=0, sticky="w", padx=8, pady=5)

        mode_frame = ttk.Frame(self)
        mode_frame.grid(row=2, column=1, sticky="w")

        ttk.Radiobutton(mode_frame, text="All", variable=self.mode_var, value="all", command=self.on_mode).pack(side="left", padx=5)
        ttk.Radiobutton(mode_frame, text="Newest", variable=self.mode_var, value="newest", command=self.on_mode).pack(side="left", padx=5)
        ttk.Radiobutton(mode_frame, text="Range", variable=self.mode_var, value="range", command=self.on_mode).pack(side="left", padx=5)


        # ----------------------------
        # Date-Time Inputs (ADD HERE)
        # ----------------------------
        ttk.Label(self, text=f"From ({DT_FMT})").grid(row=3, column=0, sticky="w", padx=8, pady=5)
        self.from_entry = ttk.Entry(self, textvariable=self.from_var, width=25)
        self.from_entry.grid(row=3, column=1, sticky="w", padx=8, pady=5)

        ttk.Label(self, text=f"To ({DT_FMT})").grid(row=4, column=0, sticky="w", padx=8, pady=5)
        self.to_entry = ttk.Entry(self, textvariable=self.to_var, width=25)
        self.to_entry.grid(row=4, column=1, sticky="w", padx=8, pady=5)

        # Buttons (ONLY updated open_latest behavior)
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=2, column=1, sticky="w")

        ttk.Button(btn_frame, text="Start", command=self.start).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Open Reports", command=self.open_reports).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Open Latest Report", command=self.open_latest_report).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Exit", command=self.destroy).pack(side="left", padx=5)

        # EXISTING LOG BOX (UNCHANGED)
        ttk.Label(self, text="Logs").grid(row=3, column=0, sticky="w")
        self.log_box = tk.Text(self, height=10, width=120)
        self.log_box.grid(row=4, column=0, columnspan=3, padx=10, pady=5)

        # ----------------------------
        # ✅ NEW: REPORT PREVIEW (ADDED)
        # ----------------------------
        ttk.Label(self, text="Report Preview").grid(row=5, column=0, sticky="w")
        self.preview_box = tk.Text(self, height=10, width=120)
        self.preview_box.grid(row=6, column=0, columnspan=3, padx=10, pady=5)

        
        # ----------------------------
        # ✅ NEW: IOC TABLE (ADDED)
        # ----------------------------
        ttk.Label(self, text="IOC Table").grid(row=7, column=0, sticky="w")

        columns = ("Type", "Value", "Risk")
        self.ioc_table = ttk.Treeview(self, columns=columns, show="headings", height=10)

        for col in columns:
            self.ioc_table.heading(col, text=col)
            self.ioc_table.column(col, width=320)

        self.ioc_table.grid(row=8, column=0, columnspan=3, padx=15, pady=5)

        # Highlight styling
        self.ioc_table.tag_configure("high", background="red")

        # ----------------------------
        # Footer
        # ----------------------------
        footer = ttk.Label(
            self,
            text="Developed for SOC Automation | Email Threat Analysis Tool",
            font=("Arial", 9),
            foreground="gray"
        )

        footer.grid(row=99, column=0, columnspan=3, pady=10)


    def on_mode(self):
        
        """
        Enable/Disable date fields depending on mode
        """
        mode = self.mode_var.get()

        state = "normal" if mode == "range" else "disabled"

        self.from_entry.configure(state=state)
        self.to_entry.configure(state=state)

    # ----------------------------
    # EXISTING METHODS (UNCHANGED)
    # ----------------------------
    def browse_inbox(self):
        path = filedialog.askdirectory()
        if path:
            self.inbox_var.set(path)

    def browse_reports(self):
        path = filedialog.askdirectory()
        if path:
            self.reports_var.set(path)

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    # ----------------------------
    # BACKGROUND EXECUTION
    # ----------------------------
    def _run(self):
        try:
            setup_logging(self.project_root, self.reports_var.get())

            # Attach UI logs (existing behavior)
            ui_handler = TextBoxHandler(self.log_box)
            ui_handler.setFormatter(logging.Formatter("%(message)s"))
            logging.getLogger().addHandler(ui_handler)

            # Run processing
            mode = self.mode_var.get()

            from_dt = None
            to_dt = None

            # Handle range mode
            if mode == "range":
                try:
                    from_dt = datetime.strptime(self.from_var.get(), DT_FMT)
                    to_dt = datetime.strptime(self.to_var.get(), DT_FMT)
                except Exception:
                    logging.error("Invalid datetime format")
                    return

            # Run watcher with correct inputs
            run_cycle(
                mode,
                self.inbox_var.get(),
                self.project_root,
                self.reports_var.get(),
                None,
                None,
                from_dt=from_dt,
                to_dt=to_dt
            )


            # ✅ Load report into UI AFTER processing
            self.load_latest_report()

        except Exception as e:
            logging.exception(f"UI failed: {e}")

    # ----------------------------
    # ✅ NEW: LOAD REPORT INTO UI
    # ----------------------------
    def load_latest_report(self):
        """
        Loads latest JSON report into:
        - Preview panel
        - IOC table
        """
        reports_dir = self.reports_var.get()

        files = [
            os.path.join(reports_dir, f)
            for f in os.listdir(reports_dir)
            if f.endswith(".json")
        ]

        if not files:
            return

        latest = max(files, key=os.path.getmtime)

        with open(latest, "r", encoding="utf-8") as f:
            data = json.load(f)

        # ✅ Preview (first part of report)
        self.preview_box.delete("1.0", tk.END)
        self.preview_box.insert(tk.END, json.dumps(data, indent=2)[:1500])

        # ✅ Populate IOC table
        self.populate_ioc_table(data)

    # ----------------------------
    # ✅ NEW: IOC TABLE POPULATION
    # ----------------------------
    def populate_ioc_table(self, data):
        """
        Extract IOCs and display in table with highlighting
        """
        for row in self.ioc_table.get_children():
            self.ioc_table.delete(row)

        iocs = data.get("iocs", {})

        for ioc_type, values in iocs.items():
            for val in values:
                risk = self.classify_risk(val)

                row_id = self.ioc_table.insert("", "end", values=(ioc_type, val, risk))

                # Highlight HIGH risk
                if risk == "HIGH":
                    self.ioc_table.item(row_id, tags=("high",))

    def classify_risk(self, value):
        """
        Simple risk logic (can upgrade later)
        """
        keywords = ["login", "verify", "update", "bank", "secure"]

        for k in keywords:
            if k in value.lower():
                return "HIGH"

        return "LOW"

    # ----------------------------
    # EXISTING: OPEN REPORTS FOLDER
    # ----------------------------
    def open_reports(self):
        subprocess.Popen(f'explorer "{self.reports_var.get()}"')

    # ----------------------------
    # ✅ UPDATED: OPEN IN NOTEPAD
    # ----------------------------
    def open_latest_report(self):
        """
        Opens latest report in NOTEPAD (updated behavior)
        """
        reports_dir = self.reports_var.get()

        files = [
            os.path.join(reports_dir, f)
            for f in os.listdir(reports_dir)
            if f.endswith(".json") or f.endswith(".txt")
        ]

        if not files:
            messagebox.showinfo("Info", "No reports found")
            return

        latest = max(files, key=os.path.getmtime)

        # ✅ Force open in Notepad
        subprocess.Popen(["notepad.exe", latest])


# ----------------------------
# RUN UI
# ----------------------------
if __name__ == "__main__":
    App().mainloop()
