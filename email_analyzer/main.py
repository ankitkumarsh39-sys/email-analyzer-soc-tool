#!/usr/bin/env python3

"""
Email Analyzer - Main Entry Point

Run:
    py -m email_analyzer.main

This module:
1. Sets up centralized logging (console + file)
2. Handles input (.eml file OR folder)
3. Creates a SAFE working copy (no original file modification)
4. Runs analysis
5. Generates reports
"""

import os
import sys
import argparse
import logging
import warnings
import shutil
import pandas as pd
from datetime import datetime


# ----------------------------
# Console Output Control
# ----------------------------
# Defines EXACT allowed console messages (SOC clean format)
BANNER_PREFIXES = (
    "==== Email Analyzer started ====",
    "BOOT - Report log:",
    "BOOT - Global log:",
    "========== Analyze request started ==========",
    "Parsing email from file",
    "============================ IOC_REPORT:",
    "========== Analyze request completed successfully ==========",
    "Generating reports...........",
    "JSON report generated:",
    "Text report generated:",
    "Blocklist generated:",
    "Blocklist created:",
    "Report log file:",
    "==== Email Analyzer finished ====",
)

class ConsoleOnlyFilter(logging.Filter):
    """
    Ensures ONLY important SOC messages appear on console.
    All detailed logs go to file logs.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()

        if msg.startswith(BANNER_PREFIXES):
            return True

        if "Hidden HTML elements detected" in msg:
            return True
        if "IOC counts:" in msg:
            return True
        if "Total IOCs classified" in msg:
            return True
        if "No .eml files found" in msg:
            return True

        return False

class SimpleConsoleFormatter(logging.Formatter):
    """
    Clean console formatter (no timestamps)
    """
    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()

        if msg.startswith(BANNER_PREFIXES):
            return msg

        return f"{record.levelname} - {record.name} - {msg}"


# ----------------------------
# Logging Setup
# ----------------------------
def setup_logging(project_root: str, reports_dir: str) -> str:
    """
    Setup logging:
    - reports/email_analysis.log
    - logging/email.log
    - clean console output
    """

    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(os.path.join(project_root, "logging"), exist_ok=True)

    global_log = os.path.join(project_root, "logging", "email.log")
    report_log = os.path.join(reports_dir, "email_analysis.log")

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Remove old handlers (important for reuse)
    for h in list(root.handlers):
        root.removeHandler(h)

    # Detailed file logging format
    file_fmt = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(name)s - %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    # Global log
    fh_global = logging.FileHandler(global_log, encoding="utf-8")
    fh_global.setLevel(logging.DEBUG)
    fh_global.setFormatter(file_fmt)
    root.addHandler(fh_global)

    # Report log
    fh_report = logging.FileHandler(report_log, encoding="utf-8")
    fh_report.setLevel(logging.DEBUG)
    fh_report.setFormatter(file_fmt)
    root.addHandler(fh_report)

    # Console handler (clean SOC format)
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(SimpleConsoleFormatter())
    sh.addFilter(ConsoleOnlyFilter())
    root.addHandler(sh)

    # Redirect Python warnings to logs
    def showwarning(message, category, filename, lineno, file=None, line=None):
        logging.getLogger("WARNINGS").warning(
            "%s:%s: %s: %s", filename, lineno, category.__name__, message
        )

    warnings.showwarning = showwarning
    
    # Boot messages (exact format required)
    boot = logging.getLogger("BOOT")
    boot.info("==== Email Analyzer started ====")
    boot.info("BOOT - Report log: %s", report_log)
    boot.info("BOOT - Global log: %s", global_log)

# ----------------------------
# Input Resolver
# ----------------------------
def resolve_input(input_path: str) -> str:
    """
    Resolves input:
    - If file → return it
    - If folder → pick newest .eml
    """

    if os.path.isfile(input_path) and input_path.lower().endswith(".eml"):
        return input_path

    if os.path.isdir(input_path):
        eml_files = [
            os.path.join(input_path, f)
            for f in os.listdir(input_path)
            if f.lower().endswith(".eml")
        ]

        if not eml_files:
            logging.getLogger(__name__).warning("No .eml files found in folder")
            return None

        return max(eml_files, key=os.path.getmtime)

    raise ValueError("Invalid input path")


# ----------------------------
# Working Copy Creator
# ----------------------------
def create_working_copy(eml_file: str, project_root: str) -> str:
    """
    Create a SAFE copy of email file.

    Why:
    - Preserve original evidence (SOC best practice)
    - Avoid accidental modification
    """

    working_dir = os.path.join(project_root, "data", "Processed")
    os.makedirs(working_dir, exist_ok=True)

    base_name = os.path.basename(eml_file)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    new_file = f"{timestamp}_{base_name}"
    dest_path = os.path.join(working_dir, new_file)

    shutil.copy2(eml_file, dest_path)

    logging.getLogger(__name__).debug("Working copy created: %s", dest_path)

    return dest_path


# ----------------------------
# Main Function
# ----------------------------
def main():
    """
    Main workflow:
    1. Setup logging
    2. Resolve input
    3. Create working copy
    4. Analyze email
    5. Generate reports
    """

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    parser = argparse.ArgumentParser(description="Email Analyzer")
    parser.add_argument(
        "input_path",
        nargs="?",
        default=os.path.join(project_root, "data", "Sample Email"),
        help="Path to .eml file or folder",
    )
    parser.add_argument(
        "--reports",
        default=os.path.join(project_root, "reports"),
        help="Reports directory",
    )

    args = parser.parse_args()

    report_log = setup_logging(project_root, args.reports)

    # Import AFTER logging setup
    from .analyzer import analyze_email
    from .mail_reporter import MailReporter

    logger = logging.getLogger(__name__)

    logger.info("========== Analyze request started ==========")

    try:
        eml_file = resolve_input(args.input_path)

        # If no file found → exit cleanly
        if not eml_file:
            logging.getLogger("BOOT").info("==== Email Analyzer finished ====")
            return

        # Create safe working copy
        working_file = create_working_copy(eml_file, project_root)

        logger.info("Parsing email from file '%s'", working_file)

        # Run analysis on copied 
        
        email_data = analyze_email(working_file)

        # ✅ SAFETY CHECK (CRITICAL FIX)
        if not email_data:
            logger.error("Email parsing failed → likely malformed .eml or empty content")

            print("❌ Invalid or malformed .eml file detected.")
            print("👉 Analysis skipped. No report generated.")

            logging.getLogger("BOOT").info("==== Email Analyzer finished ====")
            return

        logger.info("========== Analyze request completed successfully ==========")

    except Exception:
        logger.exception("Analysis failed")
        logging.getLogger("BOOT").info("==== Email Analyzer finished ====\n")
        return
    

    reporter = MailReporter(output_dir=args.reports)

    logger.info("Generating reports...........")

    try:
        # ✅ JSON
        json_path = reporter.generate_json_report(email_data)
        logger.debug("JSON report path: %s", json_path)
        logger.info("JSON report generated:")

        # ✅ TXT
        txt_path = reporter.generate_text_report(email_data)
        logger.debug("Text report path: %s", txt_path)
        logger.info("Text report generated:")

        # ✅ BLOCKLIST (EXCEL DB)
        # ✅ Update config DB
        reporter.update_config_blocklist_excel(email_data)

        # ✅ Generate blocklist report file
        blocklist_path = reporter.generate_blocklist_report(email_data)

        logger.debug("Blocklist path: %s", blocklist_path)
        logger.info("Blocklist generated:")
        logger.info("Blocklist created:")

    except Exception:
        logger.critical("REPORT GENERATION FAILED", exc_info=True)
        raise

    logger.info("Report log file:")
    logger.debug("Report log path: %s", report_log)

    logger.info("==== Email Analyzer finished ====")


# ----------------------------
# Entry Point
# ----------------------------
if __name__ == "__main__":
    main()
