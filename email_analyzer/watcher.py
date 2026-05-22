"""
watcher.py (FINAL FIXED + COMMENTED)

Purpose:
- Monitor folder for .eml files
- Process emails safely WITHOUT modifying original files
- Generate reports
"""

import os
import time
import logging
from datetime import datetime

# Import centralized logging
from .main import setup_logging

# Analyzer + Reporter
from .analyzer import analyze_email
from .mail_reporter import MailReporter


# ----------------------------
# Wait until file is stable
# ----------------------------
def wait_until_file_stable(path: str, timeout: int = 30) -> bool:
    """
    Wait until file is fully written (important for OneDrive / Power Automate)
    """
    start = time.time()
    last_size = -1
    stable = 0

    while time.time() - start < timeout:
        if not os.path.exists(path):
            return False

        size = os.path.getsize(path)

        if size == last_size and size > 0:
            stable += 1
            if stable >= 2:
                return True
        else:
            stable = 0
            last_size = size

        time.sleep(1)

    return False


# ----------------------------
# Process Single Email
# ----------------------------
def process_one_eml(eml_path: str, project_root: str, reports_dir: str,
                    processed_dir: str, failed_dir: str):
    """
    Process ONE email:
    - Analyze
    - Generate reports
    - DO NOT move original file (SOC requirement)
    """

    # ✅ Use centralized logging (FIXED)
    setup_logging(project_root, reports_dir)

    logger = logging.getLogger(__name__)

    # ----------------------------
    # Console Pattern Start
    # ----------------------------
    logger.info("==== Email Analyzer started ====")
    logger.info("BOOT - Report log: %s", os.path.join(reports_dir, "email_analysis.log"))
    logger.info("BOOT - Global log: %s", os.path.join(project_root, "logging", "email.log"))

    # ----------------------------
    # Analyze Email
    # ----------------------------
    email_data = analyze_email(eml_path)

    if not email_data:
        logger.warning("Analyzer returned no data for file: %s", eml_path)
        logger.info("==== Email Analyzer finished ====")
        return

    # ----------------------------
    # Generate Reports
    # ----------------------------
    reporter = MailReporter(output_dir=reports_dir)

    logger.info("Generating reports...........")

    try:
        json_report = reporter.generate_json_report(email_data)
        logger.debug("JSON report path: %s", json_report)
        logger.info("JSON report generated:")

        text_report = reporter.generate_text_report(email_data)
        logger.debug("Text report path: %s", text_report)
        logger.info("Text report generated:")

        blocklist = reporter.generate_blocklist(email_data)
        logger.debug("Blocklist path: %s", blocklist)
        logger.info("Blocklist generated:")
        logger.info("Blocklist created:")

    except Exception:
        logger.critical("REPORT GENERATION FAILED", exc_info=True)
        logger.info("==== Email Analyzer finished ====")
        return

    # ----------------------------
    # ✅ IMPORTANT: NO FILE MOVE
    # ----------------------------
    logger.debug("Skipping file move (processing copy only)")

    # ----------------------------
    # Console End
    # ----------------------------
    logger.info("Report log file:")
    logger.info("==== Email Analyzer finished ====")


# ----------------------------
# Parse datetime (used by UI)
# ----------------------------
def parse_dt(value: str, fmt: str = "%Y-%m-%d %H:%M") -> datetime | None:
    try:
        return datetime.strptime(value.strip(), fmt)
    except Exception:
        return None


# ----------------------------
# Run Single Cycle
# ----------------------------
def run_cycle(mode: str,
              inbox_dir: str,
              project_root: str,
              reports_dir: str,
              processed_dir: str,
              failed_dir: str,
              from_dt: datetime | None = None,
              to_dt: datetime | None = None) -> int:
    """
    Process emails based on mode:
    - all
    - newest
    - range
    """

    eml_files = [f for f in os.listdir(inbox_dir) if f.lower().endswith(".eml")]
    if not eml_files:
        return 0

    # Sort newest first
    eml_files.sort(key=lambda fn: os.path.getmtime(os.path.join(inbox_dir, fn)), reverse=True)

    selected_files = []

    if mode == "newest":
        selected_files = [eml_files[0]]

    elif mode == "range":
        if from_dt is None or to_dt is None:
            return 0

        for fn in eml_files:
            full_path = os.path.join(inbox_dir, fn)
            mtime = datetime.fromtimestamp(os.path.getmtime(full_path))

            if from_dt <= mtime <= to_dt:
                selected_files.append(fn)
    else:
        selected_files = eml_files

    count = 0

    for fn in selected_files:
        full_path = os.path.join(inbox_dir, fn)

        if not wait_until_file_stable(full_path):
            logging.getLogger(__name__).warning("File not stable yet: %s", full_path)
            continue

        process_one_eml(full_path, project_root, reports_dir, processed_dir, failed_dir)
        count += 1

    return count


# ----------------------------
# Watcher Loop
# ----------------------------
def watch_folder():
    """
    Continuous watcher loop
    """

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    inbox_dir = os.path.join(project_root, "data", "Sample Email")
    reports_dir = os.path.join(project_root, "reports")

    os.makedirs(inbox_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    # ✅ FIXED logging call
    setup_logging(project_root, reports_dir)

    logger = logging.getLogger("WATCHER")
    logger.info("Watcher running. Inbox: %s", inbox_dir)

    seen = set()

    while True:
        try:
            emls = [f for f in os.listdir(inbox_dir) if f.lower().endswith(".eml")]

            for f in emls:
                full_path = os.path.join(inbox_dir, f)

                if full_path in seen:
                    continue

                if not wait_until_file_stable(full_path):
                    logger.warning("File not stable yet: %s", full_path)
                    continue

                process_one_eml(full_path, project_root, reports_dir, None, None)
                seen.add(full_path)

        except Exception:
            logger.critical("Watcher loop error", exc_info=True)

        time.sleep(5)


# ----------------------------
# Entry Point
# ----------------------------
if __name__ == "__main__":
    watch_folder()
