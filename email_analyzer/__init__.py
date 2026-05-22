"""
Email Analyzer Module
"""

from .analyzer import analyze_email
from .mail_reporter import MailReporter

__version__ = "1.0.0"
__all__ = ["analyze_email", "MailReporter"]
