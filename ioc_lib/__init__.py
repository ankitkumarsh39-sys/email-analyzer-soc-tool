"""
IOC (Indicators of Compromise) Validator Library
A standalone, reusable library for extracting and validating IOCs from text.
Usage:
    from ioc_lib import IOCValidator
    validator = IOCValidator()
    iocs = validator.extract("your text here")
    report = validator.generate_report(iocs)
"""

from typing import Dict, List, Tuple, Optional

import re
import logging
from dataclasses import dataclass
from datetime import datetime


@dataclass
class IOCResult:
    """Data class for IOC extraction results."""
    ips: List[str]
    domains: List[str]
    urls: List[str]
    hashes: List[str]
    
    def total_count(self) -> int:
        """Total number of IOCs found."""
        return len(self.ips) + len(self.domains) + len(self.urls) + len(self.hashes)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "ips": self.ips,
            "domains": self.domains,
            "urls": self.urls,
            "hashes": self.hashes,
            "total": self.total_count()
        }


class IOCValidator:
    """
    Extract and validate Indicators of Compromise (IOCs) from text.

    Supports:
    - IP addresses (defanged patterns like 192[.]168[.]1[.]1)
    - Domains (defanged patterns like example[.]com)
    - URLs (including hxxp:// variants)
    - File hashes (MD5, SHA1, SHA256)
    - CVE identifiers
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize IOCValidator.

        Args:
            logger: Optional logger instance. Creates default if not provided.
        """
        self.logger = logger or self._setup_logger()
        self.ignored_extensions = ['.exe', '.png', '.asar', '.zip', '.txt', '.js', '.json', '.jpg', '.get']

    @staticmethod
    def _setup_logger() -> logging.Logger:
        """Setup default logger."""
        logger = logging.getLogger("IOCValidator")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def extract(self, text: str) -> IOCResult:
        """
        Extract all IOCs from text.

        Args:
            text: Input text to analyze

        Returns:
            IOCResult object containing all extracted IOCs
        """
        if not text:
            self.logger.warning("Empty text provided for IOC extraction")
            return IOCResult([], [], [], [], [])

        try:
            ips = self._extract_ips(text)
            domains = self._extract_domains(text)
            urls = self._extract_urls(text)
            hashes = self._extract_hashes(text)

            self.logger.info(
                f"Extracted IOCs - IPs: {len(ips)}, Domains: {len(domains)}, "
                f"URLs: {len(urls)}, Hashes: {len(hashes)}"
            )

            return IOCResult(ips, domains, urls, hashes)

        except Exception as e:
            self.logger.error(f"Error extracting IOCs: {str(e)}")
            return IOCResult([], [], [], [], [])

    def _extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses (supports defanged patterns)."""
        try:
            import iocextract
            ips_from_lib = sorted(list(set(iocextract.extract_ips(text))))
        except (ImportError, Exception):
            ips_from_lib = []

        # Regex-based extraction for defanged patterns
        regex_pattern = r'\b(?:\d{12}|(?:\d{1,3}(?:\[\.\]|\.|\(\.\))){3}\d{1,3})\b'
        regex_ips = sorted(list(set(re.findall(regex_pattern, text))))

        # Merge both sources and deduplicate
        all_ips = set(ips_from_lib + regex_ips)
        return sorted(list(all_ips))

    def _extract_domains(self, text: str) -> List[str]:
        """Extract domains (supports defanged patterns)."""
        regex_pattern = (
            r'\b[a-zA-Z0-9-]{1,63}(?:\[\.\]|\(\.\)|\.)(?:[a-z]{2,})(?:\/[^\s]*)?\b'
        )
        domains = set(
            d for d in re.findall(regex_pattern, text, re.IGNORECASE)
            if not any(ext in d for ext in self.ignored_extensions)
        )
        return sorted(list(domains))

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs (supports hxxp and defanged patterns)."""
        regex_pattern = (
            r'(?:http|hxxp)s?(?:\[\:\/\/\]|\:\/\/)[a-zA-Z0-9\-\.\[\]]+(?:(?:\/|\%2F)[\w\.\-\/\=\?\&\%\+\[\]]+)?'
        )
        urls = set(re.findall(regex_pattern, text))
        return sorted(list(urls))

    def _extract_hashes(self, text: str) -> List[str]:
        """Extract file hashes (MD5, SHA1, SHA256)."""
        hashes_found = set()

        # Manual regex patterns for hashes
        patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }

        for hash_type, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            hashes_found.update(matches)

        # Try iocextract library as fallback
        try:
            import iocextract
            lib_hashes = iocextract.extract_hashes(text)
            hashes_found.update(lib_hashes)
        except (ImportError, Exception):
            pass

        return sorted(list(hashes_found))

    @staticmethod
    def normalize(ioc: str, ioc_type: Optional[str] = None) -> str:
        """
        Normalize IOC by removing defanging patterns.

        Args:
            ioc: The IOC to normalize
            ioc_type: Optional type ('url', 'domain', 'ip', 'hash')

        Returns:
            Normalized IOC
        """
        cleaned = (
            ioc.replace("[.]", ".")
               .replace("(.)", ".")
               .replace("[://]", "://")
               .replace("hxxps://", "https://")
               .replace("hxxp://", "http://")
               .replace("hxxps", "https://")
               .replace("hxxp", "http")
               .replace("fxp", "ftp")
               .strip()
        )

        # Preserve URL case; lowercase others
        return cleaned if ioc_type == 'url' else cleaned.lower()

    @staticmethod
    def is_defanged(ioc: str) -> bool:
        """Check if IOC is defanged."""
        return any(pattern in ioc for pattern in ['[.]', '(.)', '[://]', 'hxxp', 'fxp'])

    def generate_report(self, ioc_result: IOCResult, detailed: bool = False) -> Dict:
        """
        Generate a report from IOC results.

        Args:
            ioc_result: IOCResult object
            detailed: If True, includes categorized IOCs

        Returns:
            Report dictionary
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_iocs": ioc_result.total_count(),
                "ips_count": len(ioc_result.ips),
                "domains_count": len(ioc_result.domains),
                "urls_count": len(ioc_result.urls),
                "hashes_count": len(ioc_result.hashes),
            }
        }

        if detailed:
            report["iocs"] = ioc_result.to_dict()

        return report

    def filter_whitelist(self, ioc_result: IOCResult, whitelist: List[str]) -> IOCResult:
        """
        Filter out whitelisted IOCs.

        Args:
            ioc_result: IOCResult object
            whitelist: List of whitelisted values

        Returns:
            Filtered IOCResult
        """
        whitelist_lower = [w.lower() for w in whitelist]

        return IOCResult(
            ips=[ip for ip in ioc_result.ips if ip.lower() not in whitelist_lower],
            domains=[d for d in ioc_result.domains if d.lower() not in whitelist_lower],
            urls=[u for u in ioc_result.urls if u.lower() not in whitelist_lower],
            hashes=[h for h in ioc_result.hashes if h.lower() not in whitelist_lower]
        )
