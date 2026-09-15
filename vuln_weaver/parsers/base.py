from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union
from vuln_weaver.models import ScanReport


class BaseParser(ABC):
    """Abstract base class for all vulnerability scan parsers."""

    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """Return the scanner identifier (e.g., 'nessus', 'nmap', 'zap')."""
        pass

    @abstractmethod
    def parse(self, file_path: Union[str, Path]) -> ScanReport:
        """Parse raw scan file and return normalized ScanReport object."""
        pass
