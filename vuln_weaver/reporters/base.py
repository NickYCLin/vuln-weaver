from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union
from vuln_weaver.models import ScanReport, DiffReport


class BaseReporter(ABC):
    """Abstract base class for report generators."""

    @abstractmethod
    def generate(self, report: ScanReport, output_path: Union[str, Path], **kwargs) -> Path:
        """Generate formatted report document."""
        pass

    @abstractmethod
    def generate_diff(self, diff_report: DiffReport, output_path: Union[str, Path], **kwargs) -> Path:
        """Generate formatted diff/re-scan document."""
        pass
