from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from tgartifacts.plugins.audit.auditor import Auditor, Finding


@dataclass
class HardenAction:
    finding: Finding
    fixable: bool


@dataclass
class HardenResult:
    applied: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    manual: List[Finding] = field(default_factory=list)


class Hardener:
    def __init__(self, tdata_path: Path):
        self.auditor = Auditor(tdata_path)

    def analyze(self):
        report = self.auditor.audit()
        fixable = [HardenAction(f, True) for f in report.findings if f.auto_fixable]
        manual = [f for f in report.findings if f.remediation and not f.auto_fixable]
        return fixable, manual

    def apply(self, finding: Finding) -> str:
        return self.auditor.apply_fix(finding)
