from dataclasses import dataclass, field
from typing import List, Optional

from .MTPAuthorization import MTPAuthorization


@dataclass
class Account:
    mtp_data: MTPAuthorization
    account_dir: str
    files: List[str] = field(default_factory=list)

    @property
    def user_id(self) -> int:
        return self.mtp_data.user_id

    @property
    def dc_id(self) -> int:
        return self.mtp_data.dc_id

    @property
    def files_count(self) -> int:
        return len(self.files)
