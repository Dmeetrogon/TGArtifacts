import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class TimelineEvent:
    timestamp: datetime
    path: str
    event_type: str
    detail: str


@dataclass
class TimelineAnomaly:
    severity: str
    title: str
    detail: str
    mitre_id: str
    events: List[TimelineEvent] = field(default_factory=list)


@dataclass
class TimelineReport:
    tdata_path: Path
    events: List[TimelineEvent]
    anomalies: List[TimelineAnomaly]
    earliest: Optional[datetime]
    latest: Optional[datetime]
    total_files: int


BULK_RULES = [
    {'count': 1000, 'window': 5, 'severity': 'CRITICAL', 'title': 'Mass file access detected'},
    {'count': 100, 'window': 2, 'severity': 'WARNING', 'title': 'Bulk file access detected'},
    {'count': 30, 'window': 1, 'severity': 'INFO', 'title': 'Elevated file access detected'},
]


class TimelineAnalyzer:
    def __init__(self, tdata_path: Path, accounts: Optional[list] = None):
        self.tdata_path = Path(tdata_path)
        self.accounts = accounts or []

    def collect_events(self) -> List[TimelineEvent]:
        events = []
        for path in self.tdata_path.rglob('*'):
            if not path.is_file():
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            rel = str(path.relative_to(self.tdata_path))
            events.append(TimelineEvent(
                timestamp=datetime.fromtimestamp(st.st_mtime),
                path=rel,
                event_type='modified',
                detail=f'{path.name} ({st.st_size} bytes)',
            ))
        return sorted(events, key=lambda e: e.timestamp)

    def detect_anomalies(self, events: List[TimelineEvent]) -> List[TimelineAnomaly]:
        anomalies = []
        anomalies.extend(self._detect_bulk_access(events))
        anomalies.extend(self._detect_timestamp_anomalies(events))
        anomalies.extend(self._detect_key_rotation())
        return anomalies

    def _detect_bulk_access(self, events: List[TimelineEvent]) -> List[TimelineAnomaly]:
        if not events:
            return []

        anomalies = []
        reported_ranges = set()

        for rule in BULK_RULES:
            threshold = rule['count']
            window = rule['window']
            severity = rule['severity']
            title = rule['title']

            timestamps = [e.timestamp.timestamp() for e in events]

            left = 0
            for right in range(len(timestamps)):
                while timestamps[right] - timestamps[left] > window:
                    left += 1

                count = right - left + 1
                if count >= threshold:
                    range_key = (int(timestamps[left]), severity)
                    if range_key not in reported_ranges:
                        reported_ranges.add(range_key)
                        group = events[left:right + 1]
                        anomalies.append(TimelineAnomaly(
                            severity=severity,
                            title=title,
                            detail=f'{count} files modified within {window}s at '
                                   f'{group[0].timestamp:%Y-%m-%d %H:%M:%S} — possible bulk exfiltration',
                            mitre_id='T1005',
                            events=group,
                        ))

        return anomalies

    def _detect_timestamp_anomalies(self, events: List[TimelineEvent]) -> List[TimelineAnomaly]:
        now = datetime.now()
        anomalies = []
        future_events = [e for e in events if e.timestamp > now]
        if future_events:
            anomalies.append(TimelineAnomaly(
                severity='CRITICAL',
                title='Future timestamps detected',
                detail=f'{len(future_events)} file(s) have modification time in the future — '
                       f'possible timestomping',
                mitre_id='T1070.006',
                events=future_events,
            ))

        round_events = []
        for e in events:
            ts = e.timestamp.timestamp()
            if ts % 3600 == 0 and ts > 0:
                round_events.append(e)
        if len(round_events) >= 3:
            anomalies.append(TimelineAnomaly(
                severity='WARNING',
                title='Suspiciously round timestamps',
                detail=f'{len(round_events)} file(s) have timestamps exactly on the hour — '
                       f'possible timestamp manipulation',
                mitre_id='T1070.006',
                events=round_events,
            ))

        return anomalies

    def _detect_key_rotation(self) -> List[TimelineAnomaly]:
        anomalies = []
        for acc in self.accounts:
            keys_to_destroy = {}
            if hasattr(acc, 'keys_to_destroy'):
                keys_to_destroy = acc.keys_to_destroy
            elif isinstance(acc, dict):
                keys_to_destroy = acc.get('keys_to_destroy', {})

            if keys_to_destroy:
                import hashlib
                details = []
                for dc_id, key in keys_to_destroy.items():
                    key_id = hashlib.sha1(key).digest()[-8:].hex()
                    details.append(f'DC {dc_id}: auth_key_id {key_id}')

                anomalies.append(TimelineAnomaly(
                    severity='WARNING',
                    title='Revoked session keys found',
                    detail=f'{len(keys_to_destroy)} key(s) pending destruction — '
                           f'possible session compromise or legitimate re-login',
                    mitre_id='T1550.004',
                ))
        return anomalies

    def analyze(self) -> TimelineReport:
        events = self.collect_events()
        anomalies = self.detect_anomalies(events)
        return TimelineReport(
            tdata_path=self.tdata_path,
            events=events,
            anomalies=anomalies,
            earliest=events[0].timestamp if events else None,
            latest=events[-1].timestamp if events else None,
            total_files=len(events),
        )
