import os
import time
import pytest
from datetime import datetime, timedelta
from pathlib import Path

from tgartifacts.plugins.timeline.analyzer import (
    TimelineAnalyzer, TimelineEvent, TimelineAnomaly, TimelineReport,
    BULK_THRESHOLD_WARNING,
)


class TestTimelineEvent:

    def test_fields(self):
        ts = datetime(2025, 1, 1, 12, 0, 0)
        e = TimelineEvent(timestamp=ts, path='key_datas', event_type='modified', detail='test')
        assert e.timestamp == ts
        assert e.path == 'key_datas'
        assert e.event_type == 'modified'


class TestTimelineAnomaly:

    def test_fields(self):
        a = TimelineAnomaly(severity='WARNING', title='t', detail='d', mitre_id='T1005')
        assert a.severity == 'WARNING'
        assert a.events == []


class TestTimelineAnalyzer:

    def test_collect_events_on_tdata(self, no_pass_tdata):
        analyzer = TimelineAnalyzer(no_pass_tdata)
        events = analyzer.collect_events()
        assert len(events) > 0
        assert all(isinstance(e, TimelineEvent) for e in events)
        timestamps = [e.timestamp for e in events]
        assert timestamps == sorted(timestamps)

    def test_detect_bulk_access(self, tmp_path):
        for i in range(15):
            (tmp_path / f"file_{i}").write_bytes(b"x")
        analyzer = TimelineAnalyzer(tmp_path)
        events = analyzer.collect_events()
        anomalies = analyzer._detect_bulk_access(events)
        assert len(anomalies) >= 1
        assert anomalies[0].mitre_id == 'T1005'

    def test_detect_future_timestamps(self, tmp_path):
        f = tmp_path / "future_file"
        f.write_bytes(b"x")
        future = time.time() + 86400 * 365
        os.utime(f, (future, future))
        analyzer = TimelineAnalyzer(tmp_path)
        events = analyzer.collect_events()
        anomalies = analyzer._detect_timestamp_anomalies(events)
        future_anomalies = [a for a in anomalies if 'Future' in a.title]
        assert len(future_anomalies) == 1
        assert future_anomalies[0].severity == 'CRITICAL'
        assert future_anomalies[0].mitre_id == 'T1070.006'

    def test_detect_key_rotation_with_dict(self):
        accounts = [{'keys_to_destroy': {2: b'\x00' * 256}}]
        analyzer = TimelineAnalyzer(Path('.'), accounts)
        anomalies = analyzer._detect_key_rotation()
        assert len(anomalies) == 1
        assert anomalies[0].mitre_id == 'T1550.004'

    def test_detect_key_rotation_empty(self):
        analyzer = TimelineAnalyzer(Path('.'), [])
        anomalies = analyzer._detect_key_rotation()
        assert anomalies == []

    def test_analyze_returns_report(self, no_pass_tdata):
        analyzer = TimelineAnalyzer(no_pass_tdata)
        report = analyzer.analyze()
        assert isinstance(report, TimelineReport)
        assert report.total_files > 0
        assert report.earliest is not None
        assert report.latest is not None

    def test_no_anomalies_on_normal_dir(self, tmp_path):
        for i in range(3):
            f = tmp_path / f"file_{i}"
            f.write_bytes(b"x")
            os.utime(f, (time.time() - i * 100, time.time() - i * 100))
        analyzer = TimelineAnalyzer(tmp_path)
        report = analyzer.analyze()
        assert report.total_files == 3
        assert len(report.anomalies) == 0
