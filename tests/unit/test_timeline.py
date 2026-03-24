"""UT: Timeline forensic analysis — events, anomalies, analyzer."""

import os
import time
import pytest
from datetime import datetime, timedelta
from pathlib import Path

from tgartifacts.plugins.timeline.analyzer import (
    TimelineAnalyzer, TimelineEvent, TimelineAnomaly, TimelineReport,
    BULK_RULES,
)


class TestTimelineEvent:

    def test_fields(self):
        """TimelineEvent stores timestamp, path, event_type and detail."""
        ts = datetime(2025, 1, 1, 12, 0, 0)
        e = TimelineEvent(timestamp=ts, path='key_datas', event_type='modified', detail='test')
        assert e.timestamp == ts
        assert e.path == 'key_datas'
        assert e.event_type == 'modified'


class TestTimelineAnomaly:

    def test_fields(self):
        """TimelineAnomaly stores severity, title, detail, mitre_id with empty events list."""
        a = TimelineAnomaly(severity='WARNING', title='t', detail='d', mitre_id='T1005')
        assert a.severity == 'WARNING'
        assert a.events == []


class TestTimelineAnalyzer:

    def test_collect_events_on_tdata(self, no_pass_tdata):
        """Collect events from real tdata, sorted by timestamp."""
        analyzer = TimelineAnalyzer(no_pass_tdata)
        events = analyzer.collect_events()
        assert len(events) > 0
        assert all(isinstance(e, TimelineEvent) for e in events)
        timestamps = [e.timestamp for e in events]
        assert timestamps == sorted(timestamps)

    def test_detect_bulk_access_info(self, tmp_path):
        """30 files with same mtime trigger INFO bulk access anomaly (T1005)."""
        for i in range(35):
            (tmp_path / f"file_{i}").write_bytes(b"x")
        analyzer = TimelineAnalyzer(tmp_path)
        events = analyzer.collect_events()
        anomalies = analyzer._detect_bulk_access(events)
        assert len(anomalies) >= 1
        info = [a for a in anomalies if a.severity == 'INFO']
        assert len(info) >= 1
        assert info[0].mitre_id == 'T1005'

    def test_detect_bulk_access_warning(self, tmp_path):
        """100 files within 2s trigger WARNING bulk access anomaly."""
        base = time.time()
        for i in range(110):
            f = tmp_path / f"file_{i}"
            f.write_bytes(b"x")
            os.utime(f, (base, base + (i * 0.01)))
        analyzer = TimelineAnalyzer(tmp_path)
        events = analyzer.collect_events()
        anomalies = analyzer._detect_bulk_access(events)
        warning = [a for a in anomalies if a.severity == 'WARNING']
        assert len(warning) >= 1

    def test_detect_bulk_access_critical(self, tmp_path):
        """1000 files within 5s trigger CRITICAL bulk access anomaly."""
        base = time.time()
        for i in range(1010):
            f = tmp_path / f"file_{i}"
            f.write_bytes(b"x")
            os.utime(f, (base, base + (i * 0.004)))
        analyzer = TimelineAnalyzer(tmp_path)
        events = analyzer.collect_events()
        anomalies = analyzer._detect_bulk_access(events)
        critical = [a for a in anomalies if a.severity == 'CRITICAL']
        assert len(critical) >= 1

    def test_detect_future_timestamps(self, tmp_path):
        """File with future mtime triggers CRITICAL timestomping anomaly (T1070.006)."""
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
        """keys_to_destroy in account info triggers key rotation anomaly (T1550.004)."""
        accounts = [{'keys_to_destroy': {2: b'\x00' * 256}}]
        analyzer = TimelineAnalyzer(Path('.'), accounts)
        anomalies = analyzer._detect_key_rotation()
        assert len(anomalies) == 1
        assert anomalies[0].mitre_id == 'T1550.004'

    def test_detect_key_rotation_empty(self):
        """No accounts produces no key rotation anomalies."""
        analyzer = TimelineAnalyzer(Path('.'), [])
        anomalies = analyzer._detect_key_rotation()
        assert anomalies == []

    def test_analyze_returns_report(self, no_pass_tdata):
        """Full analyze on real tdata returns TimelineReport with files and time range."""
        analyzer = TimelineAnalyzer(no_pass_tdata)
        report = analyzer.analyze()
        assert isinstance(report, TimelineReport)
        assert report.total_files > 0
        assert report.earliest is not None
        assert report.latest is not None

    def test_no_anomalies_on_normal_dir(self, tmp_path):
        """3 files with spread timestamps produce no anomalies."""
        for i in range(3):
            f = tmp_path / f"file_{i}"
            f.write_bytes(b"x")
            os.utime(f, (time.time() - i * 100, time.time() - i * 100))
        analyzer = TimelineAnalyzer(tmp_path)
        report = analyzer.analyze()
        assert report.total_files == 3
        assert len(report.anomalies) == 0
