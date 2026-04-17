"""
Tests for the parser module.
"""

import pytest
import json
import tempfile
from pathlib import Path

from parser import ScanReportParser, parse_scan_report


class TestScanReportParser:
    """Tests for ScanReportParser class."""

    def test_parse_custom_format(self, tmp_path):
        """Test parsing custom JSON format."""
        report = {
            "vulnerabilities": [
                {
                    "vuln_type": "sql_injection",
                    "file_path": "app/db.py",
                    "line_number": 10,
                    "severity": "HIGH",
                    "description": "SQL injection detected"
                }
            ]
        }

        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(report))

        parser = ScanReportParser()
        vulns = parser.parse(str(report_file))

        assert len(vulns) == 1
        assert vulns[0]['vuln_type'] == 'sql_injection'
        assert vulns[0]['file_path'] == 'app/db.py'
        assert vulns[0]['line_number'] == 10

    def test_normalize_severity(self):
        """Test severity normalization."""
        parser = ScanReportParser()

        assert parser._normalize_severity('HIGH') == 'HIGH'
        assert parser._normalize_severity('high') == 'HIGH'
        assert parser._normalize_severity('CRITICAL') == 'CRITICAL'
        assert parser._normalize_severity('ERROR') == 'HIGH'
        assert parser._normalize_severity('WARNING') == 'MEDIUM'
        assert parser._normalize_severity('INFO') == 'LOW'

    def test_normalize_vuln_type(self):
        """Test vulnerability type normalization."""
        parser = ScanReportParser()

        assert parser._normalize_vuln_type('sql-injection') == 'sql_injection'
        assert parser._normalize_vuln_type('SQLi') == 'sql_injection'
        assert parser._normalize_vuln_type('XSS') == 'xss'
        assert parser._normalize_vuln_type('command-injection') == 'command_injection'

    def test_file_not_found(self):
        """Test handling of missing file."""
        parser = ScanReportParser()

        with pytest.raises(FileNotFoundError):
            parser.parse('/nonexistent/report.json')


def test_parse_scan_report_convenience(tmp_path):
    """Test the convenience function."""
    report = {
        "vulnerabilities": [
            {"vuln_type": "xss", "file_path": "app.py", "line_number": 5}
        ]
    }

    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(report))

    vulns = parse_scan_report(str(report_file))

    assert len(vulns) == 1
    assert vulns[0]['vuln_type'] == 'xss'
