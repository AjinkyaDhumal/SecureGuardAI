#!/usr/bin/env python3
"""
SecureGuard AI - Pipeline Integration Test

This script tests the complete input pipeline:
    parser.py → fp_filter.py → locator.py

It creates test files and a sample scan report, then runs the full pipeline
and prints the output at each stage.
"""

import json
import tempfile
from pathlib import Path

# Import pipeline modules
from parser import ScanReportParser
from fp_filter import FalsePositiveFilter
from locator import CodeLocator


def create_test_files(tmpdir: Path) -> None:
    """Create test source files for the pipeline."""

    # 1. Production file with SQL injection vulnerability
    app_dir = tmpdir / "app"
    app_dir.mkdir(parents=True, exist_ok=True)

    (app_dir / "database.py").write_text('''"""Database module for user management."""

import sqlite3
from typing import Optional, Dict, Any


class UserDatabase:
    """Handles user database operations."""

    def __init__(self, db_path: str = 'users.db'):
        self.db_path = db_path
        self.conn = None

    def connect(self):
        """Connect to the database."""
        self.conn = sqlite3.connect(self.db_path)
        return self.conn

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID - VULNERABLE to SQL injection!"""
        cursor = self.conn.cursor()

        # Vulnerable SQL query
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)

        row = cursor.fetchone()
        if row:
            return {'id': row[0], 'name': row[1], 'email': row[2]}
        return None
''')

    # 2. Test file (should be filtered as false positive)
    tests_dir = tmpdir / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)

    (tests_dir / "test_database.py").write_text('''"""Test database module."""

import sqlite3

def test_sql_injection():
    """Test SQL injection detection - intentionally vulnerable."""
    user_id = "1; DROP TABLE users;"
    query = f"SELECT * FROM users WHERE id = {user_id}"
    assert "SELECT" in query
''')

    # 3. File with XSS vulnerability
    (app_dir / "views.py").write_text('''"""View handlers."""

from flask import render_template_string, request


def welcome_user():
    """Welcome page - VULNERABLE to XSS!"""
    username = request.args.get('name', 'Guest')

    # Vulnerable to XSS
    template = f"<h1>Welcome, {username}!</h1>"
    return render_template_string(template)


def safe_welcome():
    """Safe welcome page."""
    from markupsafe import escape
    username = request.args.get('name', 'Guest')

    # Safe - properly escaped
    return f"<h1>Welcome, {escape(username)}!</h1>"
''')

    # 4. Mock file (should be filtered)
    mocks_dir = tmpdir / "mocks"
    mocks_dir.mkdir(parents=True, exist_ok=True)

    (mocks_dir / "mock_database.py").write_text('''"""Mock database for testing."""

def mock_query(sql):
    """Mock SQL query - not real."""
    return f"MOCK: {sql}"
''')


def create_test_scan_report() -> dict:
    """Create a sample scan report in generic JSON format."""
    return {
        "scanner": "generic",
        "scan_date": "2024-01-15T10:30:00Z",
        "vulnerabilities": [
            {
                "type": "sql_injection",
                "file": "app/database.py",
                "line": 24,
                "severity": "HIGH",
                "message": "SQL injection vulnerability: user input directly concatenated into SQL query",
                "rule_id": "SEC001"
            },
            {
                "type": "sql_injection",
                "file": "tests/test_database.py",
                "line": 7,
                "severity": "HIGH",
                "message": "SQL injection in test file",
                "rule_id": "SEC001"
            },
            {
                "type": "xss",
                "file": "app/views.py",
                "line": 11,
                "severity": "MEDIUM",
                "message": "Cross-site scripting: user input rendered without escaping",
                "rule_id": "SEC002"
            },
            {
                "type": "sql_injection",
                "file": "mocks/mock_database.py",
                "line": 5,
                "severity": "LOW",
                "message": "Potential SQL injection in mock",
                "rule_id": "SEC001"
            }
        ]
    }


def create_semgrep_report() -> dict:
    """Create a sample Semgrep-format scan report."""
    return {
        "version": "1.0.0",
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-subprocess-use",
                "path": "app/database.py",
                "start": {"line": 24, "col": 8},
                "end": {"line": 24, "col": 60},
                "extra": {
                    "message": "Detected SQL query built using string formatting",
                    "severity": "ERROR",
                    "metadata": {
                        "confidence": "HIGH",
                        "cwe": ["CWE-89"]
                    }
                }
            }
        ]
    }


def run_pipeline_test():
    """Run the complete pipeline test."""

    print("=" * 70)
    print("SecureGuard AI - Pipeline Integration Test")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Step 1: Create test files
        print("\n[Step 1] Creating test files...")
        create_test_files(tmpdir)
        print(f"  Created test files in: {tmpdir}")

        # Step 2: Create scan report
        print("\n[Step 2] Creating scan report...")
        scan_report = create_test_scan_report()
        report_path = tmpdir / "scan_report.json"
        report_path.write_text(json.dumps(scan_report, indent=2))
        print(f"  Created scan report: {report_path}")
        print(f"  Vulnerabilities in report: {len(scan_report['vulnerabilities'])}")

        # Step 3: Parse scan report
        print("\n[Step 3] Parsing scan report...")
        print("-" * 50)
        parser = ScanReportParser()
        vulnerabilities = parser.parse_json(scan_report)

        print(f"  Parsed {len(vulnerabilities)} vulnerabilities:")
        for v in vulnerabilities:
            print(f"    - {v['vuln_type']} in {v['file_path']}:{v['line_number']} ({v['severity']})")

        # Step 4: Filter false positives
        print("\n[Step 4] Filtering false positives...")
        print("-" * 50)
        fp_filter = FalsePositiveFilter(repo_path=str(tmpdir))
        filtered_vulns = fp_filter.filter_vulnerabilities(vulnerabilities)

        print(f"\n  Filtering results:")
        for v in filtered_vulns:
            status = "FILTERED" if v.get('is_false_positive') else "ACTIONABLE"
            print(f"    [{status}] {v['vuln_type']} in {v['file_path']}:{v['line_number']}")
            if v.get('fp_reason'):
                print(f"              Reason: {v['fp_reason']}")

        summary = fp_filter.get_summary()
        print(f"\n  Filter summary: {json.dumps(summary)}")

        # Get actionable vulnerabilities
        actionable = fp_filter.get_actionable(filtered_vulns)
        print(f"\n  Actionable vulnerabilities: {len(actionable)}")

        # Step 5: Locate code context
        print("\n[Step 5] Locating code context...")
        print("-" * 50)
        locator = CodeLocator(repo_path=str(tmpdir))

        final_results = []
        for vuln in actionable:
            located = locator.locate(vuln)
            final_results.append(located)

            print(f"\n  Located: {located['file_path']}:{located['line_number']}")
            print(f"    Vulnerable line: {located.get('vulnerable_line', '')[:50]}...")
            print(f"    Function: {located.get('function_name', 'N/A')}")
            print(f"    Class: {located.get('class_name', 'N/A')}")
            print(f"    Context lines: {located.get('context_start_line')} - {located.get('context_end_line')}")

        # Step 6: Print final output
        print("\n" + "=" * 70)
        print("PIPELINE OUTPUT - Final Results")
        print("=" * 70)

        for i, result in enumerate(final_results, 1):
            print(f"\n--- Vulnerability {i} ---")
            print(f"Type: {result['vuln_type']}")
            print(f"Severity: {result['severity']}")
            print(f"File: {result['file_path']}:{result['line_number']}")
            print(f"Description: {result['description']}")
            print(f"Confidence: {result.get('confidence', 'N/A')}")
            print(f"Recommendation: {result.get('recommendation', 'N/A')}")
            print(f"\nFunction Scope: {result.get('function_scope', 'N/A')}")
            print(f"Class Scope: {result.get('class_scope', 'N/A')}")
            print(f"\nImports: {result.get('imports', [])}")
            print(f"\n--- Code Context ---")
            print(result.get('code_snippet', 'N/A'))

        # Output as JSON for programmatic use
        print("\n" + "=" * 70)
        print("JSON OUTPUT (for programmatic use)")
        print("=" * 70)

        # Create clean output (remove large fields for readability)
        clean_output = []
        for r in final_results:
            clean = {
                'vuln_type': r.get('vuln_type'),
                'severity': r.get('severity'),
                'file_path': r.get('file_path'),
                'line_number': r.get('line_number'),
                'description': r.get('description'),
                'confidence': r.get('confidence'),
                'recommendation': r.get('recommendation'),
                'is_false_positive': r.get('is_false_positive'),
                'function_name': r.get('function_name'),
                'class_name': r.get('class_name'),
                'vulnerable_line': r.get('vulnerable_line'),
                'imports': r.get('imports'),
            }
            clean_output.append(clean)

        print(json.dumps(clean_output, indent=2))

        print("\n" + "=" * 70)
        print("Pipeline test completed successfully!")
        print("=" * 70)

        return final_results


if __name__ == "__main__":
    run_pipeline_test()
