#!/usr/bin/env python3
"""
SecureGuard AI - Output Pipeline Integration Test

Tests the complete output pipeline:
1. validator.py - Run pytest and return structured results
2. patch_generator.py - Generate unified diff using difflib
3. reporter.py - Generate Markdown report

This test verifies that all components work together correctly.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from validator import FixValidator, validate_fix, ValidationStatus
from patch_generator import PatchGenerator, generate_patch
from reporter import ReportGenerator, generate_report, ReportConfig


def test_complete_pipeline():
    """Test the complete output pipeline with a sample vulnerability."""

    print("=" * 70)
    print("SecureGuard AI - Output Pipeline Integration Test")
    print("=" * 70)

    # Sample vulnerability
    vulnerability = {
        'vuln_type': 'sql_injection',
        'file_path': 'app/database.py',
        'line_number': 8,
        'severity': 'HIGH',
        'description': 'SQL injection vulnerability: user input is directly concatenated into SQL query without sanitization.',
        'code_snippet': '''def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    return cursor.fetchone()''',
        'scanner': 'semgrep',
        'rule_id': 'python.lang.security.audit.sqli'
    }

    # Original code
    original_code = '''import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    return cursor.fetchone()
'''

    # Fixed code
    fixed_code = '''import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Fixed: Using parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    return cursor.fetchone()
'''

    # =========================================================================
    # STEP 1: Validate the fix
    # =========================================================================
    print("\n" + "=" * 70)
    print("STEP 1: Validating Fix")
    print("=" * 70)

    validator = FixValidator(verbose=True)
    result = validator.validate(vulnerability, fixed_code)

    print(f"\nValidation Result:")
    print(f"  Status: {result.get('status')}")
    print(f"  Syntax Valid: {result.get('syntax_valid')}")
    print(f"  Tests Passed: {result.get('tests_passed', 0)}")
    print(f"  Tests Failed: {result.get('tests_failed', 0)}")

    # Add fix to result
    result['proposed_fix'] = fixed_code
    result['fix'] = fixed_code

    # =========================================================================
    # STEP 2: Generate patch
    # =========================================================================
    print("\n" + "=" * 70)
    print("STEP 2: Generating Patch")
    print("=" * 70)

    patch_gen = PatchGenerator(output_dir="output/pipeline_test", verbose=True)
    result = patch_gen.generate(result, original_code, fixed_code)

    print(f"\nPatch Result:")
    print(f"  Patch File: {result.get('patch_file_path')}")
    print(f"  Lines Added: +{result.get('lines_added', 0)}")
    print(f"  Lines Removed: -{result.get('lines_removed', 0)}")

    # Verify patch is valid git diff
    verification = patch_gen.verify_patch(result.get('diff_text', ''))
    print(f"  Valid Git Diff: {verification['valid']}")
    if not verification['valid']:
        print(f"  Issues: {verification['issues']}")

    # =========================================================================
    # STEP 3: Generate report
    # =========================================================================
    print("\n" + "=" * 70)
    print("STEP 3: Generating Report")
    print("=" * 70)

    # Add reasoning chain for the report
    result['reasoning_chain'] = [
        "Identified SQL injection vulnerability in get_user function",
        "User input (user_id) is directly interpolated into SQL query",
        "Applied parameterized query pattern using ? placeholder",
        "Passed user_id as tuple parameter to cursor.execute()",
        "Verified fix maintains original functionality"
    ]

    reporter = ReportGenerator(output_dir="output/pipeline_test", verbose=True)
    result = reporter.generate(result)

    print(f"\nReport Result:")
    print(f"  Report File: {result.get('report_file_path')}")
    print(f"  Summary: {result.get('summary')}")

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "=" * 70)
    print("PIPELINE SUMMARY")
    print("=" * 70)

    print(f"""
Vulnerability: {result.get('vuln_type')} in {result.get('file_path')}
Severity: {result.get('severity')}

Validation:
  - Status: {result.get('status')}
  - Syntax Valid: {result.get('syntax_valid')}
  - Tests: {result.get('tests_passed', 0)} passed, {result.get('tests_failed', 0)} failed

Patch:
  - File: {result.get('patch_filename')}
  - Changes: +{result.get('lines_added', 0)} -{result.get('lines_removed', 0)} lines
  - Valid Git Diff: {verification['valid']}

Report:
  - File: {result.get('report_filename')}
  - Summary: {result.get('summary')}
""")

    # Show the diff
    print("=" * 70)
    print("GENERATED DIFF")
    print("=" * 70)
    print(result.get('diff_text', 'No diff generated'))

    print("\n" + "=" * 70)
    print("Pipeline test completed successfully!")
    print("=" * 70)

    return result


def test_batch_processing():
    """Test batch processing of multiple vulnerabilities."""

    print("\n" + "=" * 70)
    print("BATCH PROCESSING TEST")
    print("=" * 70)

    vulnerabilities = [
        {
            'vuln_type': 'sql_injection',
            'file_path': 'app/users.py',
            'line_number': 15,
            'severity': 'HIGH',
            'status': 'VERIFIED',
            'tests_passed': 5,
            'tests_failed': 0
        },
        {
            'vuln_type': 'xss',
            'file_path': 'app/views.py',
            'line_number': 42,
            'severity': 'MEDIUM',
            'status': 'VERIFIED',
            'tests_passed': 3,
            'tests_failed': 0
        },
        {
            'vuln_type': 'hardcoded_secrets',
            'file_path': 'config/settings.py',
            'line_number': 8,
            'severity': 'CRITICAL',
            'status': 'UNVERIFIED',
            'tests_passed': 2,
            'tests_failed': 1,
            'is_false_positive': False
        }
    ]

    reporter = ReportGenerator(output_dir="output/pipeline_test", verbose=True)
    summary_path = reporter.generate_summary_report(vulnerabilities)

    print(f"\nSummary report generated: {summary_path}")

    # Read and display summary
    with open(summary_path, 'r') as f:
        print("\n" + f.read())


if __name__ == "__main__":
    # Run pipeline test
    result = test_complete_pipeline()

    # Run batch processing test
    test_batch_processing()
