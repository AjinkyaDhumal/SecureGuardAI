"""
SecureGuard AI - False Positive Filter Module

This module filters false positives before fix attempts.
It evaluates confidence and reachability using heuristics and LLM.

Responsibilities:
- Check if file is a test file
- Detect unreachable code (commented, dead code)
- Validate pattern exists at reported line
- Check if vulnerability is already mitigated
- Deduplicate findings with same root cause
- LLM-based confidence scoring (stub for now)

Output Schema:
{
    ...parser_output,
    is_false_positive: bool,
    fp_reason: str,
    confidence: float
}
"""

import re
import ast
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FilterResult:
    """Result of false positive filtering."""
    is_false_positive: bool
    fp_reason: str
    confidence: float
    recommendation: str  # 'FIX', 'SKIP', 'REVIEW_MANUALLY'
    checks_performed: List[str] = field(default_factory=list)


class FalsePositiveFilter:
    """
    Filters false positives from vulnerability findings.

    Uses a combination of heuristics and LLM evaluation to determine
    if a finding is likely a false positive.

    Checks performed:
    1. Test file detection
    2. Mock/fixture file detection
    3. Commented code detection
    4. Unreachable code detection
    5. Pattern validation (vulnerability exists at line)
    6. Existing mitigation detection
    7. LLM confidence scoring (stub)
    """

    # Confidence threshold for filtering
    CONFIDENCE_THRESHOLD = 0.75

    # Test file patterns
    TEST_FILE_PATTERNS = [
        r'test_.*\.py$',
        r'.*_test\.py$',
        r'.*_tests\.py$',
        r'.*/tests/.*\.py$',
        r'.*/test/.*\.py$',
        r'.*/__tests__/.*',
        r'.*\.test\.(js|ts|jsx|tsx)$',
        r'.*\.spec\.(js|ts|jsx|tsx|py)$',
        r'conftest\.py$',
    ]

    # Mock/fixture file patterns
    MOCK_FILE_PATTERNS = [
        r'mock.*\.py$',
        r'.*mock.*\.py$',
        r'fake.*\.py$',
        r'.*fake.*\.py$',
        r'stub.*\.py$',
        r'.*stub.*\.py$',
        r'fixture.*\.py$',
        r'.*fixture.*\.py$',
        r'dummy.*\.py$',
        r'.*dummy.*\.py$',
        r'.*/__mocks__/.*',
        r'.*/fixtures/.*',
    ]

    # Example/sample file patterns
    # Note: Be specific to avoid matching package names like org.springframework.samples
    EXAMPLE_FILE_PATTERNS = [
        r'example.*\.py$',
        r'.*example.*\.py$',
        r'sample.*\.py$',
        r'.*sample.*\.py$',
        r'demo.*\.py$',
        r'.*demo.*\.py$',
        r'.*/examples/.*',
        r'^samples/.*',  # Only match if samples is at the start of path
        r'.*/samples/[^/]+\.(py|js|ts)$',  # Match files directly in samples dir
    ]

    # Vulnerability-specific patterns to validate
    VULN_PATTERNS = {
        'sql_injection': [
            r'execute\s*\(',
            r'cursor\.',
            r'\.query\s*\(',
            r'f["\'].*SELECT',
            r'f["\'].*INSERT',
            r'f["\'].*UPDATE',
            r'f["\'].*DELETE',
            r'%\s*\(',  # % formatting
            r'\.format\s*\(',
        ],
        'command_injection': [
            r'subprocess\.',
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
            r'shell\s*=\s*True',
            r'Popen\s*\(',
            r'call\s*\(',
            r'check_output\s*\(',
        ],
        'xss': [
            r'render_template_string\s*\(',
            r'Markup\s*\(',
            r'mark_safe\s*\(',
            r'innerHTML',
            r'document\.write\s*\(',
            r'\{\{.*\|safe\}\}',
        ],
        'hardcoded_secrets': [
            r'password\s*=\s*["\']',
            r'api_key\s*=\s*["\']',
            r'secret\s*=\s*["\']',
            r'token\s*=\s*["\']',
            r'AWS_SECRET',
            r'PRIVATE_KEY',
        ],
        'insecure_eval': [
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'compile\s*\(',
        ],
        'insecure_deserialization': [
            r'pickle\.load',
            r'pickle\.loads',
            r'yaml\.load\s*\([^)]*\)',
            r'marshal\.load',
        ],
        'path_traversal': [
            r'open\s*\(',
            r'os\.path\.join',
            r'pathlib',
            r'\.\./',
        ],
        'weak_hashing': [
            r'md5\s*\(',
            r'sha1\s*\(',
            r'hashlib\.md5',
            r'hashlib\.sha1',
        ],
    }

    # Mitigation patterns by vulnerability type
    MITIGATION_PATTERNS = {
        'sql_injection': [
            r'execute\s*\([^,]+,\s*[\(\[]',  # Parameterized query
            r'\.filter\s*\(',  # ORM filter
            r'\.get\s*\(',  # ORM get
            r'cursor\.execute\s*\([^,]+,\s*\(',  # Tuple params
        ],
        'xss': [
            r'html\.escape\s*\(',
            r'markupsafe\.escape\s*\(',
            r'escape\s*\(',
            r'autoescape\s*=\s*True',
            r'bleach\.clean\s*\(',
        ],
        'command_injection': [
            r'shell\s*=\s*False',
            r'shlex\.quote\s*\(',
            r'shlex\.split\s*\(',
            r'subprocess\.run\s*\(\s*\[',  # List args
        ],
        'path_traversal': [
            r'os\.path\.abspath',
            r'os\.path\.realpath',
            r'\.resolve\(\)',
            r'secure_filename\s*\(',
        ],
    }

    def __init__(self, repo_path: str = ".", llm_client=None, verbose: bool = True):
        """
        Initialize the filter.

        Args:
            repo_path: Path to the repository
            llm_client: Optional LLM client for advanced evaluation
            verbose: Whether to print progress
        """
        self.repo_path = Path(repo_path)
        self.llm_client = llm_client
        self.verbose = verbose
        self.filtered_count = 0
        self.passed_count = 0
        self.file_cache: Dict[str, List[str]] = {}

    def _log(self, message: str) -> None:
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"[FP Filter] {message}")

    def _read_file(self, file_path: str) -> Optional[List[str]]:
        """
        Read file content with caching.

        Args:
            file_path: Path to the file

        Returns:
            List of lines or None if file not found
        """
        if file_path in self.file_cache:
            return self.file_cache[file_path]

        full_path = self.repo_path / file_path
        if not full_path.exists():
            return None

        try:
            content = full_path.read_text(encoding='utf-8')
            lines = content.split('\n')
            self.file_cache[file_path] = lines
            return lines
        except Exception:
            return None

    def filter_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        repo_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Filter a list of vulnerabilities for false positives.

        Args:
            vulnerabilities: List of vulnerability dicts from parser
            repo_path: Path to the repository for context

        Returns:
            List of vulnerabilities with FP evaluation added
        """
        if repo_path:
            self.repo_path = Path(repo_path)

        self._log(f"Processing {len(vulnerabilities)} vulnerabilities")

        results = []
        for vuln in vulnerabilities:
            filtered_vuln = self.evaluate(vuln)
            results.append(filtered_vuln)

            if filtered_vuln.get('is_false_positive', False):
                self.filtered_count += 1
            else:
                self.passed_count += 1

        self._log(f"Passed: {self.passed_count}, Filtered: {self.filtered_count}")
        return results

    def evaluate(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single vulnerability for false positive.

        Performs multiple checks:
        1. Test file detection
        2. Mock/fixture file detection
        3. Example/sample file detection
        4. Commented code detection
        5. Unreachable code detection
        6. Pattern validation
        7. Mitigation detection
        8. LLM confidence scoring (stub)

        Args:
            vulnerability: Vulnerability dict from parser

        Returns:
            Vulnerability dict with FP evaluation fields added
        """
        result = vulnerability.copy()
        file_path = vulnerability.get('file_path', '')
        line_number = vulnerability.get('line_number', 0)
        vuln_type = vulnerability.get('vuln_type', '')

        checks_performed = []

        # Check 1: Is this a test file?
        checks_performed.append('test_file_check')
        if self._is_test_file(file_path):
            result.update({
                'is_false_positive': True,
                'fp_reason': 'File is a test file - vulnerabilities in tests are often intentional for testing',
                'confidence': 0.95,
                'recommendation': 'SKIP',
                'checks_performed': checks_performed
            })
            return result

        # Check 2: Is this a mock/fixture file?
        checks_performed.append('mock_file_check')
        if self._is_mock_file(file_path):
            result.update({
                'is_false_positive': True,
                'fp_reason': 'File is a mock/fixture - not production code',
                'confidence': 0.92,
                'recommendation': 'SKIP',
                'checks_performed': checks_performed
            })
            return result

        # Check 3: Is this an example/sample file?
        checks_performed.append('example_file_check')
        if self._is_example_file(file_path):
            result.update({
                'is_false_positive': True,
                'fp_reason': 'File is an example/sample - not production code',
                'confidence': 0.88,
                'recommendation': 'SKIP',
                'checks_performed': checks_performed
            })
            return result

        # Read file for further checks
        lines = self._read_file(file_path)

        if lines is not None and line_number > 0:
            # Check 4: Is the code commented out?
            checks_performed.append('commented_code_check')
            is_commented, comment_type = self._is_commented_code(lines, line_number)
            if is_commented:
                result.update({
                    'is_false_positive': True,
                    'fp_reason': f'Code is commented out ({comment_type})',
                    'confidence': 0.98,
                    'recommendation': 'SKIP',
                    'checks_performed': checks_performed
                })
                return result

            # Check 5: Is the code unreachable?
            checks_performed.append('unreachable_code_check')
            is_unreachable, unreachable_reason = self._is_unreachable_code(lines, line_number)
            if is_unreachable:
                result.update({
                    'is_false_positive': True,
                    'fp_reason': f'Code appears unreachable: {unreachable_reason}',
                    'confidence': 0.85,
                    'recommendation': 'SKIP',
                    'checks_performed': checks_performed
                })
                return result

            # Check 6: Does the vulnerability pattern exist at the line?
            checks_performed.append('pattern_validation')
            pattern_exists = self._validate_pattern_exists(lines, line_number, vuln_type)
            if not pattern_exists:
                result.update({
                    'is_false_positive': True,
                    'fp_reason': f'Vulnerability pattern for {vuln_type} not found at line {line_number}',
                    'confidence': 0.80,
                    'recommendation': 'SKIP',
                    'checks_performed': checks_performed
                })
                return result

            # Check 7: Is there existing mitigation?
            checks_performed.append('mitigation_check')
            mitigation = self._check_mitigation_exists(lines, line_number, vuln_type)
            if mitigation:
                result.update({
                    'is_false_positive': True,
                    'fp_reason': f'Mitigation already exists: {mitigation}',
                    'confidence': 0.85,
                    'recommendation': 'SKIP',
                    'checks_performed': checks_performed
                })
                return result

        # Check 8: LLM confidence scoring (stub)
        checks_performed.append('llm_confidence_stub')
        llm_confidence = self._get_llm_confidence(vulnerability, lines, line_number)

        # Default: Not a false positive, proceed with fix
        result.update({
            'is_false_positive': False,
            'fp_reason': '',
            'confidence': llm_confidence,
            'recommendation': 'FIX' if llm_confidence >= self.CONFIDENCE_THRESHOLD else 'REVIEW_MANUALLY',
            'checks_performed': checks_performed
        })

        return result

    def _is_test_file(self, file_path: str) -> bool:
        """Check if the file is a test file."""
        for pattern in self.TEST_FILE_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False

    def _is_mock_file(self, file_path: str) -> bool:
        """Check if the file is a mock or fixture file."""
        for pattern in self.MOCK_FILE_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False

    def _is_example_file(self, file_path: str) -> bool:
        """Check if the file is an example or sample file."""
        for pattern in self.EXAMPLE_FILE_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False

    def _is_commented_code(self, lines: List[str], line_number: int) -> Tuple[bool, str]:
        """
        Check if the code at the given line is commented out.

        Args:
            lines: List of file lines
            line_number: Target line number (1-indexed)

        Returns:
            Tuple of (is_commented, comment_type)
        """
        if line_number < 1 or line_number > len(lines):
            return False, ''

        line = lines[line_number - 1].strip()

        # Single line comment
        if line.startswith('#'):
            return True, 'single-line comment'

        if line.startswith('//'):
            return True, 'single-line comment (JS/C style)'

        # Check for multi-line string/docstring context
        in_multiline = False
        multiline_char = None

        for i in range(line_number - 1):
            current_line = lines[i]

            # Count triple quotes
            for quote in ['"""', "'''"]:
                count = current_line.count(quote)
                if count % 2 == 1:  # Odd number means toggle
                    if in_multiline and multiline_char == quote:
                        in_multiline = False
                        multiline_char = None
                    elif not in_multiline:
                        in_multiline = True
                        multiline_char = quote

        if in_multiline:
            return True, 'inside docstring/multiline string'

        return False, ''

    def _is_unreachable_code(self, lines: List[str], line_number: int) -> Tuple[bool, str]:
        """
        Check if the code at the given line is unreachable.

        Detects:
        - Code after return/raise/break/continue
        - Code inside if False: blocks
        - Code inside __name__ == "__main__" blocks (for library code)

        Args:
            lines: List of file lines
            line_number: Target line number (1-indexed)

        Returns:
            Tuple of (is_unreachable, reason)
        """
        if line_number < 1 or line_number > len(lines):
            return False, ''

        target_line = lines[line_number - 1]
        target_indent = len(target_line) - len(target_line.lstrip())

        # Check for code after return/raise in same block
        for i in range(line_number - 2, -1, -1):
            prev_line = lines[i].rstrip()
            if not prev_line.strip():
                continue

            prev_indent = len(prev_line) - len(prev_line.lstrip())

            # If we hit a line with less or equal indentation, stop
            if prev_indent < target_indent:
                break

            # Check for control flow statements at same indent level
            if prev_indent == target_indent:
                stripped = prev_line.strip()
                if stripped.startswith(('return ', 'return\n', 'raise ', 'break', 'continue')):
                    return True, f'code after {stripped.split()[0]} statement'

        # Check for if False: or if 0: blocks
        for i in range(line_number - 2, -1, -1):
            prev_line = lines[i].rstrip()
            if not prev_line.strip():
                continue

            prev_indent = len(prev_line) - len(prev_line.lstrip())

            if prev_indent < target_indent:
                stripped = prev_line.strip()
                if re.match(r'if\s+(False|0|None)\s*:', stripped):
                    return True, 'inside "if False:" block'
                break

        return False, ''

    def _validate_pattern_exists(
        self,
        lines: List[str],
        line_number: int,
        vuln_type: str
    ) -> bool:
        """
        Verify the vulnerability pattern exists at or near the reported line.

        Args:
            lines: List of file lines
            line_number: Reported line number (1-indexed)
            vuln_type: Type of vulnerability

        Returns:
            True if pattern appears to exist
        """
        if vuln_type not in self.VULN_PATTERNS:
            # Unknown vulnerability type, assume pattern exists
            return True

        patterns = self.VULN_PATTERNS[vuln_type]

        # Check lines around the reported line (±3 lines)
        start = max(0, line_number - 4)
        end = min(len(lines), line_number + 3)

        context = '\n'.join(lines[start:end])

        for pattern in patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True

        return False

    def _check_mitigation_exists(
        self,
        lines: List[str],
        line_number: int,
        vuln_type: str
    ) -> Optional[str]:
        """
        Check if mitigation already exists for the vulnerability.

        Args:
            lines: List of file lines
            line_number: Reported line number (1-indexed)
            vuln_type: Type of vulnerability

        Returns:
            Mitigation description if found, None otherwise
        """
        if vuln_type not in self.MITIGATION_PATTERNS:
            return None

        patterns = self.MITIGATION_PATTERNS[vuln_type]

        # Check the specific line and surrounding context
        start = max(0, line_number - 4)
        end = min(len(lines), line_number + 3)

        context = '\n'.join(lines[start:end])

        for pattern in patterns:
            match = re.search(pattern, context, re.IGNORECASE)
            if match:
                return f"Found mitigation pattern: {match.group(0)}"

        return None

    def _get_llm_confidence(
        self,
        vulnerability: Dict[str, Any],
        lines: Optional[List[str]],
        line_number: int
    ) -> float:
        """
        Get LLM-based confidence score for the vulnerability.

        This is a stub that returns a heuristic-based score.
        In production, this would call an LLM for evaluation.

        Args:
            vulnerability: Vulnerability dict
            lines: File lines (if available)
            line_number: Target line number

        Returns:
            Confidence score (0.0 to 1.0)
        """
        # Stub implementation - return heuristic-based confidence
        base_confidence = 0.80

        # Adjust based on severity
        severity = vulnerability.get('severity', 'MEDIUM')
        severity_boost = {
            'CRITICAL': 0.10,
            'HIGH': 0.05,
            'MEDIUM': 0.0,
            'LOW': -0.05,
        }
        base_confidence += severity_boost.get(severity, 0)

        # Adjust based on scanner confidence if available
        metadata = vulnerability.get('metadata', {})
        scanner_confidence = metadata.get('confidence', '').upper()
        if scanner_confidence == 'HIGH':
            base_confidence += 0.05
        elif scanner_confidence == 'LOW':
            base_confidence -= 0.10

        # If we have code context, slightly boost confidence
        if lines and line_number > 0:
            base_confidence += 0.02

        # Clamp to valid range
        return max(0.0, min(1.0, base_confidence))

    def deduplicate(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate vulnerabilities with the same root cause.

        Groups by:
        - Same file
        - Same vulnerability type
        - Lines within 10 lines of each other

        Args:
            vulnerabilities: List of vulnerability dicts

        Returns:
            Deduplicated list
        """
        seen: Dict[Tuple, Dict[str, Any]] = {}

        for vuln in vulnerabilities:
            # Create a key based on file, type, and approximate location
            key = (
                vuln.get('file_path', ''),
                vuln.get('vuln_type', ''),
                vuln.get('line_number', 0) // 10  # Group by 10-line blocks
            )

            if key not in seen:
                seen[key] = vuln
            else:
                # Keep the one with higher severity or lower line number
                existing = seen[key]
                severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

                existing_priority = severity_order.get(existing.get('severity', 'MEDIUM'), 2)
                new_priority = severity_order.get(vuln.get('severity', 'MEDIUM'), 2)

                if new_priority < existing_priority:
                    seen[key] = vuln
                elif new_priority == existing_priority:
                    if vuln.get('line_number', 0) < existing.get('line_number', 0):
                        seen[key] = vuln

                self._log(f"Deduplicated: {vuln.get('vuln_type')} at {vuln.get('file_path')}:{vuln.get('line_number')}")

        return list(seen.values())

    def get_actionable(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Get only actionable vulnerabilities (not false positives).

        Args:
            vulnerabilities: List of filtered vulnerability dicts

        Returns:
            List of vulnerabilities that should be fixed
        """
        return [
            v for v in vulnerabilities
            if not v.get('is_false_positive', False)
            and v.get('confidence', 0) >= self.CONFIDENCE_THRESHOLD
        ]

    def get_summary(self) -> Dict[str, Any]:
        """
        Get filtering summary.

        Returns:
            Dict with filtering statistics
        """
        total = self.filtered_count + self.passed_count
        return {
            'total_processed': total,
            'filtered': self.filtered_count,
            'passed': self.passed_count,
            'filter_rate': round(self.filtered_count / total, 2) if total > 0 else 0
        }


def filter_false_positives(
    vulnerabilities: List[Dict[str, Any]],
    repo_path: str = ".",
    verbose: bool = True
) -> List[Dict[str, Any]]:
    """
    Convenience function to filter false positives.

    Args:
        vulnerabilities: List of vulnerability dicts from parser
        repo_path: Path to the repository
        verbose: Whether to print progress

    Returns:
        List of vulnerabilities with FP evaluation
    """
    fp_filter = FalsePositiveFilter(repo_path=repo_path, verbose=verbose)
    return fp_filter.filter_vulnerabilities(vulnerabilities)


if __name__ == "__main__":
    import json
    import tempfile
    import os

    print("=" * 60)
    print("SecureGuard AI - False Positive Filter Test")
    print("=" * 60)

    # Create a temporary directory with test files
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files

        # 1. Production file with vulnerability
        prod_file = Path(tmpdir) / "app" / "database.py"
        prod_file.parent.mkdir(parents=True, exist_ok=True)
        prod_file.write_text('''import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    return cursor.fetchone()
''')

        # 2. Test file with same vulnerability (should be filtered)
        test_file = Path(tmpdir) / "tests" / "test_database.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text('''import sqlite3

def test_get_user():
    # Intentionally vulnerable for testing
    query = f"SELECT * FROM users WHERE id = {user_id}"
    assert query is not None
''')

        # 3. File with commented vulnerability
        commented_file = Path(tmpdir) / "app" / "old_code.py"
        commented_file.write_text('''import sqlite3

def get_user(user_id):
    # Old vulnerable code:
    # query = f"SELECT * FROM users WHERE id = {user_id}"
    # cursor.execute(query)

    # New safe code:
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
''')

        # 4. File with mitigated vulnerability
        mitigated_file = Path(tmpdir) / "app" / "safe_database.py"
        mitigated_file.write_text('''import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Safe parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    return cursor.fetchone()
''')

        # 5. Mock file
        mock_file = Path(tmpdir) / "mocks" / "mock_database.py"
        mock_file.parent.mkdir(parents=True, exist_ok=True)
        mock_file.write_text('''# Mock database for testing
def mock_query(sql):
    return f"MOCK: {sql}"
''')

        # Test vulnerabilities
        test_vulns = [
            {
                'vuln_type': 'sql_injection',
                'file_path': 'app/database.py',
                'line_number': 8,
                'severity': 'HIGH',
                'description': 'SQL injection via f-string'
            },
            {
                'vuln_type': 'sql_injection',
                'file_path': 'tests/test_database.py',
                'line_number': 5,
                'severity': 'HIGH',
                'description': 'SQL injection in test file'
            },
            {
                'vuln_type': 'sql_injection',
                'file_path': 'app/old_code.py',
                'line_number': 5,
                'severity': 'HIGH',
                'description': 'SQL injection (commented out)'
            },
            {
                'vuln_type': 'sql_injection',
                'file_path': 'app/safe_database.py',
                'line_number': 8,
                'severity': 'HIGH',
                'description': 'SQL injection (mitigated)'
            },
            {
                'vuln_type': 'sql_injection',
                'file_path': 'mocks/mock_database.py',
                'line_number': 3,
                'severity': 'MEDIUM',
                'description': 'SQL injection in mock file'
            },
            {
                'vuln_type': 'xss',
                'file_path': 'app/views.py',
                'line_number': 10,
                'severity': 'MEDIUM',
                'description': 'XSS vulnerability (file not found)'
            },
        ]

        # Run filter
        fp_filter = FalsePositiveFilter(repo_path=tmpdir)
        results = fp_filter.filter_vulnerabilities(test_vulns)

        print("\n--- Filtering Results ---")
        for v in results:
            status = "FILTERED" if v.get('is_false_positive') else "ACTIONABLE"
            confidence = v.get('confidence', 0)
            print(f"\n[{status}] {v['vuln_type']} in {v['file_path']}:{v['line_number']}")
            print(f"  Confidence: {confidence:.2f}")
            print(f"  Checks: {', '.join(v.get('checks_performed', []))}")
            if v.get('fp_reason'):
                print(f"  Reason: {v['fp_reason']}")

        print(f"\n--- Summary ---")
        print(json.dumps(fp_filter.get_summary(), indent=2))

        actionable = fp_filter.get_actionable(results)
        print(f"\nActionable vulnerabilities: {len(actionable)}")
        for v in actionable:
            print(f"  - {v['vuln_type']} in {v['file_path']}:{v['line_number']}")

    print("\n" + "=" * 60)
    print("FP Filter tests completed!")
    print("=" * 60)
