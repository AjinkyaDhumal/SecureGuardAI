"""
SecureGuard AI - Parser Module

This module reads JSON/text scan reports from any SAST tool.
It extracts vulnerability information and normalizes different scanner formats.

Supported Formats:
- Semgrep
- Bandit
- OWASP ZAP
- Custom JSON format

Output Schema:
{
    vuln_type: str,
    file_path: str,
    line_number: int,
    severity: str,
    description: str,
    scanner_id: str
}
"""

import json
import re
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class Vulnerability:
    """Represents a parsed vulnerability finding."""
    vuln_type: str
    file_path: str
    line_number: int
    severity: str
    description: str
    scanner_id: str
    raw_data: Optional[Dict[str, Any]] = None
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        result = {
            'vuln_type': self.vuln_type,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'severity': self.severity,
            'description': self.description,
            'scanner_id': self.scanner_id,
        }
        if self.end_line:
            result['end_line'] = self.end_line
        if self.code_snippet:
            result['code_snippet'] = self.code_snippet
        if self.cwe_id:
            result['cwe_id'] = self.cwe_id
        if self.owasp_id:
            result['owasp_id'] = self.owasp_id
        if self.metadata:
            result['metadata'] = self.metadata
        return result


class ScanReportParser:
    """
    Parser for security scan reports from various SAST tools.

    Normalizes different scanner output formats into a common schema:
    {vuln_type, file_path, line_number, severity, description, scanner_id}

    Supported formats:
    - Semgrep JSON output
    - Bandit JSON output
    - Generic/Custom JSON format
    - OWASP ZAP JSON output
    """

    SUPPORTED_FORMATS = ['semgrep', 'bandit', 'owasp_zap', 'snyk', 'custom']

    # Comprehensive vulnerability type mapping
    VULN_TYPE_MAPPING = {
        # SQL Injection patterns
        'sql': 'sql_injection',
        'sqli': 'sql_injection',
        'sql-injection': 'sql_injection',
        'sql_injection': 'sql_injection',
        'database-injection': 'sql_injection',

        # Command Injection patterns
        'command': 'command_injection',
        'cmd': 'command_injection',
        'os-command': 'command_injection',
        'shell': 'command_injection',
        'subprocess': 'command_injection',
        'rce': 'command_injection',
        'remote-code-execution': 'command_injection',

        # XSS patterns
        'xss': 'xss',
        'cross-site-scripting': 'xss',
        'cross_site_scripting': 'xss',
        'reflected-xss': 'xss',
        'stored-xss': 'xss',
        'dom-xss': 'xss',

        # CSRF patterns
        'csrf': 'csrf',
        'cross-site-request-forgery': 'csrf',
        'xsrf': 'csrf',

        # Path Traversal patterns
        'path': 'path_traversal',
        'traversal': 'path_traversal',
        'directory-traversal': 'path_traversal',
        'lfi': 'path_traversal',
        'local-file-inclusion': 'path_traversal',

        # XXE patterns
        'xxe': 'xxe',
        'xml-external-entity': 'xxe',
        'xml-injection': 'xxe',

        # Deserialization patterns
        'deserial': 'insecure_deserialization',
        'pickle': 'insecure_deserialization',
        'yaml-load': 'insecure_deserialization',
        'marshal': 'insecure_deserialization',
        'object-injection': 'insecure_deserialization',

        # Eval/Exec patterns
        'eval': 'insecure_eval',
        'exec': 'insecure_eval',
        'code-injection': 'insecure_eval',
        'dynamic-code': 'insecure_eval',

        # Secrets patterns
        'hardcoded': 'hardcoded_secrets',
        'secret': 'hardcoded_secrets',
        'password': 'hardcoded_secrets',
        'api-key': 'hardcoded_secrets',
        'credential': 'hardcoded_secrets',
        'token': 'hardcoded_secrets',

        # Hashing patterns
        'md5': 'weak_hashing',
        'sha1': 'weak_hashing',
        'weak-hash': 'weak_hashing',
        'insecure-hash': 'weak_hashing',

        # Randomness patterns
        'random': 'weak_randomness',
        'prng': 'weak_randomness',
        'insecure-random': 'weak_randomness',

        # JWT patterns
        'jwt': 'broken_jwt_auth',
        'json-web-token': 'broken_jwt_auth',

        # CORS patterns
        'cors': 'permissive_cors',
        'cross-origin': 'permissive_cors',

        # Debug patterns
        'debug': 'debug_mode_prod',
        'development-mode': 'debug_mode_prod',

        # Redirect patterns
        'redirect': 'open_redirect',
        'open-redirect': 'open_redirect',
        'url-redirect': 'open_redirect',

        # Upload patterns
        'upload': 'arbitrary_file_upload',
        'file-upload': 'arbitrary_file_upload',
        'unrestricted-upload': 'arbitrary_file_upload',

        # Log injection patterns
        'log': 'log_injection',
        'log-injection': 'log_injection',
        'log-forging': 'log_injection',

        # LDAP patterns
        'ldap': 'ldap_injection',
        'ldap-injection': 'ldap_injection',

        # XPath patterns
        'xpath': 'xpath_injection',
        'xpath-injection': 'xpath_injection',

        # Header patterns
        'header': 'missing_security_headers',
        'security-header': 'missing_security_headers',
        'csp': 'missing_security_headers',
        'hsts': 'missing_security_headers',

        # ReDoS patterns
        'redos': 'redos',
        'regex': 'redos',
        'catastrophic-backtracking': 'redos',

        # SSRF patterns
        'ssrf': 'ssrf',
        'server-side-request-forgery': 'ssrf',
    }

    # Severity normalization mapping
    SEVERITY_MAPPING = {
        'critical': 'CRITICAL',
        'crit': 'CRITICAL',
        'high': 'HIGH',
        'error': 'HIGH',
        'severe': 'HIGH',
        'medium': 'MEDIUM',
        'med': 'MEDIUM',
        'moderate': 'MEDIUM',
        'warning': 'MEDIUM',
        'warn': 'MEDIUM',
        'low': 'LOW',
        'info': 'LOW',
        'informational': 'LOW',
        'note': 'LOW',
    }

    def __init__(self, verbose: bool = True):
        """
        Initialize the parser.

        Args:
            verbose: Whether to print parsing progress
        """
        self.vulnerabilities: List[Vulnerability] = []
        self.scanner_type: Optional[str] = None
        self.raw_report: Optional[Dict[str, Any]] = None
        self.verbose = verbose
        self.parse_errors: List[str] = []

    def _log(self, message: str) -> None:
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"[Parser] {message}")

    def parse(self, report_path: str) -> List[Dict[str, Any]]:
        """
        Parse a scan report file.

        Args:
            report_path: Path to the scan report file (JSON or text)

        Returns:
            List of normalized vulnerability dictionaries
        """
        self._log(f"Parsing report: {report_path}")

        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")

        # Read the report
        content = path.read_text(encoding='utf-8')

        # Try to parse as JSON
        try:
            self.raw_report = json.loads(content)
        except json.JSONDecodeError as e:
            self._log(f"JSON parse error: {e}")
            # Handle text format
            return self._parse_text_report(content)

        # Detect scanner type and parse accordingly
        self.scanner_type = self._detect_scanner_type(self.raw_report)
        self._log(f"Detected scanner type: {self.scanner_type}")

        # Parse based on detected format
        parse_methods = {
            'semgrep': self._parse_semgrep,
            'bandit': self._parse_bandit,
            'owasp_zap': self._parse_owasp_zap,
            'snyk': self._parse_snyk,
            'custom': self._parse_custom,
        }

        parser = parse_methods.get(self.scanner_type, self._parse_custom)
        parser(self.raw_report)

        self._log(f"Found {len(self.vulnerabilities)} vulnerabilities")

        if self.parse_errors:
            self._log(f"Parse errors: {len(self.parse_errors)}")

        return [v.to_dict() for v in self.vulnerabilities]

    def parse_json(self, report_data: Union[Dict, List]) -> List[Dict[str, Any]]:
        """
        Parse a scan report from a dictionary/list directly.

        Args:
            report_data: Parsed JSON data (dict or list)

        Returns:
            List of normalized vulnerability dictionaries
        """
        self.raw_report = report_data if isinstance(report_data, dict) else {'results': report_data}
        self.scanner_type = self._detect_scanner_type(self.raw_report)

        parse_methods = {
            'semgrep': self._parse_semgrep,
            'bandit': self._parse_bandit,
            'owasp_zap': self._parse_owasp_zap,
            'snyk': self._parse_snyk,
            'custom': self._parse_custom,
        }

        parser = parse_methods.get(self.scanner_type, self._parse_custom)
        parser(self.raw_report)

        return [v.to_dict() for v in self.vulnerabilities]

    def _detect_scanner_type(self, report: Dict[str, Any]) -> str:
        """
        Detect the scanner type from report structure.

        Args:
            report: Parsed JSON report

        Returns:
            Scanner type identifier
        """
        # Semgrep detection - has 'results' with 'check_id' field
        if 'results' in report and isinstance(report.get('results'), list):
            results = report.get('results', [])
            if results and isinstance(results[0], dict):
                if 'check_id' in results[0]:
                    return 'semgrep'
                if 'rule_id' in results[0] and 'path' in results[0]:
                    return 'semgrep'

        # Bandit detection - has 'results' and 'metrics'
        if 'results' in report and 'metrics' in report:
            results = report.get('results', [])
            if results and isinstance(results[0], dict):
                if 'issue_severity' in results[0] or 'test_id' in results[0]:
                    return 'bandit'

        # Snyk detection
        if 'vulnerabilities' in report and 'packageManager' in report:
            return 'snyk'

        # OWASP ZAP detection
        if 'site' in report or 'alerts' in report:
            return 'owasp_zap'

        # Check for explicit scanner field
        if 'scanner' in report:
            scanner_name = str(report.get('scanner', '')).lower()
            if 'semgrep' in scanner_name:
                return 'semgrep'
            if 'bandit' in scanner_name:
                return 'bandit'
            if 'zap' in scanner_name:
                return 'owasp_zap'

        return 'custom'

    def _parse_semgrep(self, report: Dict[str, Any]) -> None:
        """
        Parse Semgrep format report.

        Semgrep output structure:
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-subprocess-use",
                    "path": "app.py",
                    "start": {"line": 10, "col": 1},
                    "end": {"line": 10, "col": 50},
                    "extra": {
                        "message": "...",
                        "severity": "WARNING",
                        "metadata": {...}
                    }
                }
            ]
        }
        """
        results = report.get('results', [])

        for result in results:
            try:
                check_id = result.get('check_id', result.get('rule_id', ''))

                # Extract metadata
                extra = result.get('extra', {})
                metadata = extra.get('metadata', {})

                # Get CWE/OWASP if available
                cwe_ids = metadata.get('cwe', [])
                cwe_id = cwe_ids[0] if cwe_ids else None
                owasp_ids = metadata.get('owasp', [])
                owasp_id = owasp_ids[0] if owasp_ids else None

                vuln = Vulnerability(
                    vuln_type=self._normalize_vuln_type(check_id),
                    file_path=result.get('path', ''),
                    line_number=result.get('start', {}).get('line', 0),
                    end_line=result.get('end', {}).get('line'),
                    severity=self._normalize_severity(extra.get('severity', 'MEDIUM')),
                    description=extra.get('message', ''),
                    scanner_id=f"semgrep:{check_id}",
                    code_snippet=extra.get('lines', ''),
                    cwe_id=cwe_id,
                    owasp_id=owasp_id,
                    raw_data=result,
                    metadata={
                        'check_id': check_id,
                        'category': metadata.get('category', ''),
                        'confidence': metadata.get('confidence', ''),
                    }
                )
                self.vulnerabilities.append(vuln)
            except Exception as e:
                self.parse_errors.append(f"Semgrep parse error: {e}")

    def _parse_bandit(self, report: Dict[str, Any]) -> None:
        """
        Parse Bandit format report.

        Bandit output structure:
        {
            "results": [
                {
                    "filename": "app.py",
                    "test_id": "B102",
                    "test_name": "exec_used",
                    "issue_severity": "MEDIUM",
                    "issue_confidence": "HIGH",
                    "issue_text": "...",
                    "line_number": 10,
                    "line_range": [10, 11],
                    "code": "..."
                }
            ],
            "metrics": {...}
        }
        """
        results = report.get('results', [])

        for result in results:
            try:
                test_id = result.get('test_id', '')
                test_name = result.get('test_name', '')

                # Combine test_id and test_name for better type detection
                combined_id = f"{test_id}:{test_name}"

                line_range = result.get('line_range', [])
                end_line = line_range[-1] if len(line_range) > 1 else None

                vuln = Vulnerability(
                    vuln_type=self._normalize_vuln_type(combined_id),
                    file_path=result.get('filename', ''),
                    line_number=result.get('line_number', 0),
                    end_line=end_line,
                    severity=self._normalize_severity(result.get('issue_severity', 'MEDIUM')),
                    description=result.get('issue_text', ''),
                    scanner_id=f"bandit:{test_id}",
                    code_snippet=result.get('code', ''),
                    cwe_id=result.get('issue_cwe', {}).get('id') if isinstance(result.get('issue_cwe'), dict) else None,
                    raw_data=result,
                    metadata={
                        'test_id': test_id,
                        'test_name': test_name,
                        'confidence': result.get('issue_confidence', ''),
                    }
                )
                self.vulnerabilities.append(vuln)
            except Exception as e:
                self.parse_errors.append(f"Bandit parse error: {e}")

    def _parse_owasp_zap(self, report: Dict[str, Any]) -> None:
        """Parse OWASP ZAP format report."""
        # Handle different ZAP output formats
        alerts = report.get('alerts', [])

        # Also check for site-based format
        if not alerts and 'site' in report:
            sites = report.get('site', [])
            if isinstance(sites, list):
                for site in sites:
                    alerts.extend(site.get('alerts', []))
            elif isinstance(sites, dict):
                alerts = sites.get('alerts', [])

        for alert in alerts:
            try:
                vuln = Vulnerability(
                    vuln_type=self._normalize_vuln_type(alert.get('name', alert.get('alert', ''))),
                    file_path=alert.get('url', alert.get('uri', '')),
                    line_number=0,  # ZAP doesn't provide line numbers
                    severity=self._normalize_severity(alert.get('riskdesc', alert.get('risk', 'MEDIUM'))),
                    description=alert.get('description', alert.get('desc', '')),
                    scanner_id=f"zap:{alert.get('pluginid', alert.get('pluginId', ''))}",
                    cwe_id=str(alert.get('cweid', '')) if alert.get('cweid') else None,
                    raw_data=alert,
                    metadata={
                        'solution': alert.get('solution', ''),
                        'reference': alert.get('reference', ''),
                        'confidence': alert.get('confidence', ''),
                    }
                )
                self.vulnerabilities.append(vuln)
            except Exception as e:
                self.parse_errors.append(f"ZAP parse error: {e}")

    def _parse_snyk(self, report: Dict[str, Any]) -> None:
        """Parse Snyk format report."""
        vulns = report.get('vulnerabilities', [])

        for item in vulns:
            try:
                vuln = Vulnerability(
                    vuln_type=self._normalize_vuln_type(item.get('title', item.get('id', ''))),
                    file_path=item.get('from', [''])[0] if item.get('from') else '',
                    line_number=0,
                    severity=self._normalize_severity(item.get('severity', 'MEDIUM')),
                    description=item.get('description', ''),
                    scanner_id=f"snyk:{item.get('id', '')}",
                    cwe_id=item.get('identifiers', {}).get('CWE', [''])[0] if item.get('identifiers') else None,
                    raw_data=item,
                    metadata={
                        'package': item.get('packageName', ''),
                        'version': item.get('version', ''),
                        'fixedIn': item.get('fixedIn', []),
                    }
                )
                self.vulnerabilities.append(vuln)
            except Exception as e:
                self.parse_errors.append(f"Snyk parse error: {e}")

    def _parse_custom(self, report: Dict[str, Any]) -> None:
        """
        Parse custom/generic format report.

        Supports multiple common structures:
        - {"vulnerabilities": [...]}
        - {"findings": [...]}
        - {"issues": [...]}
        - {"results": [...]}
        - [...]  (direct list)
        """
        # Try different common keys for vulnerability lists
        vulns = (
            report.get('vulnerabilities') or
            report.get('findings') or
            report.get('issues') or
            report.get('results') or
            []
        )

        # Handle direct list
        if isinstance(report, list):
            vulns = report

        for item in vulns:
            if not isinstance(item, dict):
                continue

            try:
                # Flexible field extraction with fallbacks
                vuln_type = (
                    item.get('vuln_type') or
                    item.get('type') or
                    item.get('rule_id') or
                    item.get('rule') or
                    item.get('name') or
                    item.get('title') or
                    item.get('check_id') or
                    'unknown'
                )

                # Extract file path with fallbacks
                file_path = (
                    item.get('file_path') or
                    item.get('file') or
                    item.get('path') or
                    item.get('filename') or
                    (item.get('location', {}).get('file', '') if isinstance(item.get('location'), dict) else '') or
                    ''
                )

                # Extract line number with fallbacks
                line_number = (
                    item.get('line_number') or
                    item.get('line') or
                    item.get('lineno') or
                    item.get('start_line') or
                    (item.get('location', {}).get('line', 0) if isinstance(item.get('location'), dict) else 0) or
                    0
                )

                severity = (
                    item.get('severity') or
                    item.get('level') or
                    item.get('priority') or
                    item.get('risk') or
                    'MEDIUM'
                )

                description = (
                    item.get('description') or
                    item.get('message') or
                    item.get('msg') or
                    item.get('detail') or
                    item.get('issue_text') or
                    ''
                )

                scanner_id = (
                    item.get('scanner_id') or
                    item.get('id') or
                    item.get('rule_id') or
                    item.get('finding_id') or
                    'custom'
                )

                vuln = Vulnerability(
                    vuln_type=self._normalize_vuln_type(str(vuln_type)),
                    file_path=str(file_path),
                    line_number=int(line_number) if line_number else 0,
                    end_line=item.get('end_line') or item.get('end_lineno'),
                    severity=self._normalize_severity(str(severity)),
                    description=str(description),
                    scanner_id=str(scanner_id),
                    code_snippet=item.get('code') or item.get('snippet') or item.get('code_snippet'),
                    cwe_id=item.get('cwe') or item.get('cwe_id'),
                    owasp_id=item.get('owasp') or item.get('owasp_id'),
                    raw_data=item,
                )
                self.vulnerabilities.append(vuln)
            except Exception as e:
                self.parse_errors.append(f"Custom parse error: {e}")

    def _parse_text_report(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse a text-based report (grep-like output).

        Supports formats like:
        - file.py:10: SQL injection detected
        - [HIGH] file.py:10 - SQL injection

        Args:
            content: Raw text content

        Returns:
            List of vulnerability dictionaries
        """
        self._log("Attempting text format parsing")

        # Common patterns for text-based reports
        patterns = [
            # file:line: message
            r'^(?P<file>[^:]+):(?P<line>\d+):\s*(?P<message>.+)$',
            # [SEVERITY] file:line - message
            r'^\[(?P<severity>\w+)\]\s*(?P<file>[^:]+):(?P<line>\d+)\s*[-:]\s*(?P<message>.+)$',
            # file:line:col: message
            r'^(?P<file>[^:]+):(?P<line>\d+):\d+:\s*(?P<message>.+)$',
        ]

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            for pattern in patterns:
                match = re.match(pattern, line)
                if match:
                    groups = match.groupdict()
                    vuln = Vulnerability(
                        vuln_type=self._normalize_vuln_type(groups.get('message', '')),
                        file_path=groups.get('file', ''),
                        line_number=int(groups.get('line', 0)),
                        severity=self._normalize_severity(groups.get('severity', 'MEDIUM')),
                        description=groups.get('message', ''),
                        scanner_id='text',
                    )
                    self.vulnerabilities.append(vuln)
                    break

        return [v.to_dict() for v in self.vulnerabilities]

    def _normalize_vuln_type(self, raw_type: str) -> str:
        """
        Normalize vulnerability type to standard format.

        Args:
            raw_type: Raw vulnerability type from scanner

        Returns:
            Normalized vulnerability type
        """
        if not raw_type:
            return 'unknown'

        raw_lower = raw_type.lower().strip()

        # Direct match first
        if raw_lower in self.VULN_TYPE_MAPPING:
            return self.VULN_TYPE_MAPPING[raw_lower]

        # Check for pattern matches
        for pattern, normalized in self.VULN_TYPE_MAPPING.items():
            if pattern in raw_lower:
                return normalized

        # Handle Bandit test IDs
        bandit_mapping = {
            'b102': 'insecure_eval',  # exec_used
            'b103': 'insecure_eval',  # set_bad_file_permissions
            'b104': 'hardcoded_secrets',  # hardcoded_bind_all_interfaces
            'b105': 'hardcoded_secrets',  # hardcoded_password_string
            'b106': 'hardcoded_secrets',  # hardcoded_password_funcarg
            'b107': 'hardcoded_secrets',  # hardcoded_password_default
            'b108': 'path_traversal',  # hardcoded_tmp_directory
            'b110': 'insecure_eval',  # try_except_pass
            'b112': 'insecure_eval',  # try_except_continue
            'b301': 'insecure_deserialization',  # pickle
            'b302': 'insecure_deserialization',  # marshal
            'b303': 'weak_hashing',  # md5
            'b304': 'weak_hashing',  # des
            'b305': 'weak_hashing',  # cipher
            'b306': 'weak_hashing',  # mktemp
            'b307': 'insecure_eval',  # eval
            'b308': 'insecure_eval',  # mark_safe
            'b310': 'open_redirect',  # urllib_urlopen
            'b311': 'weak_randomness',  # random
            'b312': 'weak_randomness',  # telnetlib
            'b313': 'xxe',  # xml_bad_cElementTree
            'b314': 'xxe',  # xml_bad_ElementTree
            'b315': 'xxe',  # xml_bad_expatreader
            'b316': 'xxe',  # xml_bad_expatbuilder
            'b317': 'xxe',  # xml_bad_sax
            'b318': 'xxe',  # xml_bad_minidom
            'b319': 'xxe',  # xml_bad_pulldom
            'b320': 'xxe',  # xml_bad_etree
            'b321': 'broken_jwt_auth',  # ftplib
            'b323': 'broken_jwt_auth',  # unverified_context
            'b324': 'weak_hashing',  # hashlib
            'b501': 'broken_jwt_auth',  # request_with_no_cert_validation
            'b502': 'broken_jwt_auth',  # ssl_with_bad_version
            'b503': 'broken_jwt_auth',  # ssl_with_bad_defaults
            'b504': 'broken_jwt_auth',  # ssl_with_no_version
            'b505': 'weak_randomness',  # weak_cryptographic_key
            'b506': 'hardcoded_secrets',  # yaml_load
            'b507': 'broken_jwt_auth',  # ssh_no_host_key_verification
            'b601': 'command_injection',  # paramiko_calls
            'b602': 'command_injection',  # subprocess_popen_with_shell_equals_true
            'b603': 'command_injection',  # subprocess_without_shell_equals_true
            'b604': 'command_injection',  # any_other_function_with_shell_equals_true
            'b605': 'command_injection',  # start_process_with_a_shell
            'b606': 'command_injection',  # start_process_with_no_shell
            'b607': 'command_injection',  # start_process_with_partial_path
            'b608': 'sql_injection',  # hardcoded_sql_expressions
            'b609': 'command_injection',  # linux_commands_wildcard_injection
            'b610': 'command_injection',  # django_extra_used
            'b611': 'command_injection',  # django_rawsql_used
            'b701': 'xss',  # jinja2_autoescape_false
            'b702': 'xss',  # use_of_mako_templates
            'b703': 'xss',  # django_mark_safe
        }

        # Check for Bandit test ID
        for bid, vuln_type in bandit_mapping.items():
            if bid in raw_lower:
                return vuln_type

        # Clean and return as-is if no mapping found
        cleaned = re.sub(r'[^a-z0-9_]', '_', raw_lower)
        cleaned = re.sub(r'_+', '_', cleaned).strip('_')
        return cleaned or 'unknown'

    def _normalize_severity(self, raw_severity: str) -> str:
        """
        Normalize severity to standard format.

        Args:
            raw_severity: Raw severity from scanner

        Returns:
            Normalized severity (CRITICAL, HIGH, MEDIUM, LOW)
        """
        if not raw_severity:
            return 'MEDIUM'

        severity_lower = raw_severity.lower().strip()

        # Handle compound severities like "High (Confirmed)"
        severity_lower = severity_lower.split('(')[0].strip()
        severity_lower = severity_lower.split(' ')[0].strip()

        return self.SEVERITY_MAPPING.get(severity_lower, 'MEDIUM')

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of parsed vulnerabilities.

        Returns:
            Dict with counts by severity and type
        """
        by_severity: Dict[str, int] = {}
        by_type: Dict[str, int] = {}

        for vuln in self.vulnerabilities:
            by_severity[vuln.severity] = by_severity.get(vuln.severity, 0) + 1
            by_type[vuln.vuln_type] = by_type.get(vuln.vuln_type, 0) + 1

        return {
            'total': len(self.vulnerabilities),
            'by_severity': by_severity,
            'by_type': by_type,
            'scanner_type': self.scanner_type,
            'parse_errors': len(self.parse_errors),
        }

    def get_vulnerabilities_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities filtered by severity."""
        return [
            v.to_dict() for v in self.vulnerabilities
            if v.severity == severity.upper()
        ]

    def get_vulnerabilities_by_type(self, vuln_type: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities filtered by type."""
        return [
            v.to_dict() for v in self.vulnerabilities
            if v.vuln_type == vuln_type
        ]


def parse_scan_report(report_path: str, verbose: bool = True) -> List[Dict[str, Any]]:
    """
    Convenience function to parse a scan report.

    Args:
        report_path: Path to the scan report file
        verbose: Whether to print parsing progress

    Returns:
        List of normalized vulnerability dictionaries
    """
    parser = ScanReportParser(verbose=verbose)
    return parser.parse(report_path)


if __name__ == "__main__":
    # Test the parser module
    print("=" * 60)
    print("SecureGuard AI - Parser Module Test")
    print("=" * 60)

    import tempfile
    import os

    # Test 1: Custom/Generic JSON format
    print("\n--- Test 1: Custom JSON Format ---")
    custom_report = {
        "vulnerabilities": [
            {
                "vuln_type": "sql_injection",
                "file_path": "app/database.py",
                "line_number": 42,
                "severity": "HIGH",
                "description": "SQL injection vulnerability via string formatting"
            },
            {
                "vuln_type": "xss",
                "file_path": "app/views.py",
                "line_number": 15,
                "severity": "MEDIUM",
                "description": "Cross-site scripting in template output"
            },
            {
                "vuln_type": "hardcoded_secrets",
                "file_path": "config/settings.py",
                "line_number": 8,
                "severity": "HIGH",
                "description": "Hardcoded API key detected"
            }
        ]
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(custom_report, f)
        custom_path = f.name

    parser = ScanReportParser()
    vulns = parser.parse(custom_path)

    print(f"Parsed {len(vulns)} vulnerabilities:")
    for v in vulns:
        print(f"  - [{v['severity']}] {v['vuln_type']} in {v['file_path']}:{v['line_number']}")
    print(f"Summary: {parser.get_summary()}")
    os.unlink(custom_path)

    # Test 2: Semgrep-like format
    print("\n--- Test 2: Semgrep Format ---")
    semgrep_report = {
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-subprocess-use",
                "path": "app/utils.py",
                "start": {"line": 25, "col": 1},
                "end": {"line": 25, "col": 50},
                "extra": {
                    "message": "Dangerous subprocess use with shell=True",
                    "severity": "WARNING",
                    "metadata": {
                        "cwe": ["CWE-78"],
                        "owasp": ["A03:2021"],
                        "category": "security"
                    },
                    "lines": "subprocess.call(cmd, shell=True)"
                }
            },
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "app/parser.py",
                "start": {"line": 100, "col": 5},
                "end": {"line": 100, "col": 30},
                "extra": {
                    "message": "Detected use of eval() with user input",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-95"],
                        "category": "security"
                    },
                    "lines": "result = eval(user_input)"
                }
            }
        ],
        "errors": [],
        "version": "1.0.0"
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(semgrep_report, f)
        semgrep_path = f.name

    parser2 = ScanReportParser()
    vulns2 = parser2.parse(semgrep_path)

    print(f"Parsed {len(vulns2)} vulnerabilities:")
    for v in vulns2:
        print(f"  - [{v['severity']}] {v['vuln_type']} in {v['file_path']}:{v['line_number']}")
        if v.get('cwe_id'):
            print(f"    CWE: {v['cwe_id']}")
    print(f"Summary: {parser2.get_summary()}")
    os.unlink(semgrep_path)

    # Test 3: Bandit-like format
    print("\n--- Test 3: Bandit Format ---")
    bandit_report = {
        "results": [
            {
                "filename": "app/crypto.py",
                "test_id": "B303",
                "test_name": "md5",
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "issue_text": "Use of insecure MD5 hash function",
                "line_number": 15,
                "line_range": [15, 15],
                "code": "hashlib.md5(password.encode())"
            },
            {
                "filename": "app/shell.py",
                "test_id": "B602",
                "test_name": "subprocess_popen_with_shell_equals_true",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "subprocess call with shell=True",
                "line_number": 42,
                "line_range": [42, 43],
                "code": "subprocess.Popen(cmd, shell=True)"
            }
        ],
        "metrics": {
            "SEVERITY.HIGH": 1,
            "SEVERITY.MEDIUM": 1
        }
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(bandit_report, f)
        bandit_path = f.name

    parser3 = ScanReportParser()
    vulns3 = parser3.parse(bandit_path)

    print(f"Parsed {len(vulns3)} vulnerabilities:")
    for v in vulns3:
        print(f"  - [{v['severity']}] {v['vuln_type']} in {v['file_path']}:{v['line_number']}")
    print(f"Summary: {parser3.get_summary()}")
    os.unlink(bandit_path)

    print("\n" + "=" * 60)
    print("All parser tests completed!")
    print("=" * 60)
