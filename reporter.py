"""
SecureGuard AI - Reporter Module

This module generates Markdown reports for vulnerabilities and fixes.
Reports include vulnerability explanation, fix reasoning, test validation, and OWASP references.

Responsibilities:
- Generate Markdown report per vulnerability
- Include vulnerability explanation
- Include fix reasoning (why the fix works)
- Include test results (passed/failed/output)
- Include before/after code comparison
- Add OWASP references
- Generate summary reports for batch processing

Output Schema:
{
    ...patch_output,
    report_file_path: str,
    report_filename: str,
    summary: str
}
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
import json


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    include_owasp: bool = True
    include_recommendations: bool = True
    include_diff: bool = True
    include_test_output: bool = True
    max_test_output_lines: int = 50
    max_code_lines: int = 100


# OWASP Top 10 2021 references
OWASP_REFERENCES = {
    'sql_injection': {
        'id': 'A03:2021',
        'name': 'Injection',
        'url': 'https://owasp.org/Top10/A03_2021-Injection/'
    },
    'command_injection': {
        'id': 'A03:2021',
        'name': 'Injection',
        'url': 'https://owasp.org/Top10/A03_2021-Injection/'
    },
    'xss': {
        'id': 'A03:2021',
        'name': 'Injection',
        'url': 'https://owasp.org/Top10/A03_2021-Injection/'
    },
    'broken_jwt_auth': {
        'id': 'A07:2021',
        'name': 'Identification and Authentication Failures',
        'url': 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
    },
    'hardcoded_secrets': {
        'id': 'A02:2021',
        'name': 'Cryptographic Failures',
        'url': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
    },
    'weak_hashing': {
        'id': 'A02:2021',
        'name': 'Cryptographic Failures',
        'url': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
    },
    'insecure_deserialization': {
        'id': 'A08:2021',
        'name': 'Software and Data Integrity Failures',
        'url': 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
    },
    'path_traversal': {
        'id': 'A01:2021',
        'name': 'Broken Access Control',
        'url': 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
    },
    'xxe': {
        'id': 'A05:2021',
        'name': 'Security Misconfiguration',
        'url': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    },
    'debug_mode_prod': {
        'id': 'A05:2021',
        'name': 'Security Misconfiguration',
        'url': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    },
}


class ReportGenerator:
    """
    Generates Markdown reports for vulnerability fixes.
    
    Creates detailed reports with:
    - Vulnerability explanation
    - Fix reasoning (why the fix works)
    - Test results (passed/failed/output)
    - Before/after code comparison
    - OWASP references
    """
    
    def __init__(self, output_dir: str = "output", config: Optional[ReportConfig] = None, verbose: bool = True):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory to write report files
            config: Optional ReportConfig for customization
            verbose: Whether to print status messages
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or ReportConfig()
        self.verbose = verbose
    
    def generate(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a Markdown report for a vulnerability fix.
        
        Args:
            vulnerability: Vulnerability dict with all pipeline data
            
        Returns:
            Vulnerability dict with report info added
        """
        result = vulnerability.copy()
        
        vuln_type = vulnerability.get('vuln_type', 'unknown')
        file_path = vulnerability.get('file_path', 'unknown')
        
        if self.verbose:
            print(f"[Reporter] Generating report for: {vuln_type} in {file_path}")
        
        # Generate report content
        report_content = self._build_report(vulnerability)
        
        # Generate report filename
        report_filename = self._generate_report_filename(vulnerability)
        report_path = self.output_dir / report_filename
        
        # Write report file
        try:
            report_path.write_text(report_content, encoding='utf-8')
            if self.verbose:
                print(f"[Reporter] ✓ Wrote report: {report_path}")
        except Exception as e:
            if self.verbose:
                print(f"[Reporter] ✗ Error writing report: {e}")
            result.update({
                'report_file_path': None,
                'summary': self._generate_summary(vulnerability),
                'report_error': str(e)
            })
            return result
        
        result.update({
            'report_file_path': str(report_path),
            'report_filename': report_filename,
            'summary': self._generate_summary(vulnerability)
        })
        
        return result
    
    def _build_report(self, vulnerability: Dict[str, Any]) -> str:
        """
        Build the full Markdown report content.
        
        Args:
            vulnerability: Vulnerability dict
            
        Returns:
            Markdown report string
        """
        vuln_type = vulnerability.get('vuln_type', 'unknown')
        file_path = vulnerability.get('file_path', 'unknown')
        line_number = vulnerability.get('line_number', 0)
        severity = vulnerability.get('severity', 'UNKNOWN')
        description = vulnerability.get('description', 'No description')
        status = vulnerability.get('status', 'UNKNOWN')
        
        # Get fix and original code
        original_code = vulnerability.get('code_snippet', '') or vulnerability.get('code', 'Code not available')
        fixed_code = vulnerability.get('proposed_fix', '') or vulnerability.get('fix', 'Fix not available')
        
        # Get test results
        tests_passed = vulnerability.get('tests_passed', 0)
        tests_failed = vulnerability.get('tests_failed', 0)
        tests_total = vulnerability.get('tests_total', tests_passed + tests_failed)
        test_output = vulnerability.get('test_output', 'No test output available')
        
        # Truncate test output if needed
        if len(test_output) > 2000:
            test_output = test_output[:2000] + "\n... (truncated)"
        
        # Get reasoning chain if available
        reasoning_chain = vulnerability.get('reasoning_chain', [])
        
        # Get OWASP reference
        owasp = OWASP_REFERENCES.get(vuln_type, {
            'id': 'N/A',
            'name': 'Not classified',
            'url': 'https://owasp.org/Top10/'
        })
        
        # Build status badge
        status_emoji = "✅" if status in ['VERIFIED', 'FIXED'] else "⚠️" if status == 'SYNTAX_ONLY' else "❌"
        
        report = f"""# Security Vulnerability Fix Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Status:** {status_emoji} {status}

---

## 📋 Summary

| Field | Value |
|-------|-------|
| **Vulnerability Type** | {vuln_type.replace('_', ' ').title()} |
| **File** | `{file_path}` |
| **Line** | {line_number} |
| **Severity** | {severity} |
| **Status** | {status} |

---

## 🔍 Vulnerability Details

### Description

{description}

"""
        
        # Add OWASP reference if enabled
        if self.config.include_owasp:
            report += f"""### OWASP Reference

- **Category:** {owasp['id']} - {owasp['name']}
- **More Info:** [{owasp['url']}]({owasp['url']})

"""
        
        report += f"""---

## 💻 Code Analysis

### Original Code (Vulnerable)

```python
{original_code}
```

### Fixed Code

```python
{fixed_code}
```

---

## 🧠 Fix Reasoning

{self._get_fix_explanation(vulnerability)}

"""
        
        # Add reasoning chain if available
        if reasoning_chain:
            report += """### Agent Reasoning Chain

"""
            for i, step in enumerate(reasoning_chain, 1):
                report += f"{i}. {step}\n"
            report += "\n"
        
        report += f"""---

## ✅ Validation Results

| Metric | Value |
|--------|-------|
| **Tests Passed** | {tests_passed} |
| **Tests Failed** | {tests_failed} |
| **Total Tests** | {tests_total} |
| **Validation Status** | {status} |

"""
        
        # Add test output if enabled
        if self.config.include_test_output and test_output:
            report += f"""### Test Output

```
{test_output}
```

"""
        
        # Add diff if enabled
        if self.config.include_diff:
            diff_text = vulnerability.get('diff_text', '')
            if diff_text:
                report += f"""---

## 📝 Patch Information

- **Patch File:** `{vulnerability.get('patch_file_path', 'Not generated')}`
- **Lines Added:** +{vulnerability.get('lines_added', 0)}
- **Lines Removed:** -{vulnerability.get('lines_removed', 0)}

### Diff

```diff
{diff_text}
```

"""
        
        # Add recommendations if enabled
        if self.config.include_recommendations:
            report += f"""---

## 💡 Recommendations

{self._get_recommendations(vulnerability)}

"""
        
        # Add how to apply section
        patch_filename = vulnerability.get('patch_filename', 'fix.patch')
        report += f"""---

## 🚀 How to Apply

```bash
# Review the patch
cat {patch_filename}

# Apply the patch
git apply {patch_filename}

# Run tests to verify
pytest

# Commit the fix
git add {file_path}
git commit -m "fix({vuln_type}): remediate vulnerability in {Path(file_path).name}"
```

---

*Report generated by SecureGuard AI*
"""
        return report
    
    def _get_fix_explanation(self, vulnerability: Dict[str, Any]) -> str:
        """
        Get or generate fix explanation.
        
        Args:
            vulnerability: Vulnerability dict
            
        Returns:
            Explanation string
        """
        vuln_type = vulnerability.get('vuln_type', '')
        
        explanations = {
            'sql_injection': """
The fix replaces string concatenation/formatting in SQL queries with parameterized queries.
This prevents attackers from injecting malicious SQL code through user input.

**Why this works:**
- Parameterized queries separate SQL code from data
- The database driver handles proper escaping
- User input is treated as data, never as executable code
""",
            'command_injection': """
The fix removes shell=True and uses list arguments instead of string commands.
This prevents attackers from injecting shell commands through user input.

**Why this works:**
- Without shell=True, special characters are not interpreted
- List arguments are passed directly to the executable
- No shell metacharacter expansion occurs
""",
            'xss': """
The fix adds proper HTML escaping to user-controlled output.
This prevents attackers from injecting malicious scripts into web pages.

**Why this works:**
- HTML special characters are converted to entities
- Scripts cannot execute when properly escaped
- The browser renders the content as text, not code
""",
            'hardcoded_secrets': """
The fix moves secrets from source code to environment variables.
This prevents secrets from being exposed in version control.

**Why this works:**
- Environment variables are not committed to git
- Secrets can be managed separately per environment
- Follows the 12-factor app methodology
""",
        }
        
        return explanations.get(vuln_type, """
The fix addresses the identified vulnerability by applying security best practices.
Please review the code changes to understand the specific remediation applied.
""")
    
    def _get_recommendations(self, vulnerability: Dict[str, Any]) -> str:
        """
        Get recommendations based on vulnerability type.
        
        Args:
            vulnerability: Vulnerability dict
            
        Returns:
            Recommendations string
        """
        vuln_type = vulnerability.get('vuln_type', '')
        
        recommendations = {
            'sql_injection': """
1. **Use an ORM** - Consider using SQLAlchemy or Django ORM for safer database operations
2. **Input validation** - Validate and sanitize all user inputs
3. **Least privilege** - Use database accounts with minimal required permissions
4. **Code review** - Search for similar patterns in the codebase
""",
            'xss': """
1. **Enable auto-escaping** - Configure your template engine to auto-escape by default
2. **Content Security Policy** - Implement CSP headers to prevent inline script execution
3. **Input validation** - Validate user input on both client and server side
4. **Output encoding** - Use context-appropriate encoding (HTML, JavaScript, URL)
""",
            'hardcoded_secrets': """
1. **Secrets management** - Consider using HashiCorp Vault or AWS Secrets Manager
2. **Git history** - Rotate any secrets that were previously committed
3. **Pre-commit hooks** - Add tools like detect-secrets to prevent future leaks
4. **.env files** - Use python-dotenv and add .env to .gitignore
""",
        }
        
        return recommendations.get(vuln_type, """
1. **Review similar code** - Search for similar patterns that may need fixing
2. **Add tests** - Write tests to prevent regression
3. **Security training** - Consider security awareness training for the team
4. **Regular scanning** - Implement automated security scanning in CI/CD
""")
    
    def _generate_summary(self, vulnerability: Dict[str, Any]) -> str:
        """
        Generate a brief summary of the fix.
        
        Args:
            vulnerability: Vulnerability dict
            
        Returns:
            Summary string
        """
        vuln_type = vulnerability.get('vuln_type', 'unknown')
        file_path = vulnerability.get('file_path', 'unknown')
        status = vulnerability.get('status', 'UNKNOWN')
        
        return f"Fixed {vuln_type.replace('_', ' ')} in {file_path} - Status: {status}"
    
    def _generate_report_filename(self, vulnerability: Dict[str, Any]) -> str:
        """
        Generate a unique report filename.
        
        Args:
            vulnerability: Vulnerability dict
            
        Returns:
            Report filename string
        """
        vuln_type = vulnerability.get('vuln_type', 'fix')
        file_path = vulnerability.get('file_path', 'unknown')
        line_number = vulnerability.get('line_number', 0)
        
        clean_path = Path(file_path).stem
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        return f"report_{vuln_type}_{clean_path}_L{line_number}_{timestamp}.md"
    
    def generate_summary_report(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """
        Generate a summary report for all vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dicts
            
        Returns:
            Path to summary report
        """
        total = len(vulnerabilities)
        verified = sum(1 for v in vulnerabilities if v.get('status') == 'VERIFIED')
        unverified = sum(1 for v in vulnerabilities if v.get('status') == 'UNVERIFIED')
        skipped = sum(1 for v in vulnerabilities if v.get('is_false_positive'))
        
        report = f"""# SecureGuard AI - Summary Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Overview

| Metric | Count |
|--------|-------|
| **Total Vulnerabilities** | {total} |
| **Verified Fixes** | {verified} |
| **Unverified Fixes** | {unverified} |
| **False Positives Skipped** | {skipped} |

---

## Vulnerabilities Processed

| # | Type | File | Line | Severity | Status |
|---|------|------|------|----------|--------|
"""
        
        for i, v in enumerate(vulnerabilities, 1):
            report += f"| {i} | {v.get('vuln_type', 'unknown')} | `{v.get('file_path', '')}` | {v.get('line_number', 0)} | {v.get('severity', '')} | {v.get('status', '')} |\n"
        
        report += """
---

*Report generated by SecureGuard AI*
"""
        
        summary_path = self.output_dir / f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        summary_path.write_text(report)
        
        print(f"[Reporter] Wrote summary report: {summary_path}")
        return str(summary_path)


def generate_report(
    vulnerability: Dict[str, Any],
    output_dir: str = "output",
    config: Optional[ReportConfig] = None,
    verbose: bool = True
) -> Dict[str, Any]:
    """
    Convenience function to generate a report.
    
    Args:
        vulnerability: Vulnerability dict
        output_dir: Directory for report output
        config: Optional ReportConfig for customization
        verbose: Whether to print status messages
        
    Returns:
        Vulnerability dict with report info
    """
    generator = ReportGenerator(output_dir, config=config, verbose=verbose)
    return generator.generate(vulnerability)


if __name__ == "__main__":
    # Test the reporter module
    print("SecureGuard AI - Reporter Module")
    print("=" * 40)
    
    test_vuln = {
        'vuln_type': 'sql_injection',
        'file_path': 'app/database.py',
        'line_number': 10,
        'severity': 'HIGH',
        'description': 'SQL injection vulnerability detected in user query',
        'code_snippet': 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        'proposed_fix': 'query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (user_id,))',
        'tests_passed': 5,
        'tests_failed': 0,
        'test_output': 'All tests passed',
        'status': 'VERIFIED',
        'diff_text': '- query = f"SELECT * FROM users WHERE id = {user_id}"\n+ query = "SELECT * FROM users WHERE id = ?"',
        'patch_file_path': 'output/sql_injection_database_L10.patch',
        'patch_filename': 'sql_injection_database_L10.patch'
    }
    
    generator = ReportGenerator()
    result = generator.generate(test_vuln)
    
    print(f"\nReport generated: {result.get('report_file_path')}")
    print(f"Summary: {result.get('summary')}")
