"""
Pytest tests for SecureGuard AI pipeline.

Tests cover:
- Parser module
- False positive filter
- Code locator
- Validator
- Patch generator
- Reporter
- End-to-end pipeline (with mocked LLM)
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from parser import ScanReportParser, parse_scan_report
from fp_filter import FalsePositiveFilter
from locator import CodeLocator
from validator import FixValidator
from patch_generator import PatchGenerator
from reporter import ReportGenerator
from reviewer import FixReviewer, ReviewMode, ReviewDecision


class TestParser:
    """Tests for the scan report parser."""
    
    def test_parse_custom_format(self, tmp_path):
        """Test parsing custom JSON format."""
        report = {
            "scanner": "custom",
            "vulnerabilities": [
                {
                    "vuln_type": "sql_injection",
                    "file_path": "app/db.py",
                    "line_number": 10,
                    "severity": "HIGH"
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
    
    def test_parse_empty_report(self, tmp_path):
        """Test parsing empty report."""
        report = {"vulnerabilities": []}
        
        report_file = tmp_path / "empty.json"
        report_file.write_text(json.dumps(report))
        
        parser = ScanReportParser()
        vulns = parser.parse(str(report_file))
        
        assert len(vulns) == 0
    
    def test_parse_invalid_json(self, tmp_path):
        """Test handling invalid JSON returns empty list."""
        report_file = tmp_path / "invalid.json"
        report_file.write_text("not valid json")
        
        parser = ScanReportParser()
        # Parser handles errors gracefully and returns empty list
        vulns = parser.parse(str(report_file))
        assert len(vulns) == 0


class TestFalsePositiveFilter:
    """Tests for the false positive filter."""
    
    def test_filter_test_files(self):
        """Test that test files are filtered."""
        vuln = {
            "vuln_type": "sql_injection",
            "file_path": "tests/test_db.py",
            "line_number": 10
        }
        
        fp_filter = FalsePositiveFilter(verbose=False)
        result = fp_filter.evaluate(vuln)
        
        assert result.get('is_false_positive') == True
        assert 'test file' in result.get('fp_reason', '').lower()
    
    def test_pass_production_files(self):
        """Test that production files pass through."""
        vuln = {
            "vuln_type": "sql_injection",
            "file_path": "app/database.py",
            "line_number": 10
        }
        
        fp_filter = FalsePositiveFilter(verbose=False)
        result = fp_filter.evaluate(vuln)
        
        # Should not be filtered as false positive
        assert result.get('is_false_positive') == False or result.get('confidence', 0) >= 0.75
    
    def test_filter_example_files(self):
        """Test that example/sample files are filtered."""
        vuln = {
            "vuln_type": "xss",
            "file_path": "examples/demo.py",
            "line_number": 5
        }
        
        fp_filter = FalsePositiveFilter(verbose=False)
        result = fp_filter.evaluate(vuln)
        
        assert result.get('is_false_positive') == True


class TestCodeLocator:
    """Tests for the code locator."""
    
    def test_locate_vulnerability(self, tmp_path):
        """Test locating vulnerable code."""
        # Create a test file
        code = '''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute(query)
'''
        test_file = tmp_path / "db.py"
        test_file.write_text(code)
        
        vuln = {
            "vuln_type": "sql_injection",
            "file_path": str(test_file),
            "line_number": 2
        }
        
        locator = CodeLocator(str(tmp_path), verbose=False)
        result = locator.locate(vuln)
        
        assert 'code_snippet' in result or 'code_context' in result
        assert result.get('locate_error') is None
    
    def test_locate_missing_file(self, tmp_path):
        """Test handling missing file."""
        vuln = {
            "vuln_type": "sql_injection",
            "file_path": str(tmp_path / "nonexistent.py"),
            "line_number": 10
        }
        
        locator = CodeLocator(str(tmp_path), verbose=False)
        result = locator.locate(vuln)
        
        # Should have an error
        assert result.get('locate_error') is not None or result.get('error') is not None


class TestValidator:
    """Tests for the fix validator."""
    
    def test_validate_valid_syntax(self, tmp_path):
        """Test validating code with valid syntax."""
        original = '''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute(query)
'''
        fixed = '''def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return execute(query, (user_id,))
'''
        test_file = tmp_path / "db.py"
        test_file.write_text(original)
        
        vuln = {
            "vuln_type": "sql_injection",
            "file_path": str(test_file),
            "line_number": 2
        }
        
        validator = FixValidator(repo_path=str(tmp_path), verbose=False)
        result = validator.validate(vuln, fixed)
        
        # Should pass syntax check at minimum
        assert result.get('status') in ['VERIFIED', 'SYNTAX_OK', 'PASSED']
    
    def test_validate_invalid_syntax(self, tmp_path):
        """Test validating code with invalid syntax."""
        vuln = {
            "vuln_type": "sql_injection",
            "file_path": "db.py",
            "line_number": 2
        }
        
        invalid_code = '''def get_user(user_id)
    query = "SELECT * FROM users WHERE id = ?"  # Missing colon
    return execute(query, (user_id,))
'''
        
        validator = FixValidator(repo_path=str(tmp_path), verbose=False)
        result = validator.validate(vuln, invalid_code)
        
        # Should fail syntax check
        assert result.get('status') in ['SYNTAX_ERROR', 'FAILED', 'ERROR']


class TestPatchGenerator:
    """Tests for the patch generator."""
    
    def test_generate_patch(self, tmp_path):
        """Test generating a git-compatible patch."""
        original = '''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute(query)
'''
        fixed = '''def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return execute(query, (user_id,))
'''
        
        vuln = {
            "vuln_type": "sql_injection",
            "file_path": "app/db.py",
            "line_number": 2
        }
        
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        patch_gen = PatchGenerator(output_dir=str(output_dir), verbose=False)
        result = patch_gen.generate(vuln, original, fixed)
        
        assert result.get('patch_file_path') is not None
        assert Path(result['patch_file_path']).exists()
        
        # Check patch content
        patch_content = Path(result['patch_file_path']).read_text()
        assert 'diff --git' in patch_content or '---' in patch_content


class TestReporter:
    """Tests for the report generator."""
    
    def test_generate_report(self, tmp_path):
        """Test generating a markdown report."""
        vuln = {
            "vuln_type": "sql_injection",
            "file_path": "app/db.py",
            "line_number": 2,
            "severity": "HIGH",
            "status": "VERIFIED",
            "proposed_fix": "Use parameterized queries"
        }
        
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        
        reporter = ReportGenerator(output_dir=str(output_dir), verbose=False)
        result = reporter.generate(vuln)
        
        assert result.get('report_file_path') is not None
        
        # Check report content
        report_path = result.get('report_file_path')
        if report_path and Path(report_path).exists():
            content = Path(report_path).read_text()
            assert 'sql_injection' in content.lower()


class TestReviewer:
    """Tests for the fix reviewer."""
    
    def test_automatic_mode_approves(self):
        """Test that automatic mode auto-approves."""
        vuln = {
            "vuln_type": "sql_injection",
            "file_path": "app/db.py",
            "line_number": 2,
            "status": "VERIFIED"
        }
        
        reviewer = FixReviewer(ReviewMode.AUTOMATIC)
        result = reviewer.review(vuln)
        
        assert result.get('review_decision') == 'approved'
        assert result.get('reviewed') == True
    
    def test_review_result_structure(self):
        """Test that review result has expected structure."""
        vuln = {
            "vuln_type": "xss",
            "file_path": "views.py",
            "line_number": 10
        }
        
        reviewer = FixReviewer(ReviewMode.AUTOMATIC)
        result = reviewer.review(vuln)
        
        assert 'review_decision' in result
        assert 'reviewed' in result


class TestEndToEnd:
    """End-to-end integration tests."""
    
    def test_pipeline_dry_run(self, tmp_path):
        """Test pipeline in dry-run mode."""
        # Create test report
        report = {
            "scanner": "custom",
            "vulnerabilities": [
                {
                    "vuln_type": "sql_injection",
                    "file_path": "app/db.py",
                    "line_number": 10,
                    "severity": "HIGH"
                }
            ]
        }
        
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(report))
        
        # Create test source file
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "db.py").write_text('query = f"SELECT * FROM users WHERE id = {user_id}"')
        
        # Import and run pipeline
        from main import run_pipeline
        
        results = run_pipeline(
            scan_path=str(report_file),
            repo_path=str(tmp_path),
            output_dir=str(tmp_path / "output"),
            mode='automatic',
            dry_run=True,
            verbose=False
        )
        
        assert results['total_vulnerabilities'] == 1


# Fixtures
@pytest.fixture
def sample_vulnerability():
    """Return a sample vulnerability dict."""
    return {
        "vuln_type": "sql_injection",
        "file_path": "app/database.py",
        "line_number": 10,
        "severity": "HIGH",
        "description": "SQL injection vulnerability"
    }


@pytest.fixture
def sample_xss_vulnerability():
    """Return a sample XSS vulnerability dict."""
    return {
        "vuln_type": "xss",
        "file_path": "app/views.py",
        "line_number": 20,
        "severity": "HIGH",
        "description": "Cross-site scripting vulnerability"
    }


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
