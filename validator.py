"""
SecureGuard AI - Validator Module

This module validates fixes by applying them and running tests.
It applies fixes to temp copies and runs pytest to verify correctness.

Responsibilities:
- Apply fix to temporary copy of file
- Run pytest in subprocess
- Return structured results (pass/fail counts, output)
- Fallback to syntax check if no tests available

Output Schema:
{
    ...fix_output,
    tests_passed: int,
    tests_failed: int,
    test_output: str,
    status: 'VERIFIED' | 'UNVERIFIED' | 'SYNTAX_ONLY'
}
"""

import ast
import re
import subprocess
import tempfile
import shutil
import json
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum


class ValidationStatus(str, Enum):
    """Status of validation."""
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    SYNTAX_ONLY = "SYNTAX_ONLY"
    SYNTAX_ERROR = "SYNTAX_ERROR"
    ERROR = "ERROR"


@dataclass
class TestResult:
    """Structured test result."""
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    total: int = 0
    duration: float = 0.0
    output: str = ""
    return_code: int = 0
    test_cases: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'passed': self.passed,
            'failed': self.failed,
            'errors': self.errors,
            'skipped': self.skipped,
            'total': self.total,
            'duration': self.duration,
            'output': self.output,
            'return_code': self.return_code,
            'test_cases': self.test_cases
        }
    
    @property
    def success(self) -> bool:
        """Check if all tests passed."""
        return self.failed == 0 and self.errors == 0


@dataclass
class ValidationResult:
    """Complete validation result."""
    status: ValidationStatus
    syntax_valid: bool
    test_result: Optional[TestResult] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'status': self.status.value,
            'syntax_valid': self.syntax_valid,
            'error_message': self.error_message
        }
        if self.test_result:
            result.update({
                'tests_passed': self.test_result.passed,
                'tests_failed': self.test_result.failed,
                'tests_errors': self.test_result.errors,
                'tests_skipped': self.test_result.skipped,
                'tests_total': self.test_result.total,
                'test_duration': self.test_result.duration,
                'test_output': self.test_result.output,
                'test_cases': self.test_result.test_cases
            })
        return result


class FixValidator:
    """
    Validates proposed fixes by running tests.
    
    Applies fixes to temporary copies and runs the test suite
    to verify the fix doesn't break existing functionality.
    """
    
    def __init__(self, repo_path: str = ".", verbose: bool = True):
        """
        Initialize the validator.
        
        Args:
            repo_path: Root path of the repository
            verbose: Whether to print status messages
        """
        self.repo_path = Path(repo_path).resolve()
        self.temp_dir: Optional[Path] = None
        self.verbose = verbose
    
    def validate(
        self,
        vulnerability: Dict[str, Any],
        fix_code: str,
        test_path: Optional[str] = None,
        timeout: int = 120
    ) -> Dict[str, Any]:
        """
        Validate a proposed fix.
        
        Args:
            vulnerability: Vulnerability dict with fix output
            fix_code: The proposed fix code
            test_path: Optional specific test file/directory
            timeout: Test execution timeout in seconds
            
        Returns:
            Vulnerability dict with validation results
        """
        result = vulnerability.copy()
        file_path = vulnerability.get('file_path', '')
        
        if self.verbose:
            print(f"[Validator] Validating fix for: {file_path}")
        
        # Step 1: Syntax check
        syntax_valid, syntax_error = self._check_syntax(fix_code)
        if not syntax_valid:
            if self.verbose:
                print(f"[Validator] ✗ Syntax error: {syntax_error}")
            
            validation = ValidationResult(
                status=ValidationStatus.SYNTAX_ERROR,
                syntax_valid=False,
                error_message=syntax_error
            )
            result.update(validation.to_dict())
            return result
        
        if self.verbose:
            print(f"[Validator] ✓ Syntax check passed")
        
        # Step 2: Apply fix to temp copy and run tests
        try:
            test_result = self._run_tests_with_fix(file_path, fix_code, test_path, timeout)
            
            # Determine status based on test results
            if test_result.success:
                status = ValidationStatus.VERIFIED
                if self.verbose:
                    print(f"[Validator] ✓ All tests passed ({test_result.passed} passed)")
            elif test_result.total == 0:
                status = ValidationStatus.SYNTAX_ONLY
                if self.verbose:
                    print(f"[Validator] ⚠ No tests found, syntax-only validation")
            else:
                status = ValidationStatus.UNVERIFIED
                if self.verbose:
                    print(f"[Validator] ✗ Tests failed ({test_result.failed} failed, {test_result.passed} passed)")
            
            validation = ValidationResult(
                status=status,
                syntax_valid=True,
                test_result=test_result
            )
            result.update(validation.to_dict())
            
        except Exception as e:
            if self.verbose:
                print(f"[Validator] ✗ Error running tests: {e}")
            
            validation = ValidationResult(
                status=ValidationStatus.ERROR,
                syntax_valid=True,
                error_message=str(e)
            )
            result.update(validation.to_dict())
        
        finally:
            self.cleanup()
        
        return result
    
    def _check_syntax(self, code: str) -> Tuple[bool, Optional[str]]:
        """
        Check if code has valid Python syntax.
        
        Args:
            code: Python code string
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            ast.parse(code)
            return True, None
        except SyntaxError as e:
            return False, f"Line {e.lineno}: {e.msg}"
    
    def _run_tests_with_fix(
        self,
        file_path: str,
        fix_code: str,
        test_path: Optional[str] = None,
        timeout: int = 120
    ) -> TestResult:
        """
        Apply fix to temp copy and run tests.
        
        Args:
            file_path: Original file path
            fix_code: The fix code to apply
            test_path: Optional specific test path
            timeout: Test execution timeout
            
        Returns:
            TestResult with test execution results
        """
        # Create temp directory
        self.temp_dir = Path(tempfile.mkdtemp(prefix="secureai_validate_"))
        
        if self.verbose:
            print(f"[Validator] Created temp directory: {self.temp_dir}")
        
        # Resolve file path
        original_path = Path(file_path)
        if not original_path.is_absolute():
            original_path = self.repo_path / file_path
        
        # Copy relevant files to temp directory
        self._setup_temp_environment(original_path)
        
        # Apply fix to temp file
        temp_file = self.temp_dir / Path(file_path).name
        temp_file.write_text(fix_code, encoding='utf-8')
        
        if self.verbose:
            print(f"[Validator] Applied fix to: {temp_file}")
        
        # Determine test command
        test_cmd = self._determine_test_command(original_path, test_path)
        
        if self.verbose:
            print(f"[Validator] Running: {' '.join(test_cmd)}")
        
        # Run tests
        return self._run_pytest(test_cmd, timeout)
    
    def _setup_temp_environment(self, original_path: Path):
        """
        Set up the temporary test environment.
        
        Args:
            original_path: Path to the original file
        """
        # Copy the original file's directory contents
        original_dir = original_path.parent if original_path.exists() else self.repo_path
        
        if original_dir.exists():
            for item in original_dir.iterdir():
                if item.is_file() and item.suffix == '.py':
                    shutil.copy2(item, self.temp_dir / item.name)
                elif item.is_dir() and item.name in ['tests', 'test']:
                    shutil.copytree(item, self.temp_dir / item.name, dirs_exist_ok=True)
        
        # Copy conftest.py if exists
        conftest = self.repo_path / 'conftest.py'
        if conftest.exists():
            shutil.copy2(conftest, self.temp_dir / 'conftest.py')
        
        # Copy pytest.ini or pyproject.toml if exists
        for config_file in ['pytest.ini', 'pyproject.toml', 'setup.cfg']:
            config_path = self.repo_path / config_file
            if config_path.exists():
                shutil.copy2(config_path, self.temp_dir / config_file)
    
    def _determine_test_command(
        self,
        original_path: Path,
        test_path: Optional[str] = None
    ) -> List[str]:
        """
        Determine the appropriate test command.
        
        Args:
            original_path: Path to the original file
            test_path: Optional specific test path
            
        Returns:
            List of command arguments
        """
        # Base pytest command with JSON output for parsing
        cmd = ['python3', '-m', 'pytest', '-v', '--tb=short']
        
        if test_path:
            # Use specified test path
            cmd.append(test_path)
        else:
            # Try to find related tests
            test_file = f"test_{original_path.stem}.py"
            
            # Check common test locations
            test_locations = [
                self.temp_dir / 'tests' / test_file,
                self.temp_dir / 'test' / test_file,
                self.temp_dir / test_file,
            ]
            
            for test_loc in test_locations:
                if test_loc.exists():
                    cmd.append(str(test_loc))
                    return cmd
            
            # Check for any test files in temp dir
            test_files = list(self.temp_dir.glob('test_*.py'))
            test_files.extend(self.temp_dir.glob('*_test.py'))
            
            if test_files:
                cmd.extend([str(f) for f in test_files[:5]])  # Limit to 5 test files
            else:
                # No tests found, just do syntax check
                cmd = ['python3', '-m', 'py_compile', str(self.temp_dir / original_path.name)]
        
        return cmd
    
    def _run_pytest(self, cmd: List[str], timeout: int = 120) -> TestResult:
        """
        Run pytest and parse results.
        
        Args:
            cmd: Command to run
            timeout: Execution timeout
            
        Returns:
            TestResult with parsed results
        """
        try:
            result = subprocess.run(
                cmd,
                cwd=str(self.temp_dir),
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            output = result.stdout + result.stderr
            
            # Check if this was a syntax check (py_compile)
            if 'py_compile' in ' '.join(cmd):
                if result.returncode == 0:
                    return TestResult(
                        passed=1,
                        failed=0,
                        total=1,
                        output="Syntax check passed",
                        return_code=0
                    )
                else:
                    return TestResult(
                        passed=0,
                        failed=1,
                        total=1,
                        output=output,
                        return_code=result.returncode
                    )
            
            # Parse pytest output
            return self._parse_pytest_output(output, result.returncode)
            
        except subprocess.TimeoutExpired:
            return TestResult(
                passed=0,
                failed=1,
                errors=1,
                total=1,
                output=f'Test execution timed out after {timeout} seconds',
                return_code=-1
            )
        except Exception as e:
            return TestResult(
                passed=0,
                failed=0,
                errors=1,
                total=0,
                output=f'Error running tests: {str(e)}',
                return_code=-1
            )
    
    def _parse_pytest_output(self, output: str, return_code: int) -> TestResult:
        """
        Parse pytest output for detailed results.
        
        Args:
            output: Raw pytest output
            return_code: Process return code
            
        Returns:
            TestResult with parsed data
        """
        result = TestResult(output=output[:5000], return_code=return_code)
        
        # Parse summary line: "5 passed, 2 failed, 1 error, 3 skipped in 1.23s"
        passed_match = re.search(r'(\d+)\s+passed', output)
        failed_match = re.search(r'(\d+)\s+failed', output)
        error_match = re.search(r'(\d+)\s+error', output)
        skipped_match = re.search(r'(\d+)\s+skipped', output)
        duration_match = re.search(r'in\s+([\d.]+)s', output)
        
        if passed_match:
            result.passed = int(passed_match.group(1))
        if failed_match:
            result.failed = int(failed_match.group(1))
        if error_match:
            result.errors = int(error_match.group(1))
        if skipped_match:
            result.skipped = int(skipped_match.group(1))
        if duration_match:
            result.duration = float(duration_match.group(1))
        
        result.total = result.passed + result.failed + result.errors + result.skipped
        
        # Parse individual test cases
        test_case_pattern = re.compile(
            r'^([\w/]+\.py::[\w_]+(?:\[[\w\-]+\])?)\s+(PASSED|FAILED|ERROR|SKIPPED)',
            re.MULTILINE
        )
        
        for match in test_case_pattern.finditer(output):
            result.test_cases.append({
                'name': match.group(1),
                'status': match.group(2)
            })
        
        # If no tests were found but return code is 0, it's a pass
        if result.total == 0 and return_code == 0:
            # Check if it was a collection error
            if 'no tests ran' in output.lower() or 'collected 0 items' in output.lower():
                result.total = 0
            else:
                result.passed = 1
                result.total = 1
        
        return result
    
    def cleanup(self):
        """Clean up temporary directory."""
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                self.temp_dir = None
            except Exception as e:
                print(f"[Validator] Warning: Could not clean up temp dir: {e}")


def validate_fix(
    vulnerability: Dict[str, Any],
    fix_code: str,
    repo_path: str = ".",
    test_path: Optional[str] = None,
    verbose: bool = True
) -> Dict[str, Any]:
    """
    Convenience function to validate a fix.
    
    Args:
        vulnerability: Vulnerability dict
        fix_code: The proposed fix code
        repo_path: Root path of the repository
        test_path: Optional specific test path
        verbose: Whether to print status messages
        
    Returns:
        Vulnerability dict with validation results
    """
    validator = FixValidator(repo_path, verbose=verbose)
    return validator.validate(vulnerability, fix_code, test_path)


# ============================================================================
# TEST HARNESS
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("SecureGuard AI - Validator Module Test")
    print("=" * 70)
    
    validator = FixValidator(verbose=True)
    
    # Test 1: Valid code
    print("\n--- Test 1: Valid Python Code ---")
    valid_code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
'''
    
    test_vuln = {
        'vuln_type': 'sql_injection',
        'file_path': 'app/database.py',
        'line_number': 10
    }
    
    result = validator.validate(test_vuln, valid_code)
    print(f"Status: {result.get('status')}")
    print(f"Syntax valid: {result.get('syntax_valid')}")
    print(f"Tests passed: {result.get('tests_passed', 0)}")
    
    # Test 2: Invalid code (syntax error)
    print("\n--- Test 2: Invalid Python Code (Syntax Error) ---")
    invalid_code = '''
def get_user(user_id)  # Missing colon
    query = "SELECT * FROM users WHERE id = ?"
    return cursor.fetchone()
'''
    
    result = validator.validate(test_vuln, invalid_code)
    print(f"Status: {result.get('status')}")
    print(f"Syntax valid: {result.get('syntax_valid')}")
    print(f"Error: {result.get('error_message', 'N/A')}")
    
    # Test 3: Valid code with imports
    print("\n--- Test 3: Valid Code with Imports ---")
    code_with_imports = '''
import sqlite3
from typing import Optional

def get_user(user_id: int) -> Optional[dict]:
    """Get user by ID using parameterized query."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
'''
    
    result = validator.validate(test_vuln, code_with_imports)
    print(f"Status: {result.get('status')}")
    print(f"Syntax valid: {result.get('syntax_valid')}")
    
    print("\n" + "=" * 70)
    print("Validator test completed!")
    print("=" * 70)
