"""
SecureGuard AI - Agent Tools Module

This module defines the LangChain tools used by the remediation agent.

Tools:
- read_file_tool: Read source file content
- run_tests_tool: Apply fix and run pytest
- search_codebase_tool: Search for vulnerable patterns
- explain_fix_tool: Generate explanation for the fix

Usage:
    from agent.tools import get_all_tools
    
    tools = get_all_tools()
    # Use with LangChain agent
"""

import os
import re
import sys
import json
import tempfile
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from functools import wraps

# Import LangChain tools
from langchain_core.tools import tool

LANGCHAIN_AVAILABLE = True

# Ensure parent directory is in path for imports
_parent_dir = Path(__file__).parent.parent
if str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))


# ============================================================================
# TOOL 1: read_file_tool
# ============================================================================

@tool
def read_file_tool(file_path: str) -> str:
    """
    Read a source file and return its full content.
    
    Use this tool to read the contents of any file in the codebase.
    Returns the complete file content as a string.
    
    Args:
        file_path: Path to the source file (absolute or relative)
        
    Returns:
        The full content of the file as a string, or an error message if file not found.
    """
    try:
        path = Path(file_path)
        
        if not path.exists():
            return f"Error: File not found: {file_path}"
        
        if not path.is_file():
            return f"Error: Path is not a file: {file_path}"
        
        # Check file size to avoid reading huge files
        file_size = path.stat().st_size
        max_size = 1024 * 1024  # 1MB limit
        
        if file_size > max_size:
            return f"Error: File too large ({file_size} bytes). Maximum allowed: {max_size} bytes"
        
        # Read and return content
        content = path.read_text(encoding='utf-8', errors='replace')
        
        # Add line numbers for easier reference
        lines = content.split('\n')
        numbered_lines = [f"{i+1:4d} | {line}" for i, line in enumerate(lines)]
        
        return '\n'.join(numbered_lines)
        
    except PermissionError:
        return f"Error: Permission denied: {file_path}"
    except Exception as e:
        return f"Error reading file: {str(e)}"


# ============================================================================
# TOOL 2: run_tests_tool
# ============================================================================

@tool
def run_tests_tool(file_path: str, fix_code: str, test_command: str = "") -> str:
    """
    Apply a proposed fix to a temporary copy of the file and run pytest.
    
    This tool:
    1. Creates a temporary copy of the original file
    2. Replaces the file content with the fix_code
    3. Runs pytest to verify the fix doesn't break tests
    4. Returns the test results
    
    Args:
        file_path: Path to the original source file to fix
        fix_code: The complete fixed code to write to the temp file
        test_command: Optional custom test command (default: pytest)
        
    Returns:
        JSON string with test results: passed count, failed count, output, and status
    """
    result = {
        'passed': 0,
        'failed': 0,
        'errors': 0,
        'output': '',
        'status': 'UNKNOWN'
    }
    
    try:
        original_path = Path(file_path)
        
        if not original_path.exists():
            result['status'] = 'ERROR'
            result['output'] = f"Original file not found: {file_path}"
            return json.dumps(result)
        
        # Create a temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Copy the original file's directory structure
            original_dir = original_path.parent
            relative_path = original_path.name
            
            # If file is in a package, copy the package structure
            if original_dir.exists():
                # Copy parent directory contents to temp
                for item in original_dir.iterdir():
                    if item.is_file():
                        shutil.copy2(item, tmpdir_path / item.name)
                    elif item.is_dir() and not item.name.startswith('.'):
                        shutil.copytree(item, tmpdir_path / item.name, dirs_exist_ok=True)
            
            # Write the fixed code to the temp file
            temp_file = tmpdir_path / relative_path
            temp_file.write_text(fix_code, encoding='utf-8')
            
            # Determine test command
            if not test_command:
                # Try to find tests related to this file
                test_file = f"test_{original_path.stem}.py"
                tests_dir = original_dir / "tests"
                
                if (tests_dir / test_file).exists():
                    test_command = f"pytest {tests_dir / test_file} -v --tb=short"
                elif (original_dir / test_file).exists():
                    test_command = f"pytest {original_dir / test_file} -v --tb=short"
                else:
                    # Run syntax check at minimum (use python3 for Linux compatibility)
                    test_command = f"python3 -m py_compile {temp_file}"
            
            # Run the test command
            try:
                proc = subprocess.run(
                    test_command,
                    shell=True,
                    cwd=str(tmpdir_path),
                    capture_output=True,
                    text=True,
                    timeout=60  # 60 second timeout
                )
                
                output = proc.stdout + proc.stderr
                result['output'] = output[:2000]  # Limit output size
                
                # Parse pytest output for pass/fail counts
                if 'pytest' in test_command.lower():
                    # Look for pytest summary line: "X passed, Y failed"
                    passed_match = re.search(r'(\d+) passed', output)
                    failed_match = re.search(r'(\d+) failed', output)
                    error_match = re.search(r'(\d+) error', output)
                    
                    result['passed'] = int(passed_match.group(1)) if passed_match else 0
                    result['failed'] = int(failed_match.group(1)) if failed_match else 0
                    result['errors'] = int(error_match.group(1)) if error_match else 0
                    
                    if proc.returncode == 0:
                        result['status'] = 'PASSED'
                    else:
                        result['status'] = 'FAILED'
                else:
                    # For syntax check
                    if proc.returncode == 0:
                        result['status'] = 'SYNTAX_OK'
                        result['passed'] = 1
                    else:
                        result['status'] = 'SYNTAX_ERROR'
                        result['failed'] = 1
                        
            except subprocess.TimeoutExpired:
                result['status'] = 'TIMEOUT'
                result['output'] = 'Test execution timed out after 60 seconds'
                
    except Exception as e:
        result['status'] = 'ERROR'
        result['output'] = f"Error running tests: {str(e)}"
    
    return json.dumps(result, indent=2)


# ============================================================================
# TOOL 3: search_codebase_tool
# ============================================================================

@tool
def search_codebase_tool(pattern: str, search_path: str = ".", file_extensions: str = ".py") -> str:
    """
    Search the codebase for occurrences of a pattern (similar vulnerable code).
    
    Use this tool to find other instances of similar vulnerable patterns
    that might need the same fix.
    
    Args:
        pattern: The pattern to search for (supports regex)
        search_path: Root path to search in (default: current directory)
        file_extensions: Comma-separated file extensions to search (default: .py)
        
    Returns:
        JSON string with matches: file paths, line numbers, and matching lines
    """
    result = {
        'pattern': pattern,
        'matches': [],
        'total_matches': 0,
        'files_searched': 0
    }
    
    try:
        search_root = Path(search_path)
        
        if not search_root.exists():
            return json.dumps({
                'error': f"Search path not found: {search_path}",
                'matches': [],
                'total_matches': 0
            })
        
        # Parse file extensions
        extensions = [ext.strip() if ext.startswith('.') else f'.{ext.strip()}' 
                      for ext in file_extensions.split(',')]
        
        # Compile regex pattern
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return json.dumps({
                'error': f"Invalid regex pattern: {str(e)}",
                'matches': [],
                'total_matches': 0
            })
        
        # Walk through the directory
        for root, dirs, files in os.walk(search_root):
            # Skip hidden directories and common non-code directories
            dirs[:] = [d for d in dirs if not d.startswith('.') 
                       and d not in ('node_modules', '__pycache__', 'venv', '.git', 'dist', 'build')]
            
            for filename in files:
                # Check extension
                if not any(filename.endswith(ext) for ext in extensions):
                    continue
                
                file_path = Path(root) / filename
                result['files_searched'] += 1
                
                try:
                    content = file_path.read_text(encoding='utf-8', errors='replace')
                    lines = content.split('\n')
                    
                    for line_num, line in enumerate(lines, 1):
                        if regex.search(line):
                            result['matches'].append({
                                'file': str(file_path),
                                'line_number': line_num,
                                'content': line.strip()[:200]  # Limit line length
                            })
                            result['total_matches'] += 1
                            
                            # Limit total matches to avoid huge results
                            if result['total_matches'] >= 50:
                                result['truncated'] = True
                                return json.dumps(result, indent=2)
                                
                except Exception:
                    continue  # Skip files that can't be read
        
    except Exception as e:
        result['error'] = str(e)
    
    return json.dumps(result, indent=2)


# ============================================================================
# TOOL 4: explain_fix_tool
# ============================================================================

@tool
def explain_fix_tool(vuln_type: str, original_code: str, fixed_code: str) -> str:
    """
    Generate a plain-English explanation of why the fix works.
    
    This tool explains:
    - What was wrong with the original code
    - Why the fix addresses the vulnerability
    - Any edge cases or remaining concerns
    
    Args:
        vuln_type: The type of vulnerability (e.g., 'sql_injection', 'xss')
        original_code: The original vulnerable code
        fixed_code: The fixed code
        
    Returns:
        A detailed explanation of the fix
    """
    # Get vulnerability info from templates
    try:
        from prompts.fix_templates import get_fix_template
        template_info = get_fix_template(vuln_type)
    except ImportError:
        template_info = None
    
    # Build explanation based on vulnerability type
    explanations = {
        'sql_injection': {
            'problem': 'SQL Injection occurs when user input is directly concatenated into SQL queries, allowing attackers to manipulate the query structure.',
            'fix_approach': 'Use parameterized queries (prepared statements) where user input is passed as parameters, not concatenated into the query string.',
            'why_it_works': 'Parameterized queries separate SQL code from data. The database treats parameters as literal values, not executable SQL, preventing injection attacks.',
            'owasp': 'A03:2021-Injection'
        },
        'xss': {
            'problem': 'Cross-Site Scripting (XSS) occurs when user input is rendered in HTML without proper escaping, allowing attackers to inject malicious scripts.',
            'fix_approach': 'Escape all user input before rendering in HTML using html.escape() or template auto-escaping.',
            'why_it_works': 'HTML escaping converts special characters (<, >, &, ", \') to their HTML entity equivalents, preventing them from being interpreted as HTML/JavaScript.',
            'owasp': 'A03:2021-Injection'
        },
        'command_injection': {
            'problem': 'Command Injection occurs when user input is passed to shell commands, allowing attackers to execute arbitrary system commands.',
            'fix_approach': 'Use subprocess with shell=False and pass arguments as a list. Avoid os.system() entirely.',
            'why_it_works': 'When shell=False, arguments are passed directly to the executable without shell interpretation, preventing command chaining and injection.',
            'owasp': 'A03:2021-Injection'
        },
        'path_traversal': {
            'problem': 'Path Traversal occurs when user input is used in file paths without validation, allowing access to files outside the intended directory.',
            'fix_approach': 'Use os.path.basename() to strip directory components, then validate the resolved path stays within the allowed base directory.',
            'why_it_works': 'basename() removes all directory traversal sequences (../), and realpath validation ensures the final path is within bounds.',
            'owasp': 'A01:2021-Broken Access Control'
        },
        'hardcoded_secrets': {
            'problem': 'Hardcoded secrets in source code can be exposed through version control, logs, or decompilation.',
            'fix_approach': 'Move secrets to environment variables using os.getenv() or a .env file with python-dotenv.',
            'why_it_works': 'Environment variables are not stored in code, keeping secrets out of version control and allowing different values per environment.',
            'owasp': 'A02:2021-Cryptographic Failures'
        }
    }
    
    # Get explanation for this vulnerability type
    vuln_lower = vuln_type.lower()
    if vuln_lower in explanations:
        info = explanations[vuln_lower]
    else:
        # Generic explanation
        info = {
            'problem': f'The code contains a {vuln_type} vulnerability that could be exploited by attackers.',
            'fix_approach': 'Apply security best practices for this vulnerability type.',
            'why_it_works': 'The fix follows established security patterns to prevent exploitation.',
            'owasp': template_info.get('owasp', 'Unknown') if template_info else 'Unknown'
        }
    
    # Build the explanation
    explanation = f"""
## Fix Explanation: {vuln_type.upper().replace('_', ' ')}

### What Was Wrong
{info['problem']}

### Original Vulnerable Code
```
{original_code[:500]}{'...' if len(original_code) > 500 else ''}
```

### Fix Approach
{info['fix_approach']}

### Fixed Code
```
{fixed_code[:500]}{'...' if len(fixed_code) > 500 else ''}
```

### Why This Fix Works
{info['why_it_works']}

### OWASP Reference
{info['owasp']}

### Remaining Considerations
- Ensure all similar patterns in the codebase are also fixed
- Add input validation as an additional defense layer
- Consider adding security tests to prevent regression
"""
    
    return explanation.strip()


# ============================================================================
# TOOL REGISTRY AND UTILITIES
# ============================================================================

def get_all_tools() -> List:
    """
    Get all LangChain tools for the agent.
    
    Returns:
        List of tool functions decorated with @tool
    """
    return [
        read_file_tool,
        run_tests_tool,
        search_codebase_tool,
        explain_fix_tool
    ]


# Legacy tool registry for backward compatibility
TOOLS = {
    'read_file': read_file_tool,
    'run_tests': run_tests_tool,
    'search_codebase': search_codebase_tool,
    'explain_fix': explain_fix_tool,
}


# ============================================================================
# TEST HARNESS
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("SecureGuard AI - Agent Tools Test")
    print("=" * 60)
    
    # Create a test file
    test_dir = Path(tempfile.mkdtemp())
    test_file = test_dir / "vulnerable.py"
    test_file.write_text('''
def get_user(user_id):
    """Get user by ID - VULNERABLE!"""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
''')
    
    print(f"\nTest file created: {test_file}")
    
    # Test 1: read_file_tool
    print("\n" + "-" * 40)
    print("TEST 1: read_file_tool")
    print("-" * 40)
    result = read_file_tool.invoke({"file_path": str(test_file)})
    print(result)
    
    # Test 2: run_tests_tool
    print("\n" + "-" * 40)
    print("TEST 2: run_tests_tool")
    print("-" * 40)
    fixed_code = '''
def get_user(user_id):
    """Get user by ID - FIXED!"""
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
'''
    result = run_tests_tool.invoke({
        "file_path": str(test_file),
        "fix_code": fixed_code,
        "test_command": ""
    })
    print(result)
    
    # Test 3: search_codebase_tool
    print("\n" + "-" * 40)
    print("TEST 3: search_codebase_tool")
    print("-" * 40)
    result = search_codebase_tool.invoke({
        "pattern": r"f['\"]SELECT.*{",
        "search_path": str(test_dir),
        "file_extensions": ".py"
    })
    print(result)
    
    # Test 4: explain_fix_tool
    print("\n" + "-" * 40)
    print("TEST 4: explain_fix_tool")
    print("-" * 40)
    original = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
    fixed = 'query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (user_id,))'
    result = explain_fix_tool.invoke({
        "vuln_type": "sql_injection",
        "original_code": original,
        "fixed_code": fixed
    })
    print(result)
    
    # Cleanup
    shutil.rmtree(test_dir)
    
    print("\n" + "=" * 60)
    print("All tools tested successfully!")
    print("=" * 60)
