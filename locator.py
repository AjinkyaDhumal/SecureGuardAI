"""
SecureGuard AI - Locator Module

This module locates vulnerable code in source files.
It extracts context around the vulnerable line and identifies function scope.

Responsibilities:
- Open target file
- Extract ±20 lines of context around vulnerable line
- Identify function/class scope
- Extract imports needed for the fix
- Provide structured context for the agent

Output Schema:
{
    ...fp_output,
    code_snippet: str,
    full_context: str,
    function_scope: str,
    class_scope: str,
    imports: List[str],
    context_start_line: int,
    context_end_line: int
}
"""

import ast
import re
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class FunctionInfo:
    """Information about a function/method."""
    name: str
    start_line: int
    end_line: int
    signature: str
    decorators: List[str] = field(default_factory=list)
    is_async: bool = False
    is_method: bool = False
    class_name: Optional[str] = None


@dataclass
class ClassInfo:
    """Information about a class."""
    name: str
    start_line: int
    end_line: int
    bases: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)


class CodeLocator:
    """
    Locates vulnerable code and extracts context.

    Provides the agent with sufficient context to understand
    the vulnerability and generate an appropriate fix.

    Features:
    - Extract ±20 lines of context
    - Identify enclosing function/method
    - Identify enclosing class
    - Extract file imports
    - Provide full function body
    """

    DEFAULT_CONTEXT_LINES = 20

    def __init__(self, repo_path: str = ".", verbose: bool = True):
        """
        Initialize the locator.

        Args:
            repo_path: Root path of the repository
            verbose: Whether to print progress
        """
        self.repo_path = Path(repo_path)
        self.verbose = verbose
        self.file_cache: Dict[str, Tuple[str, List[str]]] = {}

    def _log(self, message: str) -> None:
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"[Locator] {message}")

    def _read_file(self, file_path: str) -> Tuple[Optional[str], Optional[List[str]]]:
        """
        Read file content with caching.

        Args:
            file_path: Path to the file

        Returns:
            Tuple of (content, lines) or (None, None) if not found
        """
        if file_path in self.file_cache:
            return self.file_cache[file_path]

        full_path = self.repo_path / file_path
        if not full_path.exists():
            return None, None

        try:
            content = full_path.read_text(encoding='utf-8')
            lines = content.split('\n')
            self.file_cache[file_path] = (content, lines)
            return content, lines
        except Exception as e:
            self._log(f"Error reading file: {e}")
            return None, None

    def locate(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Locate the vulnerable code and extract context.

        Args:
            vulnerability: Vulnerability dict from FP filter

        Returns:
            Vulnerability dict with code context added
        """
        result = vulnerability.copy()

        file_path = vulnerability.get('file_path', '')
        line_number = vulnerability.get('line_number', 0)

        self._log(f"Locating: {file_path}:{line_number}")

        # Read file content
        content, lines = self._read_file(file_path)

        if content is None or lines is None:
            self._log(f"File not found: {file_path}")
            result.update({
                'code_snippet': '',
                'full_context': '',
                'function_scope': '',
                'function_body': '',
                'class_scope': '',
                'imports': [],
                'error': f'File not found: {file_path}'
            })
            return result

        # Extract context (±20 lines)
        code_snippet, start_line, end_line = self._extract_context(
            lines, line_number, self.DEFAULT_CONTEXT_LINES
        )

        # Get the vulnerable line itself
        vulnerable_line = ''
        if 0 < line_number <= len(lines):
            vulnerable_line = lines[line_number - 1]

        # Get function scope
        function_info = self._get_function_scope(content, lines, line_number)
        function_scope = ''
        function_body = ''
        function_name = ''

        if function_info:
            function_scope = function_info.signature
            function_name = function_info.name
            function_body = self._extract_function_body(lines, function_info)

        # Get class scope
        class_info = self._get_class_scope(content, lines, line_number)
        class_scope = ''
        class_name = ''

        if class_info:
            class_scope = f"class {class_info.name}"
            if class_info.bases:
                class_scope += f"({', '.join(class_info.bases)})"
            class_name = class_info.name

        # Get imports
        imports = self._extract_imports(lines)

        # Build full context for the agent
        full_context = self._build_full_context(
            lines=lines,
            line_number=line_number,
            function_info=function_info,
            class_info=class_info,
            imports=imports
        )

        result.update({
            'code_snippet': code_snippet,
            'vulnerable_line': vulnerable_line.strip(),
            'full_context': full_context,
            'function_scope': function_scope,
            'function_name': function_name,
            'function_body': function_body,
            'class_scope': class_scope,
            'class_name': class_name,
            'imports': imports,
            'context_start_line': start_line,
            'context_end_line': end_line,
            'total_lines': len(lines),
            'file_content': content  # Full file for reference
        })

        return result

    def _extract_context(
        self,
        lines: List[str],
        line_number: int,
        context_lines: int
    ) -> Tuple[str, int, int]:
        """
        Extract lines around the vulnerable line.

        Args:
            lines: List of file lines
            line_number: Target line number (1-indexed)
            context_lines: Number of lines above and below

        Returns:
            Tuple of (context_string, start_line, end_line)
        """
        if line_number < 1:
            return '', 0, 0

        # Convert to 0-indexed
        idx = line_number - 1

        start = max(0, idx - context_lines)
        end = min(len(lines), idx + context_lines + 1)

        context_lines_list = []
        for i in range(start, end):
            line_num = i + 1
            # Mark the vulnerable line with >>
            marker = " >> " if line_num == line_number else "    "
            context_lines_list.append(f"{line_num:4d}{marker}{lines[i]}")

        return '\n'.join(context_lines_list), start + 1, end

    def _get_function_scope(
        self,
        content: str,
        lines: List[str],
        line_number: int
    ) -> Optional[FunctionInfo]:
        """
        Find the function containing the vulnerable line using AST.

        Args:
            content: Full file content
            lines: List of file lines
            line_number: Target line number (1-indexed)

        Returns:
            FunctionInfo or None if not in a function
        """
        try:
            tree = ast.parse(content)
        except SyntaxError:
            # Fall back to regex-based detection
            return self._get_function_scope_regex(lines, line_number)

        # Find the innermost function containing the line
        best_match: Optional[FunctionInfo] = None

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check if line is within this function
                if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                    if node.lineno <= line_number <= (node.end_lineno or node.lineno):
                        # Check if this is a better (more specific) match
                        if best_match is None or node.lineno > best_match.start_line:
                            # Build signature
                            args = []
                            for arg in node.args.args:
                                arg_str = arg.arg
                                if arg.annotation:
                                    try:
                                        arg_str += f": {ast.unparse(arg.annotation)}"
                                    except Exception:
                                        pass
                                args.append(arg_str)

                            signature = f"def {node.name}({', '.join(args)})"
                            if isinstance(node, ast.AsyncFunctionDef):
                                signature = "async " + signature

                            # Get decorators
                            decorators = []
                            for dec in node.decorator_list:
                                try:
                                    decorators.append(f"@{ast.unparse(dec)}")
                                except Exception:
                                    decorators.append("@<decorator>")

                            # Check if it's a method (inside a class)
                            is_method = False
                            class_name = None
                            for parent in ast.walk(tree):
                                if isinstance(parent, ast.ClassDef):
                                    if hasattr(parent, 'lineno') and hasattr(parent, 'end_lineno'):
                                        if parent.lineno <= node.lineno <= (parent.end_lineno or parent.lineno):
                                            is_method = True
                                            class_name = parent.name
                                            break

                            best_match = FunctionInfo(
                                name=node.name,
                                start_line=node.lineno,
                                end_line=node.end_lineno or node.lineno,
                                signature=signature,
                                decorators=decorators,
                                is_async=isinstance(node, ast.AsyncFunctionDef),
                                is_method=is_method,
                                class_name=class_name
                            )

        return best_match

    def _get_function_scope_regex(
        self,
        lines: List[str],
        line_number: int
    ) -> Optional[FunctionInfo]:
        """
        Fallback regex-based function detection.

        Args:
            lines: List of file lines
            line_number: Target line number (1-indexed)

        Returns:
            FunctionInfo or None
        """
        if line_number < 1 or line_number > len(lines):
            return None

        idx = line_number - 1
        target_indent = len(lines[idx]) - len(lines[idx].lstrip())

        # Search backwards for function definition
        function_pattern = re.compile(r'^(\s*)(async\s+)?def\s+(\w+)\s*\(([^)]*)\)')

        for i in range(idx, -1, -1):
            line = lines[i]
            match = function_pattern.match(line)

            if match:
                func_indent = len(match.group(1))
                # Function must have less indentation than target line
                # or be on the same line
                if func_indent < target_indent or i == idx:
                    is_async = match.group(2) is not None
                    func_name = match.group(3)
                    args = match.group(4)

                    # Find end of function (next line with same or less indentation)
                    end_line = i + 1
                    for j in range(i + 1, len(lines)):
                        stripped = lines[j].strip()
                        if stripped and not stripped.startswith('#'):
                            line_indent = len(lines[j]) - len(lines[j].lstrip())
                            if line_indent <= func_indent:
                                break
                            end_line = j + 1

                    prefix = "async " if is_async else ""
                    signature = f"{prefix}def {func_name}({args})"

                    return FunctionInfo(
                        name=func_name,
                        start_line=i + 1,
                        end_line=end_line,
                        signature=signature,
                        is_async=is_async
                    )

        return None

    def _get_class_scope(
        self,
        content: str,
        lines: List[str],
        line_number: int
    ) -> Optional[ClassInfo]:
        """
        Find the class containing the vulnerable line.

        Args:
            content: Full file content
            lines: List of file lines
            line_number: Target line number (1-indexed)

        Returns:
            ClassInfo or None if not in a class
        """
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return self._get_class_scope_regex(lines, line_number)

        best_match: Optional[ClassInfo] = None

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                    if node.lineno <= line_number <= (node.end_lineno or node.lineno):
                        if best_match is None or node.lineno > best_match.start_line:
                            # Get base classes
                            bases = []
                            for base in node.bases:
                                try:
                                    bases.append(ast.unparse(base))
                                except Exception:
                                    bases.append("<base>")

                            # Get method names
                            methods = []
                            for item in node.body:
                                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                    methods.append(item.name)

                            best_match = ClassInfo(
                                name=node.name,
                                start_line=node.lineno,
                                end_line=node.end_lineno or node.lineno,
                                bases=bases,
                                methods=methods
                            )

        return best_match

    def _get_class_scope_regex(
        self,
        lines: List[str],
        line_number: int
    ) -> Optional[ClassInfo]:
        """
        Fallback regex-based class detection.

        Args:
            lines: List of file lines
            line_number: Target line number (1-indexed)

        Returns:
            ClassInfo or None
        """
        if line_number < 1 or line_number > len(lines):
            return None

        idx = line_number - 1
        target_indent = len(lines[idx]) - len(lines[idx].lstrip())

        class_pattern = re.compile(r'^(\s*)class\s+(\w+)(?:\s*\(([^)]*)\))?')

        for i in range(idx, -1, -1):
            line = lines[i]
            match = class_pattern.match(line)

            if match:
                class_indent = len(match.group(1))
                if class_indent < target_indent:
                    class_name = match.group(2)
                    bases_str = match.group(3) or ''
                    bases = [b.strip() for b in bases_str.split(',') if b.strip()]

                    # Find end of class
                    end_line = i + 1
                    for j in range(i + 1, len(lines)):
                        stripped = lines[j].strip()
                        if stripped and not stripped.startswith('#'):
                            line_indent = len(lines[j]) - len(lines[j].lstrip())
                            if line_indent <= class_indent:
                                break
                            end_line = j + 1

                    return ClassInfo(
                        name=class_name,
                        start_line=i + 1,
                        end_line=end_line,
                        bases=bases
                    )

        return None

    def _extract_function_body(
        self,
        lines: List[str],
        function_info: FunctionInfo
    ) -> str:
        """
        Extract the full function body.

        Args:
            lines: List of file lines
            function_info: Function information

        Returns:
            Full function body as string
        """
        start = function_info.start_line - 1
        end = function_info.end_line

        # Include decorators if present
        if function_info.decorators:
            # Look backwards for decorators
            for i in range(start - 1, max(0, start - 10), -1):
                line = lines[i].strip()
                if line.startswith('@'):
                    start = i
                elif line and not line.startswith('#'):
                    break

        return '\n'.join(lines[start:end])

    def _extract_imports(self, lines: List[str]) -> List[str]:
        """
        Extract import statements from the file.

        Args:
            lines: List of file lines

        Returns:
            List of import statements
        """
        imports = []
        in_multiline_import = False
        current_import = []

        for line in lines:
            stripped = line.strip()

            # Handle multiline imports
            if in_multiline_import:
                current_import.append(stripped)
                if ')' in stripped:
                    imports.append(' '.join(current_import))
                    current_import = []
                    in_multiline_import = False
                continue

            # Check for import statements
            if stripped.startswith(('import ', 'from ')):
                if '(' in stripped and ')' not in stripped:
                    # Start of multiline import
                    in_multiline_import = True
                    current_import = [stripped]
                else:
                    imports.append(stripped)
            elif stripped and not stripped.startswith('#') and not stripped.startswith('"""') and not stripped.startswith("'''"):
                # Stop at first non-import, non-comment, non-docstring line
                # But only if we've seen at least one import
                if imports:
                    break

        return imports

    def _build_full_context(
        self,
        lines: List[str],
        line_number: int,
        function_info: Optional[FunctionInfo],
        class_info: Optional[ClassInfo],
        imports: List[str]
    ) -> str:
        """
        Build full context string for the agent.

        Args:
            lines: List of file lines
            line_number: Target line number
            function_info: Function information
            class_info: Class information
            imports: List of imports

        Returns:
            Formatted context string
        """
        parts = []

        # Imports section
        if imports:
            parts.append("=== IMPORTS ===")
            parts.append('\n'.join(imports))
            parts.append("")

        # Class scope section
        if class_info:
            parts.append("=== CLASS SCOPE ===")
            class_header = f"class {class_info.name}"
            if class_info.bases:
                class_header += f"({', '.join(class_info.bases)})"
            parts.append(class_header)
            if class_info.methods:
                parts.append(f"  Methods: {', '.join(class_info.methods)}")
            parts.append("")

        # Function scope section
        if function_info:
            parts.append("=== FUNCTION SCOPE ===")
            if function_info.decorators:
                parts.extend(function_info.decorators)
            parts.append(function_info.signature)
            parts.append("")

            # Full function body
            parts.append("=== FUNCTION BODY ===")
            function_body = self._extract_function_body(lines, function_info)
            parts.append(function_body)
            parts.append("")

        # Code context section (±20 lines)
        parts.append("=== CODE CONTEXT (±20 lines) ===")
        snippet, _, _ = self._extract_context(lines, line_number, self.DEFAULT_CONTEXT_LINES)
        parts.append(snippet)

        return '\n'.join(parts)

    def get_file_content(self, file_path: str) -> Optional[str]:
        """
        Get full content of a file.

        Args:
            file_path: Path to the file

        Returns:
            File content or None if not found
        """
        content, _ = self._read_file(file_path)
        return content

    def get_file_lines(self, file_path: str) -> Optional[List[str]]:
        """
        Get file content as list of lines.

        Args:
            file_path: Path to the file

        Returns:
            List of lines or None if not found
        """
        _, lines = self._read_file(file_path)
        return lines


def locate_vulnerability(
    vulnerability: Dict[str, Any],
    repo_path: str = ".",
    verbose: bool = True
) -> Dict[str, Any]:
    """
    Convenience function to locate a vulnerability.

    Args:
        vulnerability: Vulnerability dict from FP filter
        repo_path: Root path of the repository
        verbose: Whether to print progress

    Returns:
        Vulnerability dict with code context
    """
    locator = CodeLocator(repo_path, verbose=verbose)
    return locator.locate(vulnerability)


if __name__ == "__main__":
    import json
    import tempfile

    print("=" * 60)
    print("SecureGuard AI - Locator Module Test")
    print("=" * 60)

    # Create a sample file for testing
    sample_code = '''"""Database module for user management."""

import sqlite3
from flask import request, g
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
        """
        Get user by ID.

        WARNING: This method is vulnerable to SQL injection!
        """
        cursor = self.conn.cursor()

        # Vulnerable SQL query - DO NOT USE IN PRODUCTION
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)

        row = cursor.fetchone()
        if row:
            return {'id': row[0], 'name': row[1], 'email': row[2]}
        return None

    def get_user_safe(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Safe version with parameterized query."""
        cursor = self.conn.cursor()

        query = "SELECT * FROM users WHERE id = ?"
        cursor.execute(query, (user_id,))

        row = cursor.fetchone()
        if row:
            return {'id': row[0], 'name': row[1], 'email': row[2]}
        return None


def standalone_vulnerable_function(username: str):
    """A standalone function with XSS vulnerability."""
    from flask import render_template_string

    # Vulnerable to XSS
    template = f"<h1>Welcome, {username}!</h1>"
    return render_template_string(template)


@app.route('/search')
def search():
    """Search endpoint with command injection."""
    import subprocess

    query = request.args.get('q', '')

    # Vulnerable to command injection
    result = subprocess.check_output(f"grep -r '{query}' /data", shell=True)

    return result.decode()
'''

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write sample file
        sample_path = Path(tmpdir) / "app" / "database.py"
        sample_path.parent.mkdir(parents=True, exist_ok=True)
        sample_path.write_text(sample_code)

        # Test locator with different vulnerabilities
        locator = CodeLocator(tmpdir)

        test_cases = [
            {
                'vuln_type': 'sql_injection',
                'file_path': 'app/database.py',
                'line_number': 30,
                'severity': 'HIGH',
                'description': 'SQL injection in get_user method'
            },
            {
                'vuln_type': 'xss',
                'file_path': 'app/database.py',
                'line_number': 52,
                'severity': 'MEDIUM',
                'description': 'XSS in standalone function'
            },
            {
                'vuln_type': 'command_injection',
                'file_path': 'app/database.py',
                'line_number': 63,
                'severity': 'HIGH',
                'description': 'Command injection in search endpoint'
            },
        ]

        for i, test_vuln in enumerate(test_cases, 1):
            print(f"\n--- Test Case {i}: {test_vuln['vuln_type']} ---")

            result = locator.locate(test_vuln)

            print(f"File: {result.get('file_path')}:{result.get('line_number')}")
            print(f"Vulnerable line: {result.get('vulnerable_line', '')[:60]}...")
            print(f"Function: {result.get('function_name', 'N/A')}")
            print(f"Class: {result.get('class_name', 'N/A')}")
            print(f"Context lines: {result.get('context_start_line')} - {result.get('context_end_line')}")
            print(f"Imports found: {len(result.get('imports', []))}")

            if result.get('function_scope'):
                print(f"Function scope: {result['function_scope']}")

        # Print full context for first test case
        print("\n--- Full Context for Test Case 1 ---")
        result = locator.locate(test_cases[0])
        print(result.get('full_context', ''))

    print("\n" + "=" * 60)
    print("Locator tests completed!")
    print("=" * 60)
