"""
SecureGuard AI - Patch Generator Module

This module generates git-compatible patch files from fixes.
It creates unified diff format patches that can be applied with git apply.

Responsibilities:
- Generate unified diff between original and fixed file
- Output standard .patch file format compatible with `git apply`
- Support git diff header format

Output Schema:
{
    ...validator_output,
    patch_file_path: str,
    diff_text: str,
    patch_filename: str,
    lines_added: int,
    lines_removed: int
}
"""

import difflib
import hashlib
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass


@dataclass
class PatchStats:
    """Statistics about a patch."""
    lines_added: int = 0
    lines_removed: int = 0
    hunks: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'lines_added': self.lines_added,
            'lines_removed': self.lines_removed,
            'hunks': self.hunks
        }


class PatchGenerator:
    """
    Generates git-compatible patch files.
    
    Creates unified diff format patches from original and fixed code.
    The patches are compatible with `git apply` command.
    """
    
    def __init__(self, output_dir: str = "output", verbose: bool = True):
        """
        Initialize the patch generator.
        
        Args:
            output_dir: Directory to write patch files
            verbose: Whether to print status messages
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
    
    def generate(
        self,
        vulnerability: Dict[str, Any],
        original_code: str,
        fixed_code: str
    ) -> Dict[str, Any]:
        """
        Generate a patch file for a fix.
        
        Args:
            vulnerability: Vulnerability dict with validation results
            original_code: Original file content
            fixed_code: Fixed file content
            
        Returns:
            Vulnerability dict with patch info added
        """
        result = vulnerability.copy()
        file_path = vulnerability.get('file_path', 'unknown.py')
        
        if self.verbose:
            print(f"[PatchGen] Generating patch for: {file_path}")
        
        # Generate git-compatible diff
        diff_text, stats = self._generate_git_diff(original_code, fixed_code, file_path)
        
        if not diff_text.strip():
            if self.verbose:
                print(f"[PatchGen] No changes detected")
            result.update({
                'patch_file_path': None,
                'diff_text': '',
                'patch_filename': None,
                'no_changes': True
            })
            return result
        
        # Generate patch filename
        patch_filename = self._generate_patch_filename(vulnerability)
        patch_path = self.output_dir / patch_filename
        
        # Write patch file
        try:
            patch_path.write_text(diff_text, encoding='utf-8')
            if self.verbose:
                print(f"[PatchGen] ✓ Wrote patch: {patch_path}")
                print(f"[PatchGen]   +{stats.lines_added} -{stats.lines_removed} lines, {stats.hunks} hunk(s)")
        except Exception as e:
            if self.verbose:
                print(f"[PatchGen] ✗ Error writing patch: {e}")
            result.update({
                'patch_file_path': None,
                'diff_text': diff_text,
                'patch_error': str(e)
            })
            return result
        
        result.update({
            'patch_file_path': str(patch_path),
            'diff_text': diff_text,
            'patch_filename': patch_filename,
            **stats.to_dict()
        })
        
        return result
    
    def _generate_git_diff(
        self,
        original: str,
        fixed: str,
        file_path: str
    ) -> Tuple[str, PatchStats]:
        """
        Generate a git-compatible unified diff.
        
        This produces output compatible with `git apply`.
        
        Args:
            original: Original file content
            fixed: Fixed file content
            file_path: Path to the file (for header)
            
        Returns:
            Tuple of (diff_text, PatchStats)
        """
        # Normalize line endings
        original = original.replace('\r\n', '\n')
        fixed = fixed.replace('\r\n', '\n')
        
        # Split into lines (keeping line endings for accurate diff)
        original_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)
        
        # Ensure files end with newline
        if original_lines and not original_lines[-1].endswith('\n'):
            original_lines[-1] += '\n'
        if fixed_lines and not fixed_lines[-1].endswith('\n'):
            fixed_lines[-1] += '\n'
        
        # Handle empty files
        if not original_lines:
            original_lines = []
        if not fixed_lines:
            fixed_lines = []
        
        # Generate unified diff
        diff_lines = list(difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm='\n'
        ))
        
        if not diff_lines:
            return '', PatchStats()
        
        # Build git-compatible patch header
        git_header = self._build_git_header(file_path, original, fixed)
        
        # Calculate stats
        stats = self._calculate_stats(diff_lines)
        
        # Combine header and diff
        # Remove the first two lines from unified_diff (--- and +++) as we'll use git format
        diff_body = ''.join(diff_lines)
        
        # Build complete patch
        patch = git_header + diff_body
        
        return patch, stats
    
    def _build_git_header(self, file_path: str, original: str, fixed: str) -> str:
        """
        Build a git-compatible diff header.
        
        Args:
            file_path: Path to the file
            original: Original content (for hash)
            fixed: Fixed content (for hash)
            
        Returns:
            Git diff header string
        """
        # Calculate blob hashes (simplified - git uses SHA1 of "blob <size>\0<content>")
        orig_hash = hashlib.sha1(original.encode()).hexdigest()[:7]
        fixed_hash = hashlib.sha1(fixed.encode()).hexdigest()[:7]
        
        # Git diff header format
        header = f"""diff --git a/{file_path} b/{file_path}
index {orig_hash}..{fixed_hash} 100644
"""
        return header
    
    def _calculate_stats(self, diff_lines: List[str]) -> PatchStats:
        """
        Calculate patch statistics.
        
        Args:
            diff_lines: Lines of the diff
            
        Returns:
            PatchStats with counts
        """
        stats = PatchStats()
        
        for line in diff_lines:
            if line.startswith('@@'):
                stats.hunks += 1
            elif line.startswith('+') and not line.startswith('+++'):
                stats.lines_added += 1
            elif line.startswith('-') and not line.startswith('---'):
                stats.lines_removed += 1
        
        return stats
    
    def _generate_patch_filename(self, vulnerability: Dict[str, Any]) -> str:
        """
        Generate a unique patch filename.
        
        Args:
            vulnerability: Vulnerability dict
            
        Returns:
            Patch filename string
        """
        vuln_type = vulnerability.get('vuln_type', 'fix')
        file_path = vulnerability.get('file_path', 'unknown')
        line_number = vulnerability.get('line_number', 0)
        
        # Clean up file path for filename
        clean_path = Path(file_path).stem
        
        # Sanitize vuln_type for filename
        safe_vuln_type = ''.join(c if c.isalnum() or c == '_' else '_' for c in vuln_type)
        
        # Add timestamp for uniqueness
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        return f"{safe_vuln_type}_{clean_path}_L{line_number}_{timestamp}.patch"
    
    def generate_combined_patch(
        self,
        patches: List[Dict[str, Any]],
        output_name: str = "combined.patch"
    ) -> Dict[str, Any]:
        """
        Combine multiple patches into one file.
        
        Args:
            patches: List of patch dicts with diff_text
            output_name: Name for combined patch file
            
        Returns:
            Dict with combined patch info
        """
        combined_parts = []
        total_stats = PatchStats()
        
        for patch in patches:
            diff_text = patch.get('diff_text', '')
            if diff_text:
                combined_parts.append(diff_text)
                total_stats.lines_added += patch.get('lines_added', 0)
                total_stats.lines_removed += patch.get('lines_removed', 0)
                total_stats.hunks += patch.get('hunks', 0)
        
        if not combined_parts:
            return {
                'patch_file_path': None,
                'diff_text': '',
                'error': 'No patches to combine'
            }
        
        combined_text = '\n'.join(combined_parts)
        combined_path = self.output_dir / output_name
        
        try:
            combined_path.write_text(combined_text, encoding='utf-8')
            if self.verbose:
                print(f"[PatchGen] ✓ Wrote combined patch: {combined_path}")
                print(f"[PatchGen]   {len(patches)} patches, +{total_stats.lines_added} -{total_stats.lines_removed} lines")
        except Exception as e:
            return {
                'patch_file_path': None,
                'diff_text': combined_text,
                'error': str(e)
            }
        
        return {
            'patch_file_path': str(combined_path),
            'patch_filename': output_name,
            'diff_text': combined_text,
            'patch_count': len(patches),
            **total_stats.to_dict()
        }
    
    def verify_patch(self, patch_text: str) -> Dict[str, Any]:
        """
        Verify that a patch is valid git diff format.
        
        Args:
            patch_text: The patch content to verify
            
        Returns:
            Dict with verification results
        """
        issues = []
        
        lines = patch_text.split('\n')
        
        # Check for git diff header
        has_diff_header = any(line.startswith('diff --git') for line in lines)
        if not has_diff_header:
            issues.append("Missing 'diff --git' header")
        
        # Check for index line
        has_index = any(line.startswith('index ') for line in lines)
        if not has_index:
            issues.append("Missing 'index' line")
        
        # Check for --- and +++ lines
        has_from = any(line.startswith('--- ') for line in lines)
        has_to = any(line.startswith('+++ ') for line in lines)
        if not has_from:
            issues.append("Missing '--- a/...' line")
        if not has_to:
            issues.append("Missing '+++ b/...' line")
        
        # Check for at least one hunk
        has_hunk = any(line.startswith('@@') for line in lines)
        if not has_hunk:
            issues.append("Missing hunk header (@@)")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues
        }


def generate_patch(
    vulnerability: Dict[str, Any],
    original_code: str,
    fixed_code: str,
    output_dir: str = "output",
    verbose: bool = True
) -> Dict[str, Any]:
    """
    Convenience function to generate a patch.
    
    Args:
        vulnerability: Vulnerability dict
        original_code: Original file content
        fixed_code: Fixed file content
        output_dir: Directory for patch output
        verbose: Whether to print status messages
        
    Returns:
        Vulnerability dict with patch info
    """
    generator = PatchGenerator(output_dir, verbose=verbose)
    return generator.generate(vulnerability, original_code, fixed_code)


# ============================================================================
# TEST HARNESS
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("SecureGuard AI - Patch Generator Test")
    print("=" * 70)
    
    original_code = '''import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    return cursor.fetchone()
'''
    
    fixed_code = '''import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Fixed: Using parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    
    return cursor.fetchone()
'''
    
    test_vuln = {
        'vuln_type': 'sql_injection',
        'file_path': 'app/database.py',
        'line_number': 8,
        'severity': 'HIGH',
        'status': 'VERIFIED'
    }
    
    print("\n--- Generating Patch ---")
    generator = PatchGenerator(verbose=True)
    result = generator.generate(test_vuln, original_code, fixed_code)
    
    print(f"\n--- Patch File ---")
    print(f"Path: {result.get('patch_file_path')}")
    print(f"Lines added: +{result.get('lines_added', 0)}")
    print(f"Lines removed: -{result.get('lines_removed', 0)}")
    
    print(f"\n--- Diff Content ---")
    print(result.get('diff_text', ''))
    
    # Verify the patch
    print("\n--- Verifying Patch ---")
    verification = generator.verify_patch(result.get('diff_text', ''))
    print(f"Valid: {verification['valid']}")
    if verification['issues']:
        print(f"Issues: {verification['issues']}")
    
    # Test git apply compatibility
    print("\n--- Git Apply Test ---")
    print("To apply this patch, run:")
    print(f"  git apply {result.get('patch_filename', 'patch.patch')}")
    
    print("\n" + "=" * 70)
    print("Patch generator test completed!")
    print("=" * 70)
