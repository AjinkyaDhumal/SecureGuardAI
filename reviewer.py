"""
SecureGuard AI - Reviewer Module

This module handles human-in-the-loop review for fixes.
It displays diffs, fix summaries, and captures developer approval.

Responsibilities:
- Display git diff for proposed fix
- Show fix summary and test results
- Prompt for developer approval (Apply fix? y/n)
- Support both interactive and automatic modes
- Return decision: approved / rejected

Modes:
- Interactive: Pause for human approval
- Automatic: Auto-approve all fixes (for CI/CD)

Output Schema:
{
    ...input_data,
    review_decision: 'approved' | 'rejected' | 'skipped',
    reviewed: bool,
    reviewer_notes: str (optional)
}
"""

from typing import Dict, Any, Optional, List
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
import sys


class ReviewMode(str, Enum):
    """Review mode options."""
    INTERACTIVE = "interactive"
    AUTOMATIC = "automatic"


class ReviewDecision(str, Enum):
    """Review decision options."""
    APPROVED = "approved"
    REJECTED = "rejected"
    SKIPPED = "skipped"


@dataclass
class ReviewConfig:
    """Configuration for the reviewer."""
    mode: ReviewMode = ReviewMode.INTERACTIVE
    auto_approve_verified: bool = False
    show_full_diff: bool = False
    max_diff_lines: int = 30
    color_output: bool = True


@dataclass
class ReviewResult:
    """Result of a review."""
    decision: ReviewDecision
    vulnerability_type: str
    file_path: str
    timestamp: datetime = field(default_factory=datetime.now)
    notes: str = ""
    reviewer: str = "human"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'review_decision': self.decision.value,
            'reviewed': True,
            'review_timestamp': self.timestamp.isoformat(),
            'reviewer_notes': self.notes,
            'reviewer': self.reviewer
        }


class FixReviewer:
    """
    Handles human-in-the-loop review for fixes.
    
    Shows:
    - Diff
    - Summary
    - Test results
    
    Asks: Apply fix? (y/n)
    
    Returns decision: approved / rejected
    """
    
    def __init__(
        self,
        mode: ReviewMode = ReviewMode.INTERACTIVE,
        config: Optional[ReviewConfig] = None
    ):
        """
        Initialize the reviewer.
        
        Args:
            mode: Review mode (interactive or automatic)
            config: Optional ReviewConfig for customization
        """
        self.mode = mode
        self.config = config or ReviewConfig(mode=mode)
        self.review_history: List[ReviewResult] = []
        
        # ANSI color codes
        if self.config.color_output:
            self.colors = {
                'reset': '\033[0m',
                'bold': '\033[1m',
                'red': '\033[91m',
                'green': '\033[92m',
                'yellow': '\033[93m',
                'blue': '\033[94m',
                'cyan': '\033[96m',
                'gray': '\033[90m'
            }
        else:
            self.colors = {k: '' for k in ['reset', 'bold', 'red', 'green', 'yellow', 'blue', 'cyan', 'gray']}
    
    def review(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Review a proposed fix.
        
        Shows:
        - Diff
        - Summary
        - Test results
        
        Asks: Apply fix? (y/n)
        
        Returns decision: approved / rejected
        
        Args:
            vulnerability: Vulnerability dict with fix and validation data
            
        Returns:
            Vulnerability dict with review decision added
        """
        result = vulnerability.copy()
        
        vuln_type = vulnerability.get('vuln_type', 'unknown')
        file_path = vulnerability.get('file_path', 'unknown')
        status = vulnerability.get('status', 'UNKNOWN')
        
        if self.mode == ReviewMode.AUTOMATIC:
            # Auto-approve in automatic mode
            decision = ReviewDecision.APPROVED
            notes = "Auto-approved (automatic mode)"
            print(f"[Reviewer] ✓ Auto-approved: {vuln_type} in {file_path}")
        else:
            # Check if we should auto-approve verified fixes
            if self.config.auto_approve_verified and status == 'VERIFIED':
                decision = ReviewDecision.APPROVED
                notes = "Auto-approved (verified fix)"
                print(f"[Reviewer] ✓ Auto-approved verified fix: {vuln_type} in {file_path}")
            else:
                # Interactive review
                decision, notes = self._interactive_review(vulnerability)
        
        # Create review result
        review_result = ReviewResult(
            decision=decision,
            vulnerability_type=vuln_type,
            file_path=file_path,
            notes=notes,
            reviewer="automatic" if self.mode == ReviewMode.AUTOMATIC else "human"
        )
        
        result.update(review_result.to_dict())
        self.review_history.append(review_result)
        
        return result
    
    def _interactive_review(self, vulnerability: Dict[str, Any]) -> tuple:
        """
        Perform interactive review with user input.
        
        Shows:
        1. Summary
        2. Diff
        3. Test results
        
        Asks: Apply fix? (y/n)
        
        Args:
            vulnerability: Vulnerability dict
            
        Returns:
            Tuple of (ReviewDecision, notes)
        """
        c = self.colors
        
        # Display review information
        self._display_summary(vulnerability)
        self._display_diff(vulnerability)
        self._display_test_results(vulnerability)
        
        # Prompt for decision
        print(f"\n{c['bold']}{'=' * 60}{c['reset']}")
        print(f"{c['bold']}REVIEW DECISION{c['reset']}")
        print(f"{'=' * 60}")
        print(f"\n{c['cyan']}Options:{c['reset']}")
        print(f"  {c['green']}[y]{c['reset']} Approve - Apply this fix")
        print(f"  {c['red']}[n]{c['reset']} Reject  - Do not apply this fix")
        print(f"  {c['yellow']}[s]{c['reset']} Skip    - Skip for now, review later")
        print(f"  {c['blue']}[d]{c['reset']} Details - Show more details")
        
        while True:
            try:
                choice = input(f"\n{c['bold']}Apply fix? (y/n): {c['reset']}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print(f"\n{c['yellow']}[Reviewer] Non-interactive environment, auto-approving{c['reset']}")
                return ReviewDecision.APPROVED, "Auto-approved (non-interactive)"
            
            if choice in ['y', 'yes']:
                print(f"\n{c['green']}[Reviewer] ✓ Fix APPROVED{c['reset']}")
                return ReviewDecision.APPROVED, "Approved by reviewer"
            elif choice in ['n', 'no']:
                reason = self._get_rejection_reason()
                print(f"\n{c['red']}[Reviewer] ✗ Fix REJECTED{c['reset']}")
                return ReviewDecision.REJECTED, reason or "Rejected by reviewer"
            elif choice == 's':
                print(f"\n{c['yellow']}[Reviewer] ⏭ Fix SKIPPED{c['reset']}")
                return ReviewDecision.SKIPPED, "Skipped for later review"
            elif choice == 'd':
                self._display_details(vulnerability)
            else:
                print(f"{c['yellow']}Invalid choice. Please enter y or n.{c['reset']}")
    
    def _get_rejection_reason(self) -> str:
        """Get optional rejection reason from user."""
        try:
            reason = input("Rejection reason (optional, press Enter to skip): ").strip()
            return reason
        except (EOFError, KeyboardInterrupt):
            return ""
    
    def _display_summary(self, vulnerability: Dict[str, Any]) -> None:
        """Display vulnerability summary."""
        c = self.colors
        
        print(f"\n{c['bold']}{'=' * 60}{c['reset']}")
        print(f"{c['bold']}📋 VULNERABILITY SUMMARY{c['reset']}")
        print(f"{'=' * 60}")
        
        vuln_type = vulnerability.get('vuln_type', 'unknown')
        file_path = vulnerability.get('file_path', 'unknown')
        line_number = vulnerability.get('line_number', 0)
        severity = vulnerability.get('severity', 'UNKNOWN')
        status = vulnerability.get('status', 'UNKNOWN')
        
        # Color-code severity
        severity_color = {
            'CRITICAL': c['red'], 'HIGH': c['red'],
            'MEDIUM': c['yellow'], 'LOW': c['green']
        }.get(severity.upper(), c['gray'])
        
        # Color-code status
        status_color = c['green'] if status in ['VERIFIED', 'FIXED'] else c['yellow'] if status == 'SYNTAX_ONLY' else c['red']
        
        print(f"\n  {c['bold']}Type:{c['reset']}     {vuln_type.replace('_', ' ').title()}")
        print(f"  {c['bold']}File:{c['reset']}     {file_path}")
        print(f"  {c['bold']}Line:{c['reset']}     {line_number}")
        print(f"  {c['bold']}Severity:{c['reset']} {severity_color}{severity}{c['reset']}")
        print(f"  {c['bold']}Status:{c['reset']}   {status_color}{status}{c['reset']}")
        
        description = vulnerability.get('description', '')
        if description:
            print(f"\n  {c['bold']}Description:{c['reset']}")
            print(f"    {description[:100]}{'...' if len(description) > 100 else ''}")
    
    def _display_diff(self, vulnerability: Dict[str, Any]) -> None:
        """Display the diff with syntax highlighting."""
        c = self.colors
        
        print(f"\n{c['bold']}{'=' * 60}{c['reset']}")
        print(f"{c['bold']}📝 DIFF{c['reset']}")
        print(f"{'=' * 60}")
        
        diff_text = vulnerability.get('diff_text', '')
        if not diff_text:
            print(f"\n  {c['gray']}No diff available{c['reset']}")
            return
        
        diff_lines = diff_text.split('\n')
        max_lines = self.config.max_diff_lines if not self.config.show_full_diff else len(diff_lines)
        
        print()
        for line in diff_lines[:max_lines]:
            if line.startswith('+++') or line.startswith('---'):
                print(f"  {c['bold']}{line}{c['reset']}")
            elif line.startswith('+'):
                print(f"  {c['green']}{line}{c['reset']}")
            elif line.startswith('-'):
                print(f"  {c['red']}{line}{c['reset']}")
            elif line.startswith('@@'):
                print(f"  {c['cyan']}{line}{c['reset']}")
            elif line.startswith('diff --git'):
                print(f"  {c['bold']}{line}{c['reset']}")
            else:
                print(f"  {line}")
        
        if len(diff_lines) > max_lines:
            remaining = len(diff_lines) - max_lines
            print(f"\n  {c['gray']}... ({remaining} more lines, press 'd' for full diff){c['reset']}")
    
    def _display_test_results(self, vulnerability: Dict[str, Any]) -> None:
        """Display test results."""
        c = self.colors
        
        print(f"\n{c['bold']}{'=' * 60}{c['reset']}")
        print(f"{c['bold']}🧪 TEST RESULTS{c['reset']}")
        print(f"{'=' * 60}")
        
        tests_passed = vulnerability.get('tests_passed', 0)
        tests_failed = vulnerability.get('tests_failed', 0)
        tests_total = vulnerability.get('tests_total', tests_passed + tests_failed)
        status = vulnerability.get('status', 'UNKNOWN')
        
        if status == 'VERIFIED':
            status_icon = f"{c['green']}✓{c['reset']}"
        elif status == 'SYNTAX_ONLY':
            status_icon = f"{c['yellow']}⚠{c['reset']}"
        else:
            status_icon = f"{c['red']}✗{c['reset']}"
        
        print(f"\n  {c['bold']}Status:{c['reset']}  {status_icon} {status}")
        print(f"  {c['bold']}Passed:{c['reset']}  {c['green']}{tests_passed}{c['reset']}")
        print(f"  {c['bold']}Failed:{c['reset']}  {c['red']}{tests_failed}{c['reset']}")
        print(f"  {c['bold']}Total:{c['reset']}   {tests_total}")
        
        if tests_failed > 0:
            test_output = vulnerability.get('test_output', '')
            if test_output:
                print(f"\n  {c['bold']}Test Output (excerpt):{c['reset']}")
                for line in test_output.split('\n')[:5]:
                    print(f"    {c['gray']}{line[:70]}{c['reset']}")
    
    def _display_details(self, vulnerability: Dict[str, Any]) -> None:
        """Display detailed information about the fix."""
        c = self.colors
        
        print(f"\n{c['bold']}{'-' * 60}{c['reset']}")
        print(f"{c['bold']}DETAILED INFORMATION{c['reset']}")
        print(f"{'-' * 60}")
        
        # Full diff
        print(f"\n{c['bold']}📄 FULL DIFF:{c['reset']}")
        diff_text = vulnerability.get('diff_text', 'No diff available')
        for line in diff_text.split('\n'):
            if line.startswith('+') and not line.startswith('+++'):
                print(f"  {c['green']}{line}{c['reset']}")
            elif line.startswith('-') and not line.startswith('---'):
                print(f"  {c['red']}{line}{c['reset']}")
            elif line.startswith('@@'):
                print(f"  {c['cyan']}{line}{c['reset']}")
            else:
                print(f"  {line}")
        
        # Test output
        print(f"\n{c['bold']}🧪 TEST OUTPUT:{c['reset']}")
        test_output = vulnerability.get('test_output', 'No test output available')
        print(f"  {c['gray']}{test_output[:1000]}{c['reset']}")
        
        # Fix reasoning
        print(f"\n{c['bold']}💡 FIX REASONING:{c['reset']}")
        reasoning = vulnerability.get('reasoning_chain', [])
        if reasoning:
            for i, step in enumerate(reasoning, 1):
                print(f"  {i}. {step}")
        else:
            print(f"  {c['gray']}No reasoning chain available{c['reset']}")
        
        print(f"\n{'-' * 60}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get review summary."""
        approved = sum(1 for r in self.review_history if r.decision == ReviewDecision.APPROVED)
        rejected = sum(1 for r in self.review_history if r.decision == ReviewDecision.REJECTED)
        skipped = sum(1 for r in self.review_history if r.decision == ReviewDecision.SKIPPED)
        
        return {
            'total_reviewed': len(self.review_history),
            'approved': approved,
            'rejected': rejected,
            'skipped': skipped,
            'mode': self.mode.value,
            'history': [
                {
                    'vuln_type': r.vulnerability_type,
                    'file_path': r.file_path,
                    'decision': r.decision.value,
                    'notes': r.notes
                }
                for r in self.review_history
            ]
        }
    
    def print_summary(self) -> None:
        """Print a formatted summary of all reviews."""
        c = self.colors
        summary = self.get_summary()
        
        print(f"\n{c['bold']}{'=' * 60}{c['reset']}")
        print(f"{c['bold']}📊 REVIEW SUMMARY{c['reset']}")
        print(f"{'=' * 60}")
        
        print(f"\n  {c['bold']}Mode:{c['reset']}     {summary['mode']}")
        print(f"  {c['bold']}Total:{c['reset']}    {summary['total_reviewed']}")
        print(f"  {c['green']}Approved:{c['reset']} {summary['approved']}")
        print(f"  {c['red']}Rejected:{c['reset']} {summary['rejected']}")
        print(f"  {c['yellow']}Skipped:{c['reset']}  {summary['skipped']}")
        
        if summary['history']:
            print(f"\n  {c['bold']}Details:{c['reset']}")
            for item in summary['history']:
                dc = c['green'] if item['decision'] == 'approved' else c['red'] if item['decision'] == 'rejected' else c['yellow']
                print(f"    • {item['vuln_type']} in {item['file_path']}: {dc}{item['decision']}{c['reset']}")


def review_fix(
    vulnerability: Dict[str, Any],
    mode: str = "interactive"
) -> Dict[str, Any]:
    """
    Convenience function to review a fix.
    
    Args:
        vulnerability: Vulnerability dict
        mode: Review mode ('interactive' or 'automatic')
        
    Returns:
        Vulnerability dict with review decision (approved/rejected)
    """
    review_mode = ReviewMode.AUTOMATIC if mode == "automatic" else ReviewMode.INTERACTIVE
    reviewer = FixReviewer(review_mode)
    return reviewer.review(vulnerability)


def review_fixes_batch(
    vulnerabilities: List[Dict[str, Any]],
    mode: str = "interactive"
) -> List[Dict[str, Any]]:
    """
    Review multiple fixes in batch.
    
    Args:
        vulnerabilities: List of vulnerability dicts
        mode: Review mode ('interactive' or 'automatic')
        
    Returns:
        List of vulnerability dicts with review decisions
    """
    review_mode = ReviewMode.AUTOMATIC if mode == "automatic" else ReviewMode.INTERACTIVE
    reviewer = FixReviewer(review_mode)
    
    results = []
    for vuln in vulnerabilities:
        result = reviewer.review(vuln)
        results.append(result)
    
    reviewer.print_summary()
    return results


# ============================================================================
# TEST HARNESS
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("SecureGuard AI - Reviewer Module Test")
    print("=" * 70)
    
    test_vuln = {
        'vuln_type': 'sql_injection',
        'file_path': 'app/database.py',
        'line_number': 10,
        'severity': 'HIGH',
        'status': 'VERIFIED',
        'description': 'SQL injection vulnerability: user input directly concatenated into query',
        'tests_passed': 5,
        'tests_failed': 0,
        'test_output': 'All 5 tests passed\n===== 5 passed in 0.12s =====',
        'diff_text': '''diff --git a/app/database.py b/app/database.py
index abc1234..def5678 100644
--- a/app/database.py
+++ b/app/database.py
@@ -5,8 +5,8 @@ def get_user(user_id):
     conn = sqlite3.connect('users.db')
     cursor = conn.cursor()
     
-    query = f"SELECT * FROM users WHERE id = {user_id}"
-    cursor.execute(query)
+    query = "SELECT * FROM users WHERE id = ?"
+    cursor.execute(query, (user_id,))
     
     return cursor.fetchone()''',
        'code_snippet': 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        'proposed_fix': 'query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (user_id,))',
        'reasoning_chain': [
            'Identified SQL injection via string formatting',
            'User input (user_id) directly interpolated into query',
            'Replaced with parameterized query using ? placeholder',
            'Verified fix passes all existing tests'
        ]
    }
    
    # Test 1: Automatic mode
    print("\n" + "=" * 70)
    print("TEST 1: Automatic Mode")
    print("=" * 70)
    
    reviewer = FixReviewer(ReviewMode.AUTOMATIC)
    result = reviewer.review(test_vuln)
    print(f"\nDecision: {result.get('review_decision')}")
    print(f"Reviewed: {result.get('reviewed')}")
    reviewer.print_summary()
    
    # Test 2: Batch automatic mode
    print("\n" + "=" * 70)
    print("TEST 2: Batch Automatic Mode")
    print("=" * 70)
    
    test_vulns = [
        test_vuln,
        {
            'vuln_type': 'xss',
            'file_path': 'app/views.py',
            'line_number': 25,
            'severity': 'MEDIUM',
            'status': 'VERIFIED',
            'tests_passed': 3,
            'tests_failed': 0,
            'diff_text': '- return f"<div>{user_input}</div>"\n+ return f"<div>{escape(user_input)}</div>"'
        },
        {
            'vuln_type': 'hardcoded_secrets',
            'file_path': 'config/settings.py',
            'line_number': 5,
            'severity': 'CRITICAL',
            'status': 'UNVERIFIED',
            'tests_passed': 0,
            'tests_failed': 1,
            'diff_text': '- API_KEY = "sk-1234567890"\n+ API_KEY = os.environ.get("API_KEY")'
        }
    ]
    
    results = review_fixes_batch(test_vulns, mode="automatic")
    print(f"\nProcessed {len(results)} vulnerabilities")
    
    # Test 3: Interactive mode info
    print("\n" + "=" * 70)
    print("TEST 3: Interactive Mode (Demo)")
    print("=" * 70)
    print("\nIn interactive mode, the reviewer would display:")
    print("  1. Summary (type, file, severity, status)")
    print("  2. Diff (color-coded additions/deletions)")
    print("  3. Test results (passed/failed counts)")
    print("  4. Prompt: 'Apply fix? (y/n)'")
    print("\nTo test interactive mode, run:")
    print("  reviewer = FixReviewer(ReviewMode.INTERACTIVE)")
    print("  result = reviewer.review(vulnerability)")
    
    print("\n" + "=" * 70)
    print("Reviewer module test completed!")
    print("=" * 70)
