"""
SecureGuard AI - Feedback Loop Module

This module implements the retry logic with context accumulation.
It captures test results, injects failure context, and decides when to escalate.

Key Features:
- Maximum 3 retry attempts
- Each retry includes previous fixes, test failures, and reasoning history
- Prompts agent to identify wrong assumptions before retrying
- Returns VERIFIED or UNVERIFIED status with best fix

Workflow:
    1. Generate initial fix
    2. Validate fix (syntax + tests)
    3. If PASS → return VERIFIED
    4. If FAIL → inject failure context into prompt
    5. Ask: "What assumption was wrong? What will you change?"
    6. Retry with improved context
    7. After 3 attempts → return UNVERIFIED with best fix
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

# Ensure parent directory is in path
_parent_dir = Path(__file__).parent.parent
if str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))

from agent.tools import run_tests_tool


# ============================================================================
# DATA CLASSES
# ============================================================================

class FixStatus(str, Enum):
    """Status of the fix attempt."""
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    IN_PROGRESS = "IN_PROGRESS"
    ERROR = "ERROR"


@dataclass
class AttemptResult:
    """Result of a single fix attempt."""
    attempt_number: int
    fix_code: str
    tests_passed: int
    tests_failed: int
    test_output: str
    validation_status: str  # PASSED, FAILED, SYNTAX_ERROR
    reasoning: List[str] = field(default_factory=list)
    reflection: Optional[str] = None  # Agent's reflection on what went wrong

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'attempt_number': self.attempt_number,
            'fix_code': self.fix_code,
            'tests_passed': self.tests_passed,
            'tests_failed': self.tests_failed,
            'test_output': self.test_output,
            'validation_status': self.validation_status,
            'reasoning': self.reasoning,
            'reflection': self.reflection
        }


@dataclass
class FeedbackLoopConfig:
    """Configuration for the feedback loop."""
    max_attempts: int = 3
    escalate_on_failure: bool = True
    include_full_history: bool = True
    verbose: bool = True


@dataclass
class FeedbackLoopResult:
    """Result of the feedback loop execution."""
    status: FixStatus
    fix: str
    attempts: List[AttemptResult]
    best_attempt_number: int
    total_attempts: int
    reasoning_chain: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'status': self.status.value,
            'fix': self.fix,
            'attempts': [a.to_dict() for a in self.attempts],
            'best_attempt_number': self.best_attempt_number,
            'total_attempts': self.total_attempts,
            'reasoning_chain': self.reasoning_chain
        }


# ============================================================================
# PROMPT BUILDERS
# ============================================================================

def build_initial_prompt(vulnerability: Dict[str, Any], fix_template: str = "") -> str:
    """
    Build the initial prompt for the first fix attempt.

    Args:
        vulnerability: Dict containing vulnerability details
        fix_template: Optional fix template/strategy

    Returns:
        Formatted prompt string for the agent
    """
    code = vulnerability.get('code_snippet', '') or vulnerability.get('code', '')
    context = vulnerability.get('code_context', '') or vulnerability.get('full_context', '')

    template_section = ""
    if fix_template:
        template_section = f"""
FIX STRATEGY:
{fix_template}
"""

    return f"""Fix the following security vulnerability:

VULNERABILITY DETAILS:
- Type: {vulnerability.get('vuln_type', 'unknown')}
- File: {vulnerability.get('file_path', 'unknown')}
- Line: {vulnerability.get('line_number', 'unknown')}
- Severity: {vulnerability.get('severity', 'unknown')}
- Description: {vulnerability.get('description', 'No description provided')}
{template_section}
VULNERABLE CODE:
```
{code}
```

FULL CONTEXT:
```
{context}
```

INSTRUCTIONS:
1. Analyze the vulnerability carefully
2. Generate a minimal, targeted fix
3. Preserve the original code structure and style
4. Ensure the fix is syntactically correct

Return ONLY the fixed code. No explanations, no markdown code blocks."""


def build_retry_prompt(
    vulnerability: Dict[str, Any],
    previous_attempts: List[AttemptResult],
    fix_template: str = ""
) -> str:
    """
    Build a retry prompt that includes previous failure context.

    This prompt forces the agent to reflect on what went wrong
    before generating a new fix.

    Args:
        vulnerability: Dict containing vulnerability details
        previous_attempts: List of previous AttemptResult objects
        fix_template: Optional fix template/strategy

    Returns:
        Formatted retry prompt string
    """
    # Build attempt history
    attempt_history = ""
    for attempt in previous_attempts:
        status_emoji = "✗" if attempt.validation_status != "PASSED" else "✓"
        attempt_history += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ATTEMPT {attempt.attempt_number}: {status_emoji} {attempt.validation_status}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

YOUR FIX:
```
{attempt.fix_code}
```

TEST RESULT: {attempt.tests_passed} passed, {attempt.tests_failed} failed

FAILURE OUTPUT:
{attempt.test_output[:500] if attempt.test_output else 'No output'}
"""
        if attempt.reflection:
            attempt_history += f"""
YOUR REFLECTION:
{attempt.reflection}
"""

    code = vulnerability.get('code_snippet', '') or vulnerability.get('code', '')
    context = vulnerability.get('code_context', '') or vulnerability.get('full_context', '')

    template_section = ""
    if fix_template:
        template_section = f"""
FIX STRATEGY (use this as guidance):
{fix_template}
"""

    return f"""You are fixing: {vulnerability.get('vuln_type', 'unknown')}
in {vulnerability.get('file_path', 'unknown')} at line {vulnerability.get('line_number', 'unknown')}.

⚠️  YOUR PREVIOUS ATTEMPTS FAILED. Review the history below:
{attempt_history}

ORIGINAL VULNERABLE CODE:
```
{code}
```

FULL CONTEXT:
```
{context}
```
{template_section}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BEFORE GENERATING A NEW FIX, YOU MUST ANSWER:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. **What assumption was wrong?**
   - What did you assume about the code, API, or behavior that turned out to be incorrect?

2. **What will you change?**
   - Based on the test failure, what specific change will you make differently this time?

3. **Why will this fix work?**
   - Explain why your new approach will succeed where the previous one failed.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Now generate a NEW fix that addresses the root cause.
Return ONLY the fixed code. No explanations, no markdown code blocks."""


def build_reflection_prompt(
    attempt: AttemptResult,
    vulnerability: Dict[str, Any]
) -> str:
    """
    Build a prompt to get the agent's reflection on a failed attempt.

    Args:
        attempt: The failed attempt result
        vulnerability: Dict containing vulnerability details

    Returns:
        Formatted reflection prompt
    """
    return f"""Your fix for {vulnerability.get('vuln_type', 'unknown')} FAILED validation.

YOUR FIX:
```
{attempt.fix_code}
```

FAILURE OUTPUT:
{attempt.test_output[:500] if attempt.test_output else 'No output'}

Answer these questions concisely (2-3 sentences each):

1. **What assumption was wrong?**
   What did you assume that turned out to be incorrect?

2. **What will you change?**
   What specific change will you make in your next attempt?

Be specific and actionable. This reflection will guide your next fix attempt."""


# ============================================================================
# CODE EXTRACTION
# ============================================================================

def extract_code_from_response(response: str) -> str:
    """
    Extract code from the agent's response.

    Handles:
    - Markdown code blocks (```python ... ```)
    - Plain code responses
    - Mixed content (extracts code portion)

    Args:
        response: Raw response string from the agent

    Returns:
        Extracted code string
    """
    if not response:
        return ""

    response = response.strip()

    # Handle markdown code blocks
    if "```" in response:
        lines = response.split('\n')
        code_lines = []
        in_code_block = False

        for line in lines:
            if line.strip().startswith("```"):
                if in_code_block:
                    # End of code block
                    break
                else:
                    # Start of code block
                    in_code_block = True
                    continue

            if in_code_block:
                code_lines.append(line)

        if code_lines:
            return '\n'.join(code_lines)

    # No code blocks found, return as-is
    return response


# ============================================================================
# VALIDATION
# ============================================================================

def validate_fix(file_path: str, fix_code: str, test_command: str = "") -> Dict[str, Any]:
    """
    Validate a fix by applying it and running tests.

    Args:
        file_path: Path to the original file
        fix_code: The proposed fix code
        test_command: Optional test command to run

    Returns:
        Dict with validation results
    """
    try:
        result_json = run_tests_tool.invoke({
            'file_path': file_path,
            'fix_code': fix_code,
            'test_command': test_command
        })

        return json.loads(result_json)
    except Exception as e:
        return {
            'passed': 0,
            'failed': 1,
            'errors': 1,
            'output': str(e),
            'status': 'ERROR'
        }


# ============================================================================
# FEEDBACK LOOP CLASS
# ============================================================================

class FeedbackLoop:
    """
    Manages the retry loop with failure context injection.

    This class:
    1. Tracks all fix attempts with their results
    2. Injects failure context into retry prompts
    3. Forces reflection on failed attempts
    4. Selects the best fix after max attempts
    """

    def __init__(self, config: Optional[FeedbackLoopConfig] = None):
        """Initialize the feedback loop."""
        self.config = config or FeedbackLoopConfig()
        self.attempts: List[AttemptResult] = []
        self.reasoning_chain: List[str] = []

    def reset(self):
        """Reset the feedback loop state."""
        self.attempts = []
        self.reasoning_chain = []

    def get_prompt(
        self,
        vulnerability: Dict[str, Any],
        fix_template: str = ""
    ) -> str:
        """
        Get the appropriate prompt based on current attempt number.

        Args:
            vulnerability: Dict containing vulnerability details
            fix_template: Optional fix template/strategy

        Returns:
            Formatted prompt string
        """
        if len(self.attempts) == 0:
            return build_initial_prompt(vulnerability, fix_template)
        else:
            return build_retry_prompt(vulnerability, self.attempts, fix_template)

    def record_attempt(
        self,
        fix_code: str,
        test_result: Dict[str, Any],
        reflection: Optional[str] = None
    ) -> AttemptResult:
        """
        Record a fix attempt and its results.

        Args:
            fix_code: The fix code that was attempted
            test_result: Results from validation
            reflection: Optional agent reflection on failure

        Returns:
            The recorded AttemptResult
        """
        attempt_num = len(self.attempts) + 1

        attempt = AttemptResult(
            attempt_number=attempt_num,
            fix_code=fix_code,
            tests_passed=test_result.get('passed', 0),
            tests_failed=test_result.get('failed', 0),
            test_output=test_result.get('output', ''),
            validation_status=test_result.get('status', 'UNKNOWN'),
            reasoning=[],
            reflection=reflection
        )

        self.attempts.append(attempt)

        # Update reasoning chain
        status = test_result.get('status', 'UNKNOWN')
        if status in ['PASSED', 'SYNTAX_OK']:
            self.reasoning_chain.append(f"[Attempt {attempt_num}] ✓ Fix validated successfully")
        else:
            self.reasoning_chain.append(
                f"[Attempt {attempt_num}] ✗ Fix failed: {status} - {test_result.get('output', '')[:100]}"
            )

        return attempt

    def should_continue(self) -> bool:
        """Check if we should continue trying."""
        if len(self.attempts) >= self.config.max_attempts:
            return False

        # Check if last attempt passed
        if self.attempts and self.attempts[-1].validation_status in ['PASSED', 'SYNTAX_OK']:
            return False

        return True

    def get_best_attempt(self) -> Optional[AttemptResult]:
        """
        Get the best attempt based on test results.

        Priority:
        1. Any attempt that passed
        2. Attempt with fewest failures
        3. Most recent attempt
        """
        if not self.attempts:
            return None

        # First, check for any passing attempt
        for attempt in self.attempts:
            if attempt.validation_status in ['PASSED', 'SYNTAX_OK']:
                return attempt

        # Find attempt with fewest failures (prefer syntax OK over syntax error)
        def score_attempt(a: AttemptResult) -> tuple:
            # Lower is better: (has_syntax_error, failed_count, -attempt_num)
            has_syntax_error = 1 if a.validation_status == 'SYNTAX_ERROR' else 0
            return (has_syntax_error, a.tests_failed, -a.attempt_number)

        return min(self.attempts, key=score_attempt)

    def get_result(self) -> FeedbackLoopResult:
        """
        Get the final result of the feedback loop.

        Returns:
            FeedbackLoopResult with status, best fix, and history
        """
        best = self.get_best_attempt()

        if best and best.validation_status in ['PASSED', 'SYNTAX_OK']:
            status = FixStatus.VERIFIED
        else:
            status = FixStatus.UNVERIFIED

        return FeedbackLoopResult(
            status=status,
            fix=best.fix_code if best else "",
            attempts=self.attempts,
            best_attempt_number=best.attempt_number if best else 0,
            total_attempts=len(self.attempts),
            reasoning_chain=self.reasoning_chain
        )

    def run(
        self,
        vulnerability: Dict[str, Any],
        generate_fix_fn: Callable[[str], str],
        fix_template: str = "",
        generate_reflection_fn: Optional[Callable[[str], str]] = None
    ) -> FeedbackLoopResult:
        """
        Run the complete feedback loop.

        Args:
            vulnerability: Dict containing vulnerability details
            generate_fix_fn: Function that takes a prompt and returns fix code
            fix_template: Optional fix template/strategy
            generate_reflection_fn: Optional function to generate reflection

        Returns:
            FeedbackLoopResult with final status and best fix
        """
        self.reset()

        if self.config.verbose:
            print(f"\n[FeedbackLoop] Starting remediation for: {vulnerability.get('vuln_type')}")
            print(f"[FeedbackLoop] Max attempts: {self.config.max_attempts}")

        while self.should_continue():
            attempt_num = len(self.attempts) + 1

            if self.config.verbose:
                print(f"\n[FeedbackLoop] ━━━ Attempt {attempt_num}/{self.config.max_attempts} ━━━")

            # Get the prompt
            prompt = self.get_prompt(vulnerability, fix_template)

            # Generate fix
            try:
                raw_response = generate_fix_fn(prompt)
                fix_code = extract_code_from_response(raw_response)
            except Exception as e:
                if self.config.verbose:
                    print(f"[FeedbackLoop] Error generating fix: {e}")
                fix_code = ""

            if not fix_code:
                if self.config.verbose:
                    print("[FeedbackLoop] No fix code generated")
                self.record_attempt(
                    fix_code="",
                    test_result={'passed': 0, 'failed': 1, 'output': 'No fix generated', 'status': 'ERROR'}
                )
                continue

            if self.config.verbose:
                print(f"[FeedbackLoop] Generated fix ({len(fix_code)} chars)")

            # Validate the fix
            test_result = validate_fix(
                vulnerability.get('file_path', ''),
                fix_code
            )

            status = test_result.get('status', 'UNKNOWN')
            if self.config.verbose:
                if status in ['PASSED', 'SYNTAX_OK']:
                    print(f"[FeedbackLoop] ✓ Validation PASSED")
                else:
                    print(f"[FeedbackLoop] ✗ Validation FAILED: {status}")

            # Generate reflection if failed and function provided
            reflection = None
            if status not in ['PASSED', 'SYNTAX_OK'] and generate_reflection_fn:
                try:
                    attempt_for_reflection = AttemptResult(
                        attempt_number=attempt_num,
                        fix_code=fix_code,
                        tests_passed=test_result.get('passed', 0),
                        tests_failed=test_result.get('failed', 0),
                        test_output=test_result.get('output', ''),
                        validation_status=status
                    )
                    reflection_prompt = build_reflection_prompt(attempt_for_reflection, vulnerability)
                    reflection = generate_reflection_fn(reflection_prompt)

                    if self.config.verbose and reflection:
                        print(f"[FeedbackLoop] Reflection: {reflection[:100]}...")
                except Exception as e:
                    if self.config.verbose:
                        print(f"[FeedbackLoop] Error generating reflection: {e}")

            # Record the attempt
            self.record_attempt(fix_code, test_result, reflection)

            # Check if we succeeded
            if status in ['PASSED', 'SYNTAX_OK']:
                if self.config.verbose:
                    print(f"\n[FeedbackLoop] ✓ Fix VERIFIED on attempt {attempt_num}")
                break

        result = self.get_result()

        if self.config.verbose:
            print(f"\n[FeedbackLoop] ━━━ Final Result ━━━")
            print(f"[FeedbackLoop] Status: {result.status.value}")
            print(f"[FeedbackLoop] Total attempts: {result.total_attempts}")
            print(f"[FeedbackLoop] Best attempt: #{result.best_attempt_number}")

        return result


# ============================================================================
# CONVENIENCE FUNCTION
# ============================================================================

def run_with_feedback(
    generate_fix_fn: Callable[[str], str],
    vulnerability: Dict[str, Any],
    config: Optional[FeedbackLoopConfig] = None,
    fix_template: str = "",
    generate_reflection_fn: Optional[Callable[[str], str]] = None
) -> Dict[str, Any]:
    """
    Run the feedback loop on a vulnerability.

    This is the main entry point for using the feedback loop.

    Args:
        generate_fix_fn: Function that takes a prompt and returns fix code
        vulnerability: Dict containing vulnerability details
        config: Optional FeedbackLoopConfig
        fix_template: Optional fix template/strategy
        generate_reflection_fn: Optional function to generate reflection

    Returns:
        Dict with status (VERIFIED/UNVERIFIED), fix, and attempts history
    """
    loop = FeedbackLoop(config)
    result = loop.run(
        vulnerability=vulnerability,
        generate_fix_fn=generate_fix_fn,
        fix_template=fix_template,
        generate_reflection_fn=generate_reflection_fn
    )
    return result.to_dict()


# ============================================================================
# TEST HARNESS
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("SecureGuard AI - Feedback Loop Test")
    print("=" * 70)

    # Test vulnerability
    test_vuln = {
        'vuln_type': 'sql_injection',
        'file_path': 'sample_vulns/sql_injection.py',
        'line_number': 10,
        'severity': 'HIGH',
        'description': 'SQL injection vulnerability: user input concatenated into query',
        'code_snippet': 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        'code_context': '''import sqlite3

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()'''
    }

    # Mock fix generator that improves on each attempt
    attempt_counter = [0]

    def mock_generate_fix(prompt: str) -> str:
        attempt_counter[0] += 1

        if attempt_counter[0] == 1:
            # First attempt: still has issues
            return '''def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query)  # Missing parameter!
    return cursor.fetchone()'''
        elif attempt_counter[0] == 2:
            # Second attempt: better but syntax issue
            return '''def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()'''
        else:
            # Third attempt: correct
            return '''import sqlite3

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()'''

    def mock_generate_reflection(prompt: str) -> str:
        return "I assumed the cursor.execute would work without parameters. I will add the user_id as a parameter tuple."

    # Test the feedback loop
    print("\n--- Testing Feedback Loop ---\n")

    config = FeedbackLoopConfig(max_attempts=3, verbose=True)

    result = run_with_feedback(
        generate_fix_fn=mock_generate_fix,
        vulnerability=test_vuln,
        config=config,
        generate_reflection_fn=mock_generate_reflection
    )

    print("\n--- Final Result ---")
    print(json.dumps({
        'status': result['status'],
        'total_attempts': result['total_attempts'],
        'best_attempt_number': result['best_attempt_number']
    }, indent=2))

    print("\n--- Best Fix ---")
    print(result['fix'])

    print("\n--- Reasoning Chain ---")
    for step in result['reasoning_chain']:
        print(f"  • {step}")

    print("\n" + "=" * 70)
    print("Feedback loop test completed!")
    print("=" * 70)
