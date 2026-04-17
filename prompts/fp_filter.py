"""
SecureGuard AI - False Positive Filter Prompts Module

This module contains prompts for false positive filtering.
It evaluates confidence and reachability before committing to a fix attempt.

Filter Checks:
- Is this a test file?
- Is the code reachable?
- Does the pattern actually exist at the reported line?
- Is the vulnerability already mitigated?
"""

from typing import Dict, Any, Optional


FP_FILTER_SYSTEM_PROMPT = """
You are a security analyst evaluating whether a vulnerability finding is a true positive or false positive.

Your job is to analyze the code context and determine:
1. Is this a real vulnerability that needs fixing?
2. What is your confidence level (0.0 to 1.0)?
3. What is your reasoning?

Consider these factors:
- Is this a test file? (test_*.py, *_test.py, *mock*, *fixture*)
- Is the vulnerable code actually reachable in production?
- Does the reported line actually contain the vulnerability pattern?
- Is there already mitigation in place (sanitization, validation)?
- Could this be a scanner false positive?

Return your analysis in a structured format.
"""


FP_FILTER_PROMPT_TEMPLATE = """
Evaluate this vulnerability finding:

Vulnerability Type: {vuln_type}
File Path: {file_path}
Line Number: {line_number}
Severity: {severity}
Scanner Description: {description}

Code Context:
```
{code_context}
```

Analyze and respond with:
1. IS_FALSE_POSITIVE: true or false
2. CONFIDENCE: 0.0 to 1.0 (how confident are you in your assessment)
3. REASONING: Brief explanation of your decision
4. RECOMMENDATION: SKIP, FIX, or REVIEW_MANUALLY
"""


def get_fp_filter_prompt(vulnerability: Dict[str, Any], code_context: str) -> str:
    """
    Generate the false positive filter prompt for a vulnerability.

    Args:
        vulnerability: Dict containing vulnerability details
        code_context: The code context around the vulnerable line

    Returns:
        Formatted prompt string for FP evaluation
    """
    return FP_FILTER_PROMPT_TEMPLATE.format(
        vuln_type=vulnerability.get('vuln_type', 'unknown'),
        file_path=vulnerability.get('file_path', 'unknown'),
        line_number=vulnerability.get('line_number', 'unknown'),
        severity=vulnerability.get('severity', 'unknown'),
        description=vulnerability.get('description', 'No description'),
        code_context=code_context
    )


def parse_fp_response(response: str) -> Dict[str, Any]:
    """
    Parse the LLM response for false positive evaluation.

    Args:
        response: Raw LLM response string

    Returns:
        Dict with is_false_positive, confidence, reasoning, recommendation
    """
    # TODO: Implement in Phase 2
    # - Parse structured response
    # - Extract confidence score
    # - Extract reasoning

    result = {
        'is_false_positive': False,
        'confidence': 0.5,
        'reasoning': 'Not implemented',
        'recommendation': 'REVIEW_MANUALLY'
    }

    # Basic parsing logic (to be enhanced)
    response_lower = response.lower()

    if 'is_false_positive: true' in response_lower:
        result['is_false_positive'] = True
    elif 'is_false_positive: false' in response_lower:
        result['is_false_positive'] = False

    # Extract confidence if present
    import re
    confidence_match = re.search(r'confidence:\s*([\d.]+)', response_lower)
    if confidence_match:
        try:
            result['confidence'] = float(confidence_match.group(1))
        except ValueError:
            pass

    return result


def evaluate_false_positive(
    vulnerability: Dict[str, Any],
    code_context: str,
    llm_client=None
) -> Dict[str, Any]:
    """
    Evaluate whether a vulnerability is a false positive.

    Args:
        vulnerability: Dict containing vulnerability details
        code_context: The code context around the vulnerable line
        llm_client: Optional LLM client for evaluation

    Returns:
        Dict with evaluation results
    """
    # TODO: Implement in Phase 2
    # - Call LLM with FP filter prompt
    # - Parse response
    # - Return structured result

    print(f"[FP Filter] Evaluating: {vulnerability.get('vuln_type')} in {vulnerability.get('file_path')}")

    # Quick heuristic checks (before LLM call)
    file_path = vulnerability.get('file_path', '')

    # Check if test file
    is_test_file = any(pattern in file_path.lower() for pattern in [
        'test_', '_test.', 'tests/', '/test/', 'mock', 'fixture', 'conftest'
    ])

    if is_test_file:
        return {
            'is_false_positive': True,
            'confidence': 0.9,
            'fp_reason': 'File appears to be a test file',
            'recommendation': 'SKIP'
        }

    # Default: needs LLM evaluation
    return {
        'is_false_positive': False,
        'confidence': 0.5,
        'fp_reason': 'Requires LLM evaluation (not implemented)',
        'recommendation': 'REVIEW_MANUALLY'
    }


def is_above_threshold(confidence: float, threshold: float = 0.75) -> bool:
    """
    Check if confidence is above the filter threshold.

    Args:
        confidence: The confidence score (0.0 to 1.0)
        threshold: The minimum threshold (default 0.75)

    Returns:
        True if confidence >= threshold
    """
    return confidence >= threshold


# Common false positive patterns
FP_PATTERNS = {
    'test_file': [
        r'test_.*\.py$',
        r'.*_test\.py$',
        r'.*/tests/.*',
        r'.*mock.*',
        r'.*fixture.*',
        r'conftest\.py$',
    ],
    'commented_code': [
        r'^\s*#',
        r'^\s*"""',
        r"^\s*'''",
    ],
    'already_mitigated': {
        'sql_injection': [
            r'execute\s*\([^,]+,\s*\(',  # Parameterized query
            r'\.format\s*\(\s*\)',  # Empty format (no user input)
        ],
        'xss': [
            r'html\.escape',
            r'markupsafe\.escape',
            r'autoescape\s*=\s*True',
        ],
    }
}


if __name__ == "__main__":
    # Test the FP filter module
    print("SecureGuard AI - False Positive Filter Module")
    print("=" * 40)

    test_vuln = {
        'vuln_type': 'sql_injection',
        'file_path': 'app/database.py',
        'line_number': 42,
        'severity': 'HIGH',
        'description': 'Possible SQL injection'
    }

    test_context = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
'''

    result = evaluate_false_positive(test_vuln, test_context)
    print(f"Evaluation result: {result}")

    # Test with test file
    test_vuln_test = {
        'vuln_type': 'sql_injection',
        'file_path': 'tests/test_database.py',
        'line_number': 10,
        'severity': 'HIGH',
        'description': 'Possible SQL injection'
    }

    result = evaluate_false_positive(test_vuln_test, test_context)
    print(f"Test file evaluation: {result}")
