"""
SecureGuard AI - Prompts Module

This module contains prompt templates for:
- fix_templates.py: 24 vulnerability-specific fix templates
- fp_filter.py: False positive filtering prompts
"""

from .fix_templates import get_fix_template, VULNERABILITY_TEMPLATES
from .fp_filter import get_fp_filter_prompt, evaluate_false_positive

__all__ = [
    'get_fix_template',
    'VULNERABILITY_TEMPLATES',
    'get_fp_filter_prompt',
    'evaluate_false_positive',
]
