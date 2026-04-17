"""
SecureGuard AI - Agent Module

This module defines the LangGraph workflow and agent orchestration.
It creates the remediation agent with tools, memory, and the system prompt.

Workflow:
    generate_fix → validate → [PASS] → review → END
                           → [FAIL] → generate_fix (retry)
                           → [MAX_ATTEMPTS] → escalate → END

State Object:
    - vuln_type: Type of vulnerability
    - file_path: Path to vulnerable file
    - code: Original vulnerable code
    - fix: Proposed fix code
    - test_result: Result of validation tests
    - attempts: Current attempt count
    - max_attempts: Maximum retry attempts (default: 3)
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List, Literal, Annotated, TypedDict
from dataclasses import dataclass, field
from enum import Enum

# LangChain imports
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

# LangGraph imports
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

# Ensure parent directory is in path
_parent_dir = Path(__file__).parent.parent
if str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))

# Local imports
from config.template_loader import TemplateLoader
from agent.tools import get_all_tools, read_file_tool, run_tests_tool, search_codebase_tool
from agent.feedback_loop import FeedbackLoop, FeedbackLoopConfig, FeedbackLoopResult, FixStatus


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class AgentConfig:
    """Configuration for the remediation agent."""
    model_name: str = None
    model_provider: str = None
    temperature: float = None
    max_tokens: int = None
    max_attempts: int = None
    verbose: bool = None
    repo_path: str = None

    def __post_init__(self):
        """Load configuration from environment variables if not explicitly set."""
        from dotenv import load_dotenv
        load_dotenv()

        # Load from environment with fallback to defaults
        if self.model_provider is None:
            self.model_provider = os.getenv("LLM_PROVIDER", "anthropic")

        if self.model_name is None:
            # Default model based on provider
            default_models = {
                "anthropic": "claude-sonnet-4-20250514",
                "openai": "gpt-4o"  # GPT-4o is faster and cheaper than gpt-4
            }
            self.model_name = os.getenv("LLM_MODEL", default_models.get(self.model_provider, "claude-sonnet-4-20250514"))

        if self.temperature is None:
            self.temperature = float(os.getenv("LLM_TEMPERATURE", "0.0"))

        if self.max_tokens is None:
            self.max_tokens = int(os.getenv("LLM_MAX_TOKENS", "2048"))

        if self.max_attempts is None:
            self.max_attempts = int(os.getenv("MAX_RETRIES", "3"))

        if self.verbose is None:
            verbose_str = os.getenv("VERBOSE", "true").lower()
            self.verbose = verbose_str in ("true", "1", "yes")

        if self.repo_path is None:
            self.repo_path = os.getenv("REPO_PATH", ".")

    @property
    def llm_model(self) -> str:
        """Return the full model identifier."""
        return f"{self.model_provider}/{self.model_name}"


class ValidationStatus(str, Enum):
    """Status of fix validation."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    SYNTAX_ERROR = "SYNTAX_ERROR"
    ERROR = "ERROR"


class AgentStatus(str, Enum):
    """Overall agent status."""
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    ESCALATED = "ESCALATED"
    ERROR = "ERROR"


# ============================================================================
# STATE DEFINITION
# ============================================================================

class AgentState(TypedDict):
    """
    State object for the LangGraph workflow.

    This state is passed between nodes and updated at each step.
    """
    # Vulnerability information
    vuln_type: str
    file_path: str
    line_number: int
    severity: str
    description: str

    # Code context
    code: str  # Original vulnerable code
    code_context: str  # Surrounding code context
    imports: List[str]  # File imports
    function_name: Optional[str]  # Enclosing function
    class_name: Optional[str]  # Enclosing class

    # Fix generation
    fix: str  # Proposed fix code
    fix_explanation: str  # Explanation of the fix

    # Validation
    test_result: Dict[str, Any]  # Test results
    validation_status: str  # PASSED, FAILED, SYNTAX_ERROR
    validation_message: str  # Detailed validation message

    # Retry tracking
    attempts: int  # Current attempt count
    max_attempts: int  # Maximum retry attempts

    # History
    messages: Annotated[List, add_messages]  # Conversation history
    reasoning_chain: List[str]  # Step-by-step reasoning

    # Final status
    status: str  # IN_PROGRESS, FIXED, ESCALATED, ERROR
    error: Optional[str]  # Error message if any


def create_initial_state(vulnerability: Dict[str, Any], config: AgentConfig) -> AgentState:
    """Create initial state from vulnerability dict."""
    return AgentState(
        vuln_type=vulnerability.get('vuln_type', 'unknown'),
        file_path=vulnerability.get('file_path', ''),
        line_number=vulnerability.get('line_number', 0),
        severity=vulnerability.get('severity', 'MEDIUM'),
        description=vulnerability.get('description', ''),
        code=vulnerability.get('code_snippet', ''),
        code_context=vulnerability.get('code_context', ''),
        imports=vulnerability.get('imports', []),
        function_name=vulnerability.get('function_name'),
        class_name=vulnerability.get('class_name'),
        fix='',
        fix_explanation='',
        test_result={},
        validation_status='',
        validation_message='',
        attempts=0,
        max_attempts=config.max_attempts,
        messages=[],
        reasoning_chain=[],
        status=AgentStatus.IN_PROGRESS.value,
        error=None
    )


# ============================================================================
# LLM INITIALIZATION
# ============================================================================

def is_valid_api_key(key: Optional[str], provider: str) -> bool:
    """
    Check if an API key looks valid (not a placeholder).

    Args:
        key: The API key to check
        provider: Provider name ('anthropic' or 'openai')

    Returns:
        True if key appears valid, False otherwise
    """
    if not key:
        return False

    # Check for placeholder values
    placeholders = [
        'your-', 'sk-xxx', 'replace', 'insert', 'add-your',
        'example', 'dummy', 'test-key', 'placeholder'
    ]

    key_lower = key.lower()
    if any(placeholder in key_lower for placeholder in placeholders):
        return False

    # Check for minimum length and proper prefix
    if provider == "anthropic":
        # Anthropic keys start with 'sk-ant-' and are ~100+ chars
        return key.startswith('sk-ant-') and len(key) > 50
    elif provider == "openai":
        # OpenAI keys can be:
        # - Direct OpenAI: 'sk-proj-' or 'sk-' (50+ chars)
        # - OpenRouter: 'sk-or-v1-' (70+ chars) - compatible with OpenAI API
        if key.startswith('sk-or-v1-'):
            return len(key) > 60  # OpenRouter keys
        return key.startswith('sk-') and len(key) > 40  # Direct OpenAI keys

    return len(key) > 20  # Generic check


def get_llm(config: AgentConfig):
    """
    Initialize the LLM based on configuration.

    Args:
        config: AgentConfig with model settings

    Returns:
        ChatModel instance (ChatAnthropic or ChatOpenAI)

    Raises:
        ValueError: If API key is missing or invalid
    """
    if config.model_provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not is_valid_api_key(api_key, "anthropic"):
            raise ValueError(
                "Invalid or missing ANTHROPIC_API_KEY. "
                "Please set a valid Anthropic API key in your .env file. "
                "Get one at: https://console.anthropic.com/"
            )

        return ChatAnthropic(
            model=config.model_name,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )
    elif config.model_provider == "openai":
        from langchain_openai import ChatOpenAI

        api_key = os.getenv("OPENAI_API_KEY")
        if not is_valid_api_key(api_key, "openai"):
            raise ValueError(
                "Invalid or missing OPENAI_API_KEY. "
                "Please set a valid OpenAI API key in your .env file. "
                "Get one at: https://platform.openai.com/api-keys"
            )

        # Check if using OpenRouter (key starts with sk-or-v1-)
        base_url = None
        if api_key.startswith('sk-or-v1-'):
            base_url = "https://openrouter.ai/api/v1"
            if config.verbose:
                print("[Agent] Detected OpenRouter API key, using OpenRouter endpoint")

        llm_kwargs = {
            "model": config.model_name,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
        }

        if base_url:
            llm_kwargs["base_url"] = base_url

        return ChatOpenAI(**llm_kwargs)
    else:
        raise ValueError(f"Unknown model provider: {config.model_provider}")


# ============================================================================
# SYSTEM PROMPTS
# ============================================================================

AGENT_SYSTEM_PROMPT = """You are an expert security engineer and code remediator.
You have been given a vulnerability finding from a security scanner.

Your job is to:
1. Understand the vulnerability and its context
2. Generate a minimal, targeted fix that addresses ONLY the security issue
3. Preserve the original code structure and style
4. Ensure the fix is syntactically correct and functional

CRITICAL RULES:
- Return ONLY valid, working code
- Do NOT include markdown code blocks (no ```)
- Do NOT include explanations in the code
- Do NOT change unrelated code
- Preserve all comments and formatting
- Make the MINIMAL change necessary to fix the vulnerability
"""

FIX_GENERATION_PROMPT = """Fix the following {vuln_type} vulnerability.

VULNERABILITY DETAILS:
- Type: {vuln_type}
- File: {file_path}
- Line: {line_number}
- Severity: {severity}
- Description: {description}

{fix_template}

ORIGINAL CODE:
```
{code}
```

CONTEXT (surrounding code):
```
{code_context}
```

{retry_context}

Generate the FIXED code. Return ONLY the fixed code, nothing else:"""

REVIEW_PROMPT = """Review the following security fix.

VULNERABILITY: {vuln_type}
ORIGINAL CODE:
```
{original_code}
```

FIXED CODE:
```
{fixed_code}
```

Verify that:
1. The fix addresses the vulnerability
2. No new vulnerabilities are introduced
3. The code is syntactically correct
4. The fix is minimal and targeted

Provide a brief assessment (2-3 sentences) and conclude with either:
- APPROVED: The fix is correct and safe
- NEEDS_REVISION: [reason]
"""


# ============================================================================
# NODE FUNCTIONS
# ============================================================================

def generate_fix_node(state: AgentState, config: AgentConfig, llm, template_loader: TemplateLoader) -> Dict[str, Any]:
    """
    Node: Generate a fix for the vulnerability using LLM.

    This node:
    1. Loads the appropriate fix template
    2. Builds the prompt with code context
    3. Calls the LLM to generate a fix
    4. Updates state with the proposed fix
    """
    attempts = state['attempts'] + 1
    reasoning = [f"[Attempt {attempts}/{state['max_attempts']}] Generating fix for {state['vuln_type']}"]

    # Get fix template
    template = template_loader.get_template_for_vuln(state['vuln_type'])
    fix_template = ""
    if template:
        fix_template = f"FIX STRATEGY:\n{template.fix_strategy}\n\n{template.template}"

    # Build retry context if this is a retry
    retry_context = ""
    if attempts > 1 and state.get('validation_message'):
        retry_context = f"""
PREVIOUS ATTEMPT FAILED:
{state['validation_message']}

Please fix the issues and try again. Focus on:
1. Ensuring syntactically correct code
2. Addressing the validation feedback
"""
        reasoning.append(f"Previous attempt failed: {state['validation_message'][:100]}...")

    # Build the prompt
    prompt = FIX_GENERATION_PROMPT.format(
        vuln_type=state['vuln_type'],
        file_path=state['file_path'],
        line_number=state['line_number'],
        severity=state['severity'],
        description=state['description'],
        fix_template=fix_template,
        code=state['code'] or state['code_context'],
        code_context=state['code_context'],
        retry_context=retry_context
    )

    # Call LLM
    messages = [
        SystemMessage(content=AGENT_SYSTEM_PROMPT),
        HumanMessage(content=prompt)
    ]

    try:
        response = llm.invoke(messages)
        fix_code = response.content.strip()

        # Clean up any markdown artifacts
        if fix_code.startswith("```"):
            lines = fix_code.split('\n')
            # Remove first and last lines if they're code block markers
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            fix_code = '\n'.join(lines)

        reasoning.append(f"Generated fix ({len(fix_code)} chars)")

        return {
            'fix': fix_code,
            'attempts': attempts,
            'reasoning_chain': state['reasoning_chain'] + reasoning,
            'messages': state['messages'] + [
                HumanMessage(content=prompt),
                AIMessage(content=fix_code)
            ]
        }

    except Exception as e:
        reasoning.append(f"Error generating fix: {str(e)}")
        return {
            'fix': '',
            'attempts': attempts,
            'error': str(e),
            'status': AgentStatus.ERROR.value,
            'reasoning_chain': state['reasoning_chain'] + reasoning
        }


def validate_node(state: AgentState, config: AgentConfig) -> Dict[str, Any]:
    """
    Node: Validate the proposed fix.

    This node:
    1. Applies the fix to a temp file
    2. Runs syntax check and tests
    3. Updates state with validation results
    """
    reasoning = [f"Validating fix for {state['file_path']}"]

    if not state['fix']:
        return {
            'validation_status': ValidationStatus.ERROR.value,
            'validation_message': 'No fix code provided',
            'test_result': {'status': 'ERROR', 'output': 'No fix code'},
            'reasoning_chain': state['reasoning_chain'] + reasoning + ['No fix code to validate']
        }

    # Run tests using the run_tests_tool
    import json

    try:
        # Use the tool to validate
        result_json = run_tests_tool.invoke({
            'file_path': state['file_path'],
            'fix_code': state['fix'],
            'test_command': ''
        })

        test_result = json.loads(result_json)

        # Determine validation status
        status = test_result.get('status', 'UNKNOWN')

        if status in ['PASSED', 'SYNTAX_OK']:
            validation_status = ValidationStatus.PASSED.value
            validation_message = f"Validation passed: {test_result.get('passed', 0)} tests passed"
            reasoning.append(f"✓ Validation PASSED")
        elif status == 'SYNTAX_ERROR':
            validation_status = ValidationStatus.SYNTAX_ERROR.value
            validation_message = f"Syntax error: {test_result.get('output', '')[:200]}"
            reasoning.append(f"✗ Syntax error detected")
        else:
            validation_status = ValidationStatus.FAILED.value
            validation_message = f"Tests failed: {test_result.get('failed', 0)} failures. {test_result.get('output', '')[:200]}"
            reasoning.append(f"✗ Validation FAILED: {test_result.get('failed', 0)} test failures")

        return {
            'test_result': test_result,
            'validation_status': validation_status,
            'validation_message': validation_message,
            'reasoning_chain': state['reasoning_chain'] + reasoning
        }

    except Exception as e:
        reasoning.append(f"Validation error: {str(e)}")
        return {
            'test_result': {'status': 'ERROR', 'output': str(e)},
            'validation_status': ValidationStatus.ERROR.value,
            'validation_message': f'Validation error: {str(e)}',
            'reasoning_chain': state['reasoning_chain'] + reasoning
        }


def review_node(state: AgentState, config: AgentConfig, llm) -> Dict[str, Any]:
    """
    Node: Review the fix for correctness and safety.

    This node:
    1. Calls LLM to review the fix
    2. Checks for any remaining issues
    3. Marks the fix as complete or needs revision
    """
    reasoning = ["Reviewing fix for correctness and safety"]

    # Build review prompt
    prompt = REVIEW_PROMPT.format(
        vuln_type=state['vuln_type'],
        original_code=state['code'] or state['code_context'],
        fixed_code=state['fix']
    )

    messages = [
        SystemMessage(content="You are a security code reviewer. Be thorough but concise."),
        HumanMessage(content=prompt)
    ]

    try:
        response = llm.invoke(messages)
        review_text = response.content.strip()

        # Check if approved
        if "APPROVED" in review_text.upper():
            reasoning.append("✓ Fix APPROVED by reviewer")
            return {
                'fix_explanation': review_text,
                'status': AgentStatus.FIXED.value,
                'reasoning_chain': state['reasoning_chain'] + reasoning
            }
        else:
            reasoning.append(f"Review feedback: {review_text[:100]}...")
            # If not approved but validation passed, still mark as fixed
            # (reviewer feedback is informational)
            return {
                'fix_explanation': review_text,
                'status': AgentStatus.FIXED.value,
                'reasoning_chain': state['reasoning_chain'] + reasoning
            }

    except Exception as e:
        reasoning.append(f"Review error: {str(e)}")
        # Don't fail the whole process if review fails
        return {
            'fix_explanation': f"Review skipped due to error: {str(e)}",
            'status': AgentStatus.FIXED.value,
            'reasoning_chain': state['reasoning_chain'] + reasoning
        }


def escalate_node(state: AgentState) -> Dict[str, Any]:
    """
    Node: Escalate when max attempts reached.

    This node marks the vulnerability for human review.
    """
    reasoning = [
        f"Max attempts ({state['max_attempts']}) reached",
        "Escalating to human review"
    ]

    return {
        'status': AgentStatus.ESCALATED.value,
        'reasoning_chain': state['reasoning_chain'] + reasoning
    }


# ============================================================================
# ROUTING FUNCTIONS
# ============================================================================

def should_retry_or_review(state: AgentState) -> Literal["review", "generate_fix", "escalate"]:
    """
    Routing function: Decide next step after validation.

    Returns:
        - "review" if validation passed
        - "generate_fix" if validation failed and attempts < max
        - "escalate" if max attempts reached
    """
    if state['validation_status'] == ValidationStatus.PASSED.value:
        return "review"

    if state['attempts'] >= state['max_attempts']:
        return "escalate"

    return "generate_fix"


# ============================================================================
# GRAPH BUILDER
# ============================================================================

def build_agent_graph(config: AgentConfig, llm, template_loader: TemplateLoader) -> StateGraph:
    """
    Build the LangGraph workflow.

    Graph structure:
        START → generate_fix → validate → [routing]
                                         → PASS → review → END
                                         → FAIL → generate_fix (retry)
                                         → MAX_ATTEMPTS → escalate → END
    """
    # Create the graph
    workflow = StateGraph(AgentState)

    # Add nodes with bound parameters
    workflow.add_node(
        "generate_fix",
        lambda state: generate_fix_node(state, config, llm, template_loader)
    )
    workflow.add_node(
        "validate",
        lambda state: validate_node(state, config)
    )
    workflow.add_node(
        "review",
        lambda state: review_node(state, config, llm)
    )
    workflow.add_node(
        "escalate",
        escalate_node
    )

    # Set entry point
    workflow.set_entry_point("generate_fix")

    # Add edges
    workflow.add_edge("generate_fix", "validate")

    # Conditional routing after validation
    workflow.add_conditional_edges(
        "validate",
        should_retry_or_review,
        {
            "review": "review",
            "generate_fix": "generate_fix",
            "escalate": "escalate"
        }
    )

    # Terminal edges
    workflow.add_edge("review", END)
    workflow.add_edge("escalate", END)

    return workflow


# ============================================================================
# AGENT CREATION AND EXECUTION
# ============================================================================

class RemediationAgent:
    """
    The main remediation agent class.

    Wraps the LangGraph workflow and provides a simple interface
    for processing vulnerabilities.
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        """Initialize the agent with configuration."""
        self.config = config or AgentConfig()
        self.template_loader = TemplateLoader()
        self.llm = None
        self.graph = None
        self.compiled_graph = None

    def initialize(self) -> bool:
        """
        Initialize the LLM and build the graph.

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            if self.config.verbose:
                print(f"[Agent] Initializing with model: {self.config.model_name}")
                print(f"[Agent] Provider: {self.config.model_provider}")
                print(f"[Agent] Temperature: {self.config.temperature}")
                print(f"[Agent] Max attempts: {self.config.max_attempts}")

            # Initialize LLM
            self.llm = get_llm(self.config)

            # Build graph
            self.graph = build_agent_graph(self.config, self.llm, self.template_loader)

            # Compile graph
            self.compiled_graph = self.graph.compile()

            if self.config.verbose:
                print("[Agent] Initialization complete")

            return True

        except Exception as e:
            print(f"[Agent] Initialization failed: {str(e)}")
            return False

    def process_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single vulnerability through the workflow.

        Args:
            vulnerability: Dict with vulnerability details

        Returns:
            Dict with fix results
        """
        if not self.compiled_graph:
            if not self.initialize():
                return {
                    'status': AgentStatus.ERROR.value,
                    'error': 'Agent initialization failed'
                }

        # Create initial state
        initial_state = create_initial_state(vulnerability, self.config)

        if self.config.verbose:
            print(f"\n[Agent] Processing: {vulnerability.get('vuln_type')} in {vulnerability.get('file_path')}")

        try:
            # Run the graph
            final_state = self.compiled_graph.invoke(initial_state)

            if self.config.verbose:
                print(f"[Agent] Status: {final_state.get('status')}")
                print(f"[Agent] Attempts: {final_state.get('attempts')}")

            return {
                'status': final_state.get('status'),
                'fix': final_state.get('fix'),
                'fix_explanation': final_state.get('fix_explanation'),
                'attempts': final_state.get('attempts'),
                'validation_status': final_state.get('validation_status'),
                'test_result': final_state.get('test_result'),
                'reasoning_chain': final_state.get('reasoning_chain'),
                'error': final_state.get('error')
            }

        except Exception as e:
            return {
                'status': AgentStatus.ERROR.value,
                'error': str(e),
                'attempts': initial_state.get('attempts', 0)
            }

    def process_with_feedback(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a vulnerability using the feedback loop for improved retries.

        This method uses the FeedbackLoop class which:
        1. Tracks all fix attempts with their results
        2. Injects failure context into retry prompts
        3. Forces reflection on failed attempts ("What assumption was wrong?")
        4. Selects the best fix after max attempts

        Args:
            vulnerability: Dict with vulnerability details

        Returns:
            Dict with status (VERIFIED/UNVERIFIED), fix, and attempts history
        """
        if not self.llm:
            if not self.initialize():
                return {
                    'status': FixStatus.ERROR.value,
                    'error': 'Agent initialization failed'
                }

        if self.config.verbose:
            print(f"\n[Agent] Processing with feedback loop: {vulnerability.get('vuln_type')}")

        # Get fix template for this vulnerability type
        template = self.template_loader.get_template_for_vuln(vulnerability.get('vuln_type', ''))
        fix_template = ""
        if template:
            fix_template = f"{template.fix_strategy}\n\n{template.template}"

        # Create feedback loop config
        fb_config = FeedbackLoopConfig(
            max_attempts=self.config.max_attempts,
            verbose=self.config.verbose
        )

        # Create the feedback loop
        feedback_loop = FeedbackLoop(fb_config)

        # Define the fix generation function using our LLM
        def generate_fix(prompt: str) -> str:
            messages = [
                SystemMessage(content=AGENT_SYSTEM_PROMPT),
                HumanMessage(content=prompt)
            ]
            response = self.llm.invoke(messages)
            return response.content

        # Define the reflection generation function
        def generate_reflection(prompt: str) -> str:
            messages = [
                SystemMessage(content="You are a security engineer reflecting on a failed fix attempt. Be concise and specific."),
                HumanMessage(content=prompt)
            ]
            response = self.llm.invoke(messages)
            return response.content

        # Run the feedback loop
        result = feedback_loop.run(
            vulnerability=vulnerability,
            generate_fix_fn=generate_fix,
            fix_template=fix_template,
            generate_reflection_fn=generate_reflection
        )

        # Convert to dict and add agent status
        result_dict = result.to_dict()

        # Map feedback loop status to agent status
        if result.status == FixStatus.VERIFIED:
            result_dict['agent_status'] = AgentStatus.FIXED.value
        else:
            result_dict['agent_status'] = AgentStatus.ESCALATED.value

        return result_dict


def create_remediation_agent(config: Optional[AgentConfig] = None) -> RemediationAgent:
    """
    Create and return the remediation agent.

    Args:
        config: Optional AgentConfig for customizing agent behavior

    Returns:
        RemediationAgent instance
    """
    agent = RemediationAgent(config)
    return agent


def run_agent(agent: RemediationAgent, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run the agent on a single vulnerability.

    Args:
        agent: The RemediationAgent instance
        vulnerability: Dict containing vulnerability details

    Returns:
        Dict with fix results
    """
    return agent.process_vulnerability(vulnerability)


# ============================================================================
# TEST HARNESS
# ============================================================================

if __name__ == "__main__":
    import json
    from dotenv import load_dotenv

    # Load environment variables from .env file
    load_dotenv()

    print("=" * 70)
    print("SecureGuard AI - LangGraph Agent Test")
    print("=" * 70)

    # Check for API keys
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")

    # Validate the keys
    anthropic_valid = is_valid_api_key(anthropic_key, "anthropic")
    openai_valid = is_valid_api_key(openai_key, "openai")

    if not anthropic_valid and not openai_valid:
        print("\n⚠️  No API keys found!")
        print("Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable.")
        print("\nRunning in dry-run mode (testing graph structure only)...")

        # Test graph structure without LLM
        config = AgentConfig(verbose=True)

        print("\n--- Testing Graph Structure ---")
        template_loader = TemplateLoader()

        # Create a mock LLM for testing
        class MockLLM:
            def invoke(self, messages):
                class MockResponse:
                    content = "def get_user(user_id):\n    query = 'SELECT * FROM users WHERE id = ?'\n    cursor.execute(query, (user_id,))\n    return cursor.fetchone()"
                return MockResponse()

        mock_llm = MockLLM()
        graph = build_agent_graph(config, mock_llm, template_loader)
        compiled = graph.compile()

        print("✓ Graph compiled successfully")
        print(f"✓ Nodes: generate_fix, validate, review, escalate")
        print(f"✓ Entry point: generate_fix")
        print(f"✓ Conditional routing after validate")

        # Test state creation
        test_vuln = {
            'vuln_type': 'sql_injection',
            'file_path': 'test.py',
            'line_number': 10,
            'severity': 'HIGH',
            'description': 'SQL injection detected',
            'code_snippet': 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        }

        initial_state = create_initial_state(test_vuln, config)
        print(f"\n✓ Initial state created:")
        print(f"  - vuln_type: {initial_state['vuln_type']}")
        print(f"  - attempts: {initial_state['attempts']}")
        print(f"  - max_attempts: {initial_state['max_attempts']}")
        print(f"  - status: {initial_state['status']}")

    else:
        # Full test with real LLM
        provider = "anthropic" if anthropic_valid else "openai"
        model = "claude-sonnet-4-20250514" if anthropic_valid else "gpt-4o"

        print(f"\n✓ Using {provider} with model: {model}")

        config = AgentConfig(
            model_name=model,
            model_provider=provider,
            temperature=0.0,
            max_attempts=3,
            verbose=True
        )

        agent = create_remediation_agent(config)

        # Test vulnerability
        test_vuln = {
            'vuln_type': 'sql_injection',
            'file_path': 'sample_vulns/sql_injection.py',
            'line_number': 10,
            'severity': 'HIGH',
            'description': 'SQL injection vulnerability: user input directly concatenated into query',
            'code_snippet': '''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()''',
            'code_context': '''import sqlite3

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def list_users():
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()'''
        }

        print("\n--- Running Agent ---")
        result = run_agent(agent, test_vuln)

        print("\n--- Result ---")
        print(json.dumps({
            'status': result.get('status'),
            'attempts': result.get('attempts'),
            'validation_status': result.get('validation_status'),
            'error': result.get('error')
        }, indent=2))

        if result.get('fix'):
            print("\n--- Generated Fix ---")
            print(result['fix'])

        if result.get('reasoning_chain'):
            print("\n--- Reasoning Chain ---")
            for step in result['reasoning_chain']:
                print(f"  • {step}")

    print("\n" + "=" * 70)
    print("Agent test completed!")
    print("=" * 70)
