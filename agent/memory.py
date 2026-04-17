"""
SecureGuard AI - Agent Memory Module

This module manages the agent's conversation memory.
It stores fix attempt history and test failure messages for context on retry.

Key Features:
- ConversationBufferMemory management
- Fix attempt history tracking
- Context accumulation for retries
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class MemoryEntry:
    """A single memory entry for the agent."""
    timestamp: str
    entry_type: str  # 'attempt', 'failure', 'success', 'context'
    content: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


class AgentMemory:
    """
    Manages the agent's memory for fix attempts and context.

    This class wraps LangChain's ConversationBufferMemory and adds
    structured storage for fix attempts, test failures, and reasoning.
    """

    def __init__(self, max_history: int = 10):
        """
        Initialize the agent memory.

        Args:
            max_history: Maximum number of entries to keep in memory
        """
        self.max_history = max_history
        self.entries: List[MemoryEntry] = []
        self.current_vulnerability: Optional[Dict[str, Any]] = None
        self._langchain_memory = None  # Will be initialized in Phase 2

        print(f"[Memory] Initialized with max_history={max_history}")

    def set_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """
        Set the current vulnerability being processed.

        Args:
            vulnerability: Dict containing vulnerability details
        """
        self.current_vulnerability = vulnerability
        self.add_entry('context', {
            'action': 'set_vulnerability',
            'vulnerability': vulnerability
        })

    def add_entry(self, entry_type: str, content: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Add a new entry to the memory.

        Args:
            entry_type: Type of entry ('attempt', 'failure', 'success', 'context')
            content: The content to store
            metadata: Optional additional metadata
        """
        entry = MemoryEntry(
            timestamp=datetime.now().isoformat(),
            entry_type=entry_type,
            content=content,
            metadata=metadata or {}
        )

        self.entries.append(entry)

        # Trim if exceeding max history
        if len(self.entries) > self.max_history:
            self.entries = self.entries[-self.max_history:]

        print(f"[Memory] Added entry: type={entry_type}")

    def add_attempt(self, attempt_number: int, fix_code: str, reasoning: List[str]) -> None:
        """
        Record a fix attempt.

        Args:
            attempt_number: The attempt number (1, 2, 3, ...)
            fix_code: The proposed fix code
            reasoning: List of reasoning steps
        """
        self.add_entry('attempt', {
            'attempt_number': attempt_number,
            'fix_code': fix_code,
            'reasoning': reasoning
        })

    def add_failure(self, attempt_number: int, test_output: str, tests_failed: int) -> None:
        """
        Record a test failure.

        Args:
            attempt_number: The attempt number that failed
            test_output: The pytest output
            tests_failed: Number of tests that failed
        """
        self.add_entry('failure', {
            'attempt_number': attempt_number,
            'test_output': test_output,
            'tests_failed': tests_failed
        })

    def add_success(self, attempt_number: int, fix_code: str) -> None:
        """
        Record a successful fix.

        Args:
            attempt_number: The successful attempt number
            fix_code: The verified fix code
        """
        self.add_entry('success', {
            'attempt_number': attempt_number,
            'fix_code': fix_code
        })

    def get_attempt_history(self) -> List[Dict[str, Any]]:
        """
        Get the history of all fix attempts.

        Returns:
            List of attempt entries
        """
        return [
            entry.content
            for entry in self.entries
            if entry.entry_type == 'attempt'
        ]

    def get_failure_history(self) -> List[Dict[str, Any]]:
        """
        Get the history of all test failures.

        Returns:
            List of failure entries
        """
        return [
            entry.content
            for entry in self.entries
            if entry.entry_type == 'failure'
        ]

    def get_full_context(self) -> str:
        """
        Build a full context string for the agent.

        Returns:
            Formatted string with all relevant history
        """
        context_parts = []

        if self.current_vulnerability:
            context_parts.append(f"Current vulnerability: {self.current_vulnerability.get('vuln_type')}")
            context_parts.append(f"File: {self.current_vulnerability.get('file_path')}")
            context_parts.append(f"Line: {self.current_vulnerability.get('line_number')}")

        attempts = self.get_attempt_history()
        failures = self.get_failure_history()

        for attempt in attempts:
            context_parts.append(f"\nAttempt {attempt['attempt_number']}:")
            context_parts.append(f"Fix: {attempt['fix_code'][:100]}...")

        for failure in failures:
            context_parts.append(f"\nFailure on attempt {failure['attempt_number']}:")
            context_parts.append(f"Tests failed: {failure['tests_failed']}")
            context_parts.append(f"Output: {failure['test_output'][:200]}...")

        return "\n".join(context_parts)

    def clear(self) -> None:
        """Clear all memory entries."""
        self.entries = []
        self.current_vulnerability = None
        print("[Memory] Cleared all entries")

    def to_dict(self) -> Dict[str, Any]:
        """
        Export memory to a dictionary.

        Returns:
            Dict representation of the memory
        """
        return {
            'max_history': self.max_history,
            'current_vulnerability': self.current_vulnerability,
            'entries': [
                {
                    'timestamp': e.timestamp,
                    'entry_type': e.entry_type,
                    'content': e.content,
                    'metadata': e.metadata
                }
                for e in self.entries
            ]
        }


if __name__ == "__main__":
    # Test the memory module
    print("SecureGuard AI - Memory Module")
    print("=" * 40)

    memory = AgentMemory(max_history=5)

    # Set vulnerability
    memory.set_vulnerability({
        'vuln_type': 'sql_injection',
        'file_path': 'app.py',
        'line_number': 42
    })

    # Add attempts
    memory.add_attempt(1, "cursor.execute(query, params)", ["Read file", "Identified pattern"])
    memory.add_failure(1, "AssertionError: expected parameterized query", 2)

    memory.add_attempt(2, "cursor.execute(query, (user_id,))", ["Fixed parameter format"])
    memory.add_success(2, "cursor.execute(query, (user_id,))")

    # Get context
    print("\nFull context:")
    print(memory.get_full_context())

    print("\nMemory dict:")
    print(memory.to_dict())
