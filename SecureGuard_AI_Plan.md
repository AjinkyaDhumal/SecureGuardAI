# SecureGuard AI

## AI Security Vulnerability Detection & Code Remediation Agent

*From security scan to PR-ready fix — automatically.*

*No more developers drowning in false positives.*

| Metric | Value |
|--------|-------|
| Sprint Duration | 2 Days |
| Team Members | 3 |
| Vuln Types | 24+ (Configurable) |
| Target Accuracy | ≥75% |
| Agent Framework | LangChain + LangGraph |

> **UPDATED PLAN:** This document incorporates the revised problem statement — the project is now a full AI Remediation Agent, not just a scanner. It adds: (1) LangChain agent architecture with reasoning chain, (2) a feedback loop between fix generation and test validation, and (3) false positive filtering as a first-class pipeline stage.

---

## 1. The Problem We Are Solving

Security scanners detect vulnerabilities but stop at the report. Developers spend hours triaging noise and manually fixing what remains. The gap between detection and remediation is where security debt accumulates.

| Pain Point | What It Costs |
|------------|---------------|
| Detection-only tools | Produce long reports full of findings. Developers must manually read each one, locate the vulnerable code, understand the context, write a fix, and test it. This takes hours per vulnerability. |
| False positive noise | Up to 40% of findings from static analysis tools are false positives. Without filtering, developers waste time investigating non-issues and begin to ignore the tool entirely. |
| Manual fix quality | Developers under time pressure write quick fixes that address the symptom but not the root cause. The fix itself can introduce new vulnerabilities. |
| No feedback loop | Current tools have no mechanism to learn whether their suggestions worked. Each scan is stateless. There is no improvement over time. |

**SecureGuard AI closes the loop:** scan report in → AI agent reasons about the vulnerability → generates a targeted fix → validates it against your test suite → delivers a PR-ready patch with plain-English explanation. Target: 75% fix accuracy, covering 24 vulnerability types.

---

## 2. What Changed — Old vs New Problem Statement

The updated problem statement shifts the scope significantly. Here is exactly what changed and what we are now building:

| Aspect | Old Plan | New Plan (What We Build) |
|--------|----------|--------------------------|
| Core task | Detect vulnerabilities in new code at commit time | Full AI agent: read scan report → locate code → generate fix → validate → deliver patch |
| AI role | LLM called once per file to classify vulnerabilities | LangChain agent with multi-step reasoning, tool use, retry logic, and feedback loop |
| Input | Raw code diff from git commit | Scan report JSON/text from any SAST tool (Semgrep, Bandit, OWASP ZAP, custom) |
| Output | JSON vulnerability report shown in terminal | PR-ready .patch file + Markdown explanation report |
| Validation | Not included | Agent runs existing pytest suite against the fix before declaring success |
| False positives | Confidence threshold filter (0.75) | Dedicated FP filtering agent step with reasoning chain before any fix is attempted |
| Feedback loop | Not included | Fix → Test → Score → Retry loop. Agent retries with refined prompt if fix fails tests |
| Accuracy target | Not specified | ≥75% fix accuracy, measurable and demonstrated to judges |
| Frameworks | FastAPI, Rich, ReportLab | LangChain agent + tools, same LLM API, pytest integration |

---

## 3. The AI Agent Architecture

Our system uses LangGraph to model the remediation pipeline as a stateful graph. Each stage (parse, filter, locate, fix, validate) is a node, and execution flows through conditional edges based on outcomes such as test pass/fail. LangChain is used to implement tools and prompts within each node.

This is the most important section. The judges will evaluate whether we built a real agent with reasoning — not just a script that calls an LLM once. We use LangGraph to orchestrate the agent workflow as a stateful graph, while LangChain is used for tools, prompt templates, and LLM interactions. The set of vulnerability types and their associated prompts are configurable, allowing teams to extend or customize detection coverage.

### 3.1 What Is a LangGraph-Based Agent Using LangChain Tools?

A LangGraph-based agent system uses LangChain tools and models the workflow as a stateful graph. The LLM decides which tools to call, in what order, and LangGraph handles routing, retries, and state transitions. Unlike a simple chain (Step A then Step B always), the graph-based agent reasons about what to do next based on what happened in the previous step, with explicit conditional edges controlling the flow.

| Pattern | What It Means |
|---------|---------------|
| Simple LLM call | You send a prompt. The LLM responds. Done. One round trip, no memory, no tool use, no retry. |
| LangChain Chain | A fixed sequence of steps: Prompt A → LLM → Prompt B → LLM. The order is hardcoded. No decision-making. |
| LangChain Agent | The LLM decides what to do. It can call tools (read file, run tests), see the result, decide to retry with a different approach, and loop until the task is complete or it gives up. |

### 3.2 The Full Agent Pipeline

The pipeline has 8 stages. Stages 1-3 are pre-processing. Stage 4 is the core agent reasoning loop. Stages 5-8 are validation, review, and output generation.

```
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌──────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│ 1.Parse │ → │2.Filter │ → │3.Locate │ → │4.Agent  │ → │5.Validate│ → │6.Review │ → │ 7.Patch │ → │8.Report │
│Read scan│   │Remove FP│   │Find vuln│   │Reason + │   │Run tests │   │Dev      │   │Git diff │   │Plain    │
│report   │   │         │   │code     │   │fix      │   │          │   │approval │   │output   │   │English  │
└─────────┘   └─────────┘   └─────────┘   └─────────┘   └──────────┘   └─────────┘   └─────────┘   └─────────┘
```

These stages are implemented as LangGraph nodes connected through conditional edges that allow retries and branching.

- **Stage 6 – Review:** After a fix passes validation, the system presents the generated diff and a summary of the fix. In interactive mode, the developer can approve or reject the patch before it is applied.

- **Stage 4 (Agent)** contains the feedback loop. If Stage 5 (Validate) fails, LangGraph routes execution back to the fix-generation node via a conditional edge when validation fails. The agent tries again with a refined approach using accumulated context. Maximum 3 retries before escalating. After validation passes, an optional review stage (Stage 6) allows the developer to approve or reject the fix before patching.

### 3.3 Stage 4 — The LangGraph Remediation Agent (Core)

This is what makes the project a genuine AI agent rather than a script. The agent has 4 tools it can call and makes decisions about which tool to use based on what it knows so far.

#### Agent Tools

| Tool Name | What It Does |
|-----------|--------------|
| `read_file_tool` | Opens a source file and returns its content. The agent calls this to read the full file context around the vulnerable line — not just the snippet. |
| `run_tests_tool` | Applies a proposed fix to a temp copy of the file and runs pytest. Returns pass/fail count and the full output of any failures. |
| `search_codebase_tool` | Searches the codebase for other usages of the vulnerable pattern. Lets the agent understand if the fix needs to be applied in multiple places. |
| `explain_fix_tool` | Forces the agent to write a plain-English explanation of WHY the fix works. This doubles as a self-check — if it cannot explain it, it re-evaluates. |

#### The Agent Reasoning Chain — Step by Step

This is the internal thought process the agent follows. This is what judges mean when they ask about reasoning:

| Reasoning Step | What the Agent Does |
|----------------|---------------------|
| Step 1: Understand | Agent reads the vulnerability type, severity, and OWASP classification from the parser output. It identifies which of its configured prompt templates applies (24 built-in, extensible via config). |
| Step 2: Gather context | Agent calls `read_file_tool` to get the full file, not just the flagged line. It looks 20 lines above and below to understand function scope, imports, and data flow. |
| Step 3: FP check | Before generating any fix, the agent checks: Is this real? Could this be a test file? Is this pattern actually reachable? If confidence < 0.75, it marks as likely false positive and skips. |
| Step 4: Generate fix | Agent selects the correct prompt template for the vuln type and generates a targeted fix. Prompt instructs it to return ONLY valid code, no explanation, no markdown. |
| Step 5: Self-review | Agent calls `explain_fix_tool`. It must articulate: what was wrong, why the fix works, and whether any edge cases remain. If it cannot explain it clearly, it regenerates. |
| Step 6: Validate | Agent calls `run_tests_tool` on the proposed fix. Reads the test output. |
| Step 7: Decision | PASS: proceed to patch generation. FAIL: read the failure message, update its reasoning (what assumption was wrong?), generate a refined fix. LangGraph routes execution back to the fix-generation node via a conditional edge. |
| Step 8: Escalate | After 3 failed retries: mark fix as unverified, include the best attempt with a warning flag in the output. Never silently discard a finding. |

LangGraph routes execution back to the fix-generation node via a conditional edge when validation fails, ensuring structured retry behavior.

### 3.4 The Feedback Loop (What Judges Will Scrutinize)

The feedback loop is the mechanism that makes the agent improve within a single run. It is not learning in the ML sense — it is iterative refinement with context accumulation. LangGraph routes execution back to the fix-generation node via a conditional edge when validation fails, ensuring structured retry behavior.

**FEEDBACK LOOP:** Fix attempt N fails tests → Agent reads test failure output → Agent adds failure context to its prompt → Agent generates fix attempt N+1 with the new information → Tests run again via the LangGraph validate node. The agent explicitly states what it changed and why.

| Loop State | Agent Behavior |
|------------|----------------|
| Iteration 1 | Agent generates fix based on vulnerability description and code context alone. Runs tests. |
| If tests FAIL | Test failure message added to agent context: 'Your previous fix failed because: [pytest output]. The specific assertion that failed was: [assertion]. Revise your fix to address this.' |
| Iteration 2 | Agent now knows the shape of the failure. It adjusts the fix specifically to address the failing test case, not just the vulnerability pattern. |
| If tests FAIL again | Second failure added. Agent is now told: 'You have attempted this fix twice. Here are both failures. Identify the root assumption that was wrong in both attempts before generating fix 3.' |
| Iteration 3 | Agent must reason about root cause before generating fix 3. This forces deeper analysis rather than syntactic variation. |
| After 3 failures | Best attempt (lowest test failure count) is included in output with an UNVERIFIED flag. Developer sees the attempt and all 3 failure reasons for manual review. |

### 3.5 False Positive Filtering Stage

This stage runs BEFORE any fix is attempted. It prevents wasted LLM calls and, more importantly, prevents the agent from generating incorrect fixes for non-issues. The filter respects the active vulnerability configuration — only types enabled in vuln_config.yaml are processed.

| Filter Check | What It Does |
|--------------|--------------|
| File context check | Is this a test file (test_*.py, *_test.*, *mock*, *fixture*)? Test files intentionally contain unsafe-looking patterns. |
| Reachability check | Is the vulnerable code path reachable in production? Code in unused functions, commented blocks, or dead branches is flagged as LOW priority. |
| Confidence threshold | LLM assigns a confidence score 0.0-1.0. Findings below 0.75 are filtered. The filter reasoning is logged so developers can review what was excluded. |
| Pattern validation | Agent checks: does the reported line number actually contain the reported pattern? Scanner line numbers are sometimes off by 1-3 lines. Agent re-locates before proceeding. |
| Deduplication | Multiple scanner findings that point to the same root cause are grouped into one fix attempt. Prevents generating 3 separate fixes for 3 instances of the same pattern. |

---

## 4. LangGraph + LangChain Implementation

LangGraph defines the workflow structure (nodes, edges, retries), while LangChain provides tool abstractions and prompt templates used within each node.

SecureGuard supports two modes:
- **Automatic mode:** fully autonomous execution
- **Interactive mode:** includes a developer approval step after validation

### Configurable Vulnerability Scanning

The vulnerability scanning scope and prompt templates are fully configurable:
- `config/vuln_config.yaml` defines which vulnerability types are active, their categories, and fix strategies. The default configuration includes all 24 built-in types.
- Each vulnerability type maps to a prompt template in `prompts/fix_templates.py`. Custom templates can be added by specifying a path in vuln_config.yaml.
- At startup, the agent loads the configuration and registers only the specified vulnerability types and their associated prompts.

This allows teams to:
- Restrict scanning to project-relevant vulnerability categories
- Add organization-specific vulnerability patterns
- Customize fix strategies and prompt wording for their codebase
- Override severity levels based on internal security policies

This section gives the exact code structure for the LangGraph + LangChain agent system. Member B owns this. It is the core of the project.

### 4.1 Package Installation

```bash
pip install langchain langchain-anthropic langchain-core anthropic python-dotenv pytest difflib
```

### 4.2 Agent File Structure

| File | Responsibility |
|------|----------------|
| `agent/agent.py` | Defines LangGraph workflow (nodes and transitions). Creates the graph executor, registers LangChain tools, defines the system prompt, and runs the remediation pipeline. |
| `agent/tools.py` | LangChain tools used within graph nodes. Defines the 4 tools: read_file_tool, run_tests_tool, search_codebase_tool, explain_fix_tool. Each tool is a Python function wrapped with @tool decorator. |
| `agent/memory.py` | Manages the agent's ConversationBufferMemory. Stores the fix attempt history and test failure messages so the agent has full context on retry. |
| `agent/feedback_loop.py` | Implements retry logic aligned with LangGraph state transitions. Captures test results, injects failure context, and decides when to escalate after 3 attempts. |
| `prompts/fix_templates.py` | 24 built-in vulnerability-specific system prompts (configurable). Each template tells the agent exactly what pattern to replace and what the secure alternative looks like. Custom templates can be added via vuln_config.yaml. |
| `prompts/fp_filter.py` | False positive filter prompt. Instructs the agent to evaluate confidence and reachability before committing to a fix attempt. |
| `reviewer.py` | Displays diff output, shows fix summary, and captures developer approval decision. Used in interactive mode. |
| `config/vuln_config.yaml` | Configuration file defining vulnerability types, categories, and associated prompt template paths. Teams can add, remove, or modify vulnerability definitions and prompts without changing code. |

### 4.3 LangGraph Workflow Design

Our remediation pipeline is implemented as a graph with nodes:
```
parse → filter → locate → generate_fix → validate → review → patch → report
```

Conditional edges:
- `validate → PASS → patch`
- `validate → FAIL → generate_fix` (retry)
- `retry_count ≥ 3 → escalate`

This provides explicit control over retries and ensures deterministic execution.

### Human-in-the-Loop Review

After validation, SecureGuard optionally pauses to present the proposed fix to the developer.

The interface includes:
- A unified diff showing code changes
- A concise summary of the fix
- Test validation results

The developer can:
- **Approve the fix** → patch is applied
- **Reject the fix** → vulnerability is skipped

This ensures high trust and prevents unintended changes. This step is optional and can be disabled in CI/CD environments.

### 4.4 The Agent Definition (agent/agent.py — LangGraph Workflow)

```python
from langchain_anthropic import ChatAnthropic
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.memory import ConversationBufferMemory
from agent.tools import read_file_tool, run_tests_tool, search_codebase_tool, explain_fix_tool

AGENT_SYSTEM_PROMPT = '''
You are an expert security engineer and code remediator.
You have been given a vulnerability finding from a security scanner.
Your job is to: (1) verify the finding is real, (2) understand the full code context,
(3) generate a minimal targeted fix, (4) validate it passes tests.
Think step by step. Use your tools. Explain your reasoning at each step.
Return ONLY valid code in your fix. No markdown, no explanation in the fix itself.
'''

def create_remediation_agent():
    llm = ChatAnthropic(model='claude-sonnet-4-20250514', temperature=0)
    tools = [read_file_tool, run_tests_tool, search_codebase_tool, explain_fix_tool]
    memory = ConversationBufferMemory(memory_key='chat_history', return_messages=True)
    
    prompt = ChatPromptTemplate.from_messages([
        ('system', AGENT_SYSTEM_PROMPT),
        MessagesPlaceholder('chat_history'),
        ('human', '{input}'),
        MessagesPlaceholder('agent_scratchpad'),
    ])
    
    agent = create_tool_calling_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, memory=memory,
                         verbose=True, max_iterations=10, handle_parsing_errors=True)
```

### 4.5 The Feedback Loop (agent/feedback_loop.py)

```python
def run_with_feedback(agent_executor, vulnerability, max_retries=3):
    """
    Runs the agent on a vulnerability with retry logic.
    On each retry, injects the test failure as new context so the agent
    can reason about what went wrong and adjust its approach.
    """
    attempts = []
    for attempt_num in range(1, max_retries + 1):
        # Build the input — first attempt uses clean context,
        # subsequent attempts include all previous failure reasons
        if attempt_num == 1:
            input_msg = build_initial_prompt(vulnerability)
        else:
            last_failure = attempts[-1]['test_output']
            input_msg = build_retry_prompt(vulnerability, attempts, last_failure)
        
        # Run the agent
        result = agent_executor.invoke({'input': input_msg})
        fix_code = extract_code_from_response(result['output'])
        
        # Validate the fix against the test suite
        test_result = run_tests_on_fix(vulnerability['file_path'], fix_code)
        
        attempts.append({
            'attempt': attempt_num,
            'fix_code': fix_code,
            'tests_passed': test_result['passed'],
            'tests_failed': test_result['failed'],
            'test_output': test_result['output'],
            'reasoning': result.get('intermediate_steps', [])
        })
        
        if test_result['failed'] == 0:
            return {'status': 'VERIFIED', 'fix': fix_code, 'attempts': attempts}
    
    # All retries exhausted — return best attempt
    best = min(attempts, key=lambda a: a['tests_failed'])
    return {'status': 'UNVERIFIED', 'fix': best['fix_code'], 'attempts': attempts}
```

### 4.6 The Retry Prompt (What the Agent Sees on Failure)

This is the prompt injected into agent memory when a fix fails tests. This is the mechanism that creates the feedback loop:

```python
def build_retry_prompt(vulnerability, previous_attempts, last_failure):
    attempt_history = ''
    for a in previous_attempts:
        attempt_history += f'Attempt {a["attempt"]}:\n'
        attempt_history += f'Your fix:\n{a["fix_code"]}\n'
        attempt_history += f'Test result: {a["tests_failed"]} test(s) failed\n'
        attempt_history += f'Failure output:\n{a["test_output"]}\n\n'
    
    return f'''
You are fixing: {vulnerability['vuln_type']} in {vulnerability['file_path']} at line {vulnerability['line_number']}.

YOUR PREVIOUS ATTEMPTS FAILED. Here is the full history:
{attempt_history}

Before generating a new fix, answer these questions in your reasoning:
1. What assumption did you make in your previous attempt(s) that was wrong?
2. What does the test failure tell you about the correct behavior expected?
3. What will you do differently this time?

Then generate a new fix that addresses the root cause of the test failure.
'''
```

---

## 5. Complete Module Breakdown

The project has 8 core modules. Each is independently testable. The team is split so each person owns a complete vertical slice.

| Module | Owner | Responsibility |
|--------|-------|----------------|
| `parser.py` | Member A | Reads JSON/text scan report from any SAST tool. Extracts: vuln_type, file_path, line_number, severity, description. Normalises different scanner formats into a shared schema. |
| `fp_filter.py` | Member A | False positive filtering stage. Calls LLM to evaluate confidence and reachability. Deduplicates findings. Returns filtered list with reasoning for each exclusion. |
| `locator.py` | Member A | Opens the target file, extracts 20 lines of context around the vulnerable line, identifies function scope and imports needed for the fix. |
| `agent/agent.py` | Member B | LangGraph-based agent definition. Registers tools, creates LangGraph workflow with LangChain tools and ConversationBufferMemory, defines the security engineer system prompt. |
| `agent/tools.py` | Member B | LangChain tools used within LangGraph nodes. 4 tools: read_file_tool, run_tests_tool, search_codebase_tool, explain_fix_tool. Each wrapped with @tool decorator. |
| `agent/feedback_loop.py` | Member B | Implements retry logic aligned with LangGraph state transitions. Injects test failure context into agent memory. Tracks attempt history. Escalates after 3 failures. |
| `prompts/fix_templates.py` | Member B | 24 built-in configurable prompt templates. One per vuln type. Selected automatically by the agent based on parsed vulnerability classification. Custom prompts can be added or modified via vuln_config.yaml. |
| `validator.py` | Member C | Applies fix to a temp copy of the target file. Runs pytest in a subprocess. Returns structured result: pass count, fail count, failure messages, coverage delta. |
| `patch_generator.py` | Member C | Generates unified git diff between original and fixed file using Python difflib. Output is a standard .patch file that can be applied with git apply. |
| `reporter.py` | Member C | Generates a Markdown report per vulnerability: what was wrong, why it was dangerous, what the fix does, which tests validated it, and the OWASP reference. |
| `main.py` | Member C | Single entry point. Wires all modules. Usage: `python main.py --scan report.json --repo ./myproject`. Outputs .patch and .md files to output/ directory. |
| `reviewer.py` | Member C | Displays diff output, shows fix summary, and captures developer approval decision. Used in interactive mode to pause before applying patches. |
| `config/vuln_config.yaml` | Member B | YAML configuration file for vulnerability types and prompt templates. Defines which vulnerabilities to scan, their categories, fix strategies, and paths to custom prompt templates. |

---

## 6. Vulnerability Types Covered (24 Default, Configurable)

Each vulnerability type has a dedicated prompt template in `prompts/fix_templates.py` and a sample vulnerable file in `sample_vulns/` for accuracy testing. SecureGuard ships with 24 built-in vulnerability types, but both the vulnerability list and the associated prompt templates are fully configurable. Teams can add custom vulnerability types, modify existing prompts, or restrict scanning to a subset — all through a YAML configuration file without changing any code.

### Configuration options (via config/vuln_config.yaml):

- **vulnerabilities:** List of active vulnerability types to scan (default: all 24)
- **prompts:** Path mappings to custom prompt templates per vulnerability type
- **categories:** Grouping of vulnerabilities (Injection, Web, Auth & Crypto, etc.)
- **severity_override:** Optional per-type severity adjustments
- **custom_types:** User-defined vulnerability definitions with fix strategies

**Example:** To scan only injection vulnerabilities, set `vulnerabilities: [sql_injection, command_injection, ldap_injection, xpath_injection]`. To add a new type, define its name, category, fix strategy, and prompt template path under `custom_types`.

| Vulnerability | Category | Fix Strategy |
|---------------|----------|--------------|
| SQL Injection | Injection | String concat in queries → parameterized statements |
| Command Injection | Injection | shell=True with user input → list args, no shell |
| LDAP Injection | Injection | Unsanitized LDAP search → escape + safe library |
| XPath Injection | Injection | String concat in XPath → parameterized XPath |
| XSS | Web | Unescaped output → HTML escape, auto-escaping template |
| CSRF | Web | Missing token → CSRF middleware generation |
| Open Redirect | Web | Unvalidated redirect → whitelist allowed URLs |
| XXE | Web | External entity processing → disable in parser config |
| Path Traversal | File & Data | User input in file path → basename + base dir check |
| Insecure Deserialization | File & Data | pickle.loads untrusted data → JSON + type validation |
| Arbitrary File Upload | File & Data | No MIME/ext check → whitelist + rename on upload |
| Log Injection | File & Data | Raw input in log → sanitize, strip newlines |
| Hardcoded Secrets | Auth & Crypto | Literal API key in source → os.getenv + .env file |
| Weak Hashing | Auth & Crypto | MD5/SHA1 for passwords → bcrypt / argon2 / PBKDF2 |
| Broken JWT Auth | Auth & Crypto | verify=False → enable all JWT verifications |
| Weak Randomness | Auth & Crypto | random.randint for tokens → secrets.token_hex(32) |
| Insecure eval/exec | Code & Config | eval(user_input) → ast.literal_eval or refactor |
| Debug Mode in Prod | Code & Config | debug=True hardcoded → environment variable control |
| Overly Permissive CORS | Code & Config | Allow-Origin: * → restrict to known trusted origins |
| Missing Security Headers | Code & Config | No CSP/HSTS → security header middleware |
| Buffer Overflow (C/C++) | Resource & Memory | strcpy no bounds → strncpy with explicit size |
| Use After Free | Resource & Memory | ptr used after free → NULL after free, smart pointers |
| Integer Overflow | Resource & Memory | No overflow check → bounds check before arithmetic |
| ReDoS | Resource & Memory | Catastrophic backtracking regex → rewrite pattern |
| (Custom) | User-defined | Add via config/vuln_config.yaml with custom prompt template |

---

## 7. Team Structure & Responsibilities

### Member A — Input Pipeline
**Owns:** `parser.py`, `fp_filter.py`, `locator.py` — scan report in, verified vulnerability context out

### Member B — AI Agent Core
**Owns:** `agent/agent.py`, `agent/tools.py`, `agent/feedback_loop.py`, `prompts/fix_templates.py` — the LangGraph orchestration and LangChain reasoning engine

### Member C — Output Pipeline + Wiring
**Owns:** `validator.py`, `patch_generator.py`, `reporter.py`, `main.py` — fix validation, PR patch, report generation, single entry point

### The Shared Data Schema (Agree on This Before Splitting)

All three modules communicate through Python dicts. Print this and pin it up:

| Stage | Dict Shape Passed to Next Stage |
|-------|--------------------------------|
| Parser output | `{ vuln_type, file_path, line_number, severity, description, scanner_id }` |
| FP filter output | `{ ...parser_output, is_false_positive: bool, fp_reason: str, confidence: float }` |
| Locator output | `{ ...fp_output, code_snippet: str, full_context: str, function_scope: str }` |
| Agent fix output | `{ ...locator_output, proposed_fix: str, reasoning_chain: list, attempt_number: int }` |
| Validator output | `{ ...fix_output, tests_passed: int, tests_failed: int, test_output: str, status: VERIFIED\|UNVERIFIED }` |
| Patch generator out | `{ ...validator_output, patch_file_path: str, diff_text: str }` |
| Reporter output | `{ ...patch_output, report_file_path: str, summary: str }` |

Demonstrate the interactive review step by showing the diff and approving the fix live.

---

## 8. Two-Day Sprint Schedule

### Day 1 — Foundation + Agent Setup

| Phase | When | Who | Deliverable |
|-------|------|-----|-------------|
| 9:00–9:30 | Day 1 AM | All 3 | Agree on shared data schema. Member B installs LangChain and confirms a basic agent call works with mock tools. |
| 9:30–12:00 | Day 1 AM | Member A | parser.py working on 3 sample JSON formats (Semgrep, Bandit, custom). locator.py returning 20-line context correctly. |
| 9:30–12:00 | Day 1 AM | Member B | agent/agent.py created. LangGraph workflow running with LangChain tools with mock tools. First 8 prompt templates drafted. vuln_config.yaml schema defined (injection + web categories). |
| 9:30–12:00 | Day 1 AM | Member C | pytest harness set up. sample_vulns/ directory with 6 vulnerable files + passing baseline tests. validator.py shell created. |
| 12:00–13:00 | Day 1 PM | All 3 | Lunch sync. Each person demos their morning output. Confirm schema handoffs work. |
| 13:00–16:00 | Day 1 PM | Member A | fp_filter.py complete. False positive filtering tested on 6 sample cases. Integration: parser → filter → locator pipeline working. |
| 13:00–16:00 | Day 1 PM | Member B | agent/tools.py with all 4 tools. feedback_loop.py with retry logic. Agent doing 2-step reasoning on first 4 vuln types. |
| 13:00–16:00 | Day 1 PM | Member C | validator.py applying patch to temp copy and running pytest. patch_generator.py generating valid .patch files. |
| 17:00–18:00 | Day 1 PM | All 3 | End-of-day integration: run one vulnerability end-to-end through all 8 stages. Fix a SQL injection. Confirm .patch file is produced. |

### Day 2 — Complete Pipeline + Accuracy + Demo Prep

| Phase | When | Who | Deliverable |
|-------|------|-----|-------------|
| 9:00–10:00 | Day 2 AM | All 3 | Fix any integration bugs from Day 1. All 3 modules talking to each other cleanly. |
| 10:00–12:00 | Day 2 AM | Member A | Expand sample_vulns/ to all 24 types. Run accuracy benchmark. Log failures and share with Member B for prompt tuning. |
| 10:00–12:00 | Day 2 AM | Member B | Complete all 24 prompt templates. Validate vuln_config.yaml loads correctly. Tune based on Day 1 failures. Test feedback loop on multi-retry cases. |
| 10:00–12:00 | Day 2 AM | Member C | reporter.py generating clean Markdown. main.py single entry point wiring all modules with argparse. |
| 12:00–13:00 | Day 2 PM | All 3 | Full accuracy run across all 24 vulnerability types. Must be at or above 75%. Document the number. |
| 13:00–14:30 | Day 2 PM | All 3 | Build 3 demo scenarios. Rehearse the demo twice. Record backup video of full pipeline run. |
| 14:30–16:00 | Day 2 PM | All 3 | Polish README, prepare judge Q&A answers, finalize demo machine setup. |

Unlike fully automated tools, SecureGuard includes an optional human approval step before applying fixes.

---

## 9. Demo Plan (5 Minutes)

The demo must show the full pipeline running live — not slides. Judges want to see the agent reasoning, the feedback loop in action, and the PR patch output.

### The 5-Minute Demo Script

| Segment | What To Say and Show |
|---------|----------------------|
| 0:00 – 0:30 (All) | "Security scanners produce reports. Developers drown in them. We built an agent that reads the report, finds the code, generates a fix, validates it against your tests, and hands you a PR. Let us show you." |
| 0:30 – 2:00 (Member A) | Run: `python main.py --scan demo_report.json --repo ./demo_project`. Show the parser reading the report. Show fp_filter.py filtering one false positive (explain why it was filtered — this is a key differentiator). Show locator finding the vulnerable line. |
| 2:00 – 3:30 (Member B) | Show the LangGraph agent output (verbose=True so reasoning is visible). Point to the agent calling read_file_tool, then explain_fix_tool. Show it generating the fix. If possible: show a retry — make the first fix intentionally fail a test so judges see the feedback loop in real time. |
| 3:30 – 4:15 (Member C) | Show the .patch file output. Open it — it is a valid git diff. Show the .md report — plain English, OWASP reference, before/after code. "Your developer reviews this in 30 seconds and clicks merge." |
| 4:15 – 5:00 (All) | "75% fix accuracy across 24 vulnerability types. Full OWASP Top 10 coverage. Agent reasons before it acts. Feedback loop means it learns from test failures in real time. This is not a scanner. This is a security engineer." |

### The Single Wow Moment

The wow moment is the feedback loop running live. Set up a demo case where the first fix attempt fails one test. Judges will see the agent read the failure, say what assumption was wrong, and generate a corrected fix that passes. No other team will show a self-correcting agent.

### Questions Judges Will Ask — Prepare These Answers

| Judge Question | Our Answer |
|----------------|------------|
| How is the feedback loop implemented? | LangGraph manages state transitions and retries. LangChain ConversationBufferMemory stores the full history. On retry, we inject the pytest failure output as a new human message. The agent sees its previous attempt and the test failure side by side and reasons about what changed. |
| How do you measure 75% accuracy? | We run the agent against all configured sample vulnerable files (24 built-in, extensible). A fix is counted as accurate if: (1) it compiles, (2) all existing tests pass, (3) the vulnerability pattern is no longer present (verified by re-running the scanner). |
| How does false positive filtering work? | Before any fix is attempted, a dedicated LLM call evaluates: is this code actually reachable? Is this a test file? Does the line number actually contain the reported pattern? Anything below 0.75 confidence is excluded with a logged reason. |
| What makes this an agent and not a chain? | A chain executes a fixed sequence. Our LangGraph-based agent decides at runtime which tools to call, in what order, based on what it finds. If the code has multiple usages of the vulnerable pattern, the agent calls search_codebase_tool to find them all before generating the fix. |
| What if there are no tests in the repo? | validator.py falls back to two checks: (1) syntax validity via ast.parse, (2) re-running the SAST scanner on the fixed code to confirm the finding no longer appears. Fix is marked SYNTAX-ONLY-VERIFIED. |

---

## 10. Competitive Differentiation

| Tool | Their Gap | Our Advantage |
|------|-----------|---------------|
| GitHub Copilot | Suggests code as you type. No scan report integration. No test validation. No patch output. | We read any SAST report, validate against real tests, and output a PR-ready patch. |
| Snyk | Detects vulnerable dependencies. Does not fix application code. No LLM reasoning. | We fix application-level vulnerabilities with LLM reasoning and self-validation. |
| SonarQube | Excellent detection. No automated remediation. Developers still fix manually. | We close the loop. Detection to validated fix in a single command. |
| Cursor/Copilot Fix | LLM suggests fixes inline. No test validation loop. No false positive filtering. No audit trail. | We validate every fix against the test suite before delivering it. We filter false positives. We generate an audit report. |

### One-Sentence Pitch to Judges

> "SecureGuard is the only tool that takes any SAST report, generates a validated fix using an AI agent with a reasoning chain and feedback loop, and delivers a PR-ready patch — turning hours of manual remediation into a single command."

---

## 11. Risk Mitigation

| Risk | Mitigation |
|------|------------|
| LangChain/LangGraph install fails | All LangChain and LangGraph packages installable via pip --user. No system packages needed. Test this on Day 1 morning before splitting. |
| Agent reasoning is too slow | Set temperature=0 for deterministic, faster responses. Limit max_iterations=10. Cache tool outputs where possible. |
| LLM fix fails to compile | Retry prompt adds: 'Return ONLY valid Python. No markdown. No explanation. The previous response caused a SyntaxError at line X.' Three retries before escalating. |
| No tests in target repo | validator.py fallback: ast.parse for syntax check + re-scan with scanner. Mark as SYNTAX-ONLY-VERIFIED. Still produce the patch. |
| Accuracy below 75% | Narrow scope to 10 most common types. All 10 will be perfect rather than 24 at 65%. Configuration allows teams to enable only relevant vulnerability types. Judges care about the demonstrated number, not the attempted count. |
| Demo feedback loop not live | Pre-stage a demo case with a known first-attempt failure. This guarantees the feedback loop is visible even if live network is slow. |
| Incorrect fix applied automatically | Interactive review step allows developer approval before applying patch. In CI/CD mode, fixes are flagged for manual review if confidence is below threshold. |

---

**We are not building a scanner. We are building a security engineer — with optional human oversight.**

**Scan report in. PR-ready fix out. Agent reasoning visible. Feedback loop live. LangGraph orchestration. Developer review built in.**

*Let's build it.*
