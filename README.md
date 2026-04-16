# SecureGuard AI

**AI Security Vulnerability Detection & Code Remediation Agent**

*From security scan to PR-ready fix — automatically.*

## Overview

SecureGuard AI is an intelligent agent that:
1. Takes a security scan report (JSON/text)
2. Filters false positives
3. Locates vulnerable code
4. Generates fixes using LLM + prompt templates
5. Validates fixes via pytest
6. Retries using feedback loop (max 3 attempts)
7. Optionally asks for human approval
8. Outputs PR-ready `.patch` files and Markdown reports

**Target: ≥75% fix accuracy across 24 vulnerability types**

---

## Quick Start

```bash
# 1. Create virtual environment & install dependencies
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Copy environment file and add your API keys
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY or OPENAI_API_KEY

# 3. Run via CLI
python main.py --scan demo.json --repo . --mode automatic --verbose

# 4. Or run the Web UI
streamlit run ui_app.py
```

---

## Web UI (Streamlit)

SecureGuard AI includes an interactive web interface built with Streamlit.

### Launch

```bash
streamlit run ui_app.py
```

The app opens at **http://localhost:8501** by default.

### UI Walkthrough

#### Step 1 — Upload Scan Report

In the **sidebar**, click **Browse files** and select a JSON scan report.

Pre-built scan reports included in this repo:

| Report | Target Project | Vulnerabilities |
|--------|---------------|-----------------|
| `demo.json` | `./webapp` (Python) | SQL Injection, XSS |
| `petclinic_scan.json` | Spring PetClinic (Java) | SQL Injection, Hardcoded Secrets, Command Injection |

#### Step 2 — Set Repository Path

Enter the **absolute path** to the target repository in the text input:

| Scan Report | Repository Path |
|-------------|-----------------|
| `demo.json` | `/path/to/SecureAI` (current directory) |
| `petclinic_scan.json` | `/path/to/spring-petclinic` |

#### Step 3 — Configure (Optional)

Expand the **⚙️ Configuration** panel in the sidebar. Defaults are loaded from `.env`.

| Setting | Recommended Value | Notes |
|---------|-------------------|-------|
| LLM Provider | `anthropic` | Or `openai` |
| Model | `claude-sonnet-4-20250514` | Or `gpt-4o` for OpenAI |
| Max Tokens | `2048` | Lower = cheaper; `1024` for aggressive savings |
| Max Retries | `2` or `3` | Each retry costs one LLM call |
| Review Mode | `interactive` | Lets you approve/reject in the UI |
| FP Threshold | `0.75` | Higher = stricter filtering |

#### Step 4 — Run

Click **🚀 Run SecureGuard**. The pipeline takes ~5–120 seconds depending on vulnerability count and LLM response time.

#### Step 5 — Review Results

After execution you will see:

- **📊 Results** — Metrics: total vulns, false positives, fixes verified, patches generated
- **📜 Execution Logs** — Expand to see full step-by-step pipeline output
- **🔍 Patch Review** — Each vulnerability shows:
  - Status badge (VERIFIED / UNVERIFIED / ERROR)
  - Severity, attempts, patch filename
  - Full diff view
  - Markdown report

#### Step 6 — Approve & Apply (Interactive Mode)

If review mode is `interactive`:

1. Click **✅ Approve** or **❌ Reject** for each vulnerability
2. After approving, click **🔧 Apply Patch to Repo** to run `git apply`
3. A success/failure message is shown

---

## CLI Usage

```bash
# Basic usage
python main.py --scan report.json --repo ./myproject

# Automatic mode (no human approval required)
python main.py --scan report.json --repo ./myproject --mode automatic

# Verbose output with retries
python main.py --scan report.json --repo ./myproject --mode automatic --verbose

# Dry run (parse and analyze only)
python main.py --scan report.json --repo ./myproject --dry-run

# Filter only (identify false positives)
python main.py --scan report.json --repo ./myproject --filter-only

# Custom output directory
python main.py --scan report.json --repo ./myproject --output ./fixes
```

### Demo Commands

```bash
# Python demo (fast, ~7s)
python main.py --scan demo.json --repo . --mode automatic --verbose

# Java Spring PetClinic demo (~2min)
python main.py --scan petclinic_scan.json --repo /path/to/spring-petclinic --mode automatic --verbose
```

---

## Project Structure

```
SecureAI/
├── main.py                 # CLI entry point & pipeline orchestrator
├── ui_app.py               # Streamlit web UI
├── parser.py               # Scan report parser
├── fp_filter.py            # False positive filter
├── locator.py              # Code locator
├── validator.py            # Fix validator
├── patch_generator.py      # Git patch generator
├── reporter.py             # Markdown report generator
├── reviewer.py             # Human-in-the-loop review
├── agent/
│   ├── agent.py            # LangGraph workflow + AgentConfig
│   ├── tools.py            # LangChain tools
│   ├── feedback_loop.py    # Retry logic with reflection
│   └── memory.py           # Agent memory
├── prompts/
│   ├── fix_templates.py    # 24 vulnerability templates
│   └── fp_filter.py        # FP filter prompts
├── config/
│   └── vuln_config.yaml    # Vulnerability configuration
├── webapp/                 # Demo vulnerable Python app
│   ├── database.py         # SQL Injection sample
│   └── handlers.py         # XSS sample
├── demo.json               # Demo scan report (Python)
├── petclinic_scan.json     # Demo scan report (Java/Spring)
├── output/                 # Generated patches & reports
├── tests/
│   └── test_pipeline.py    # Pytest suite (15 tests)
├── .env                    # Runtime config (API keys, LLM settings)
├── .env.example            # Template for .env
└── requirements.txt        # Python dependencies
```

---

## Configuration (.env)

All runtime configuration is in `.env`. Key settings:

```bash
# API Keys (set at least one)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...

# LLM Settings
LLM_PROVIDER=anthropic          # or openai
LLM_MODEL=claude-sonnet-4-20250514    # or gpt-4o
LLM_TEMPERATURE=0               # 0 = deterministic
LLM_MAX_TOKENS=2048             # controls cost

# Agent
MAX_RETRIES=3
VERBOSE=true

# Review & Filtering
REVIEW_MODE=interactive         # or automatic
FP_CONFIDENCE_THRESHOLD=0.75

# Output
OUTPUT_DIR=output
```

Edit `config/vuln_config.yaml` to:
- Enable/disable vulnerability types
- Add custom vulnerability patterns
- Override severity levels
- Map scanner rule IDs

---

## Supported Vulnerability Types (24)

| Category | Vulnerabilities |
|----------|-----------------|
| **Injection** | SQL Injection, Command Injection, LDAP Injection, XPath Injection |
| **Web** | XSS, CSRF, Open Redirect, XXE |
| **File & Data** | Path Traversal, Insecure Deserialization, Arbitrary File Upload, Log Injection |
| **Auth & Crypto** | Hardcoded Secrets, Weak Hashing, Broken JWT Auth, Weak Randomness |
| **Code & Config** | Insecure eval/exec, Debug Mode in Prod, Permissive CORS, Missing Security Headers |
| **Resource & Memory** | Buffer Overflow, Use After Free, Integer Overflow, ReDoS |

---

## Pipeline Stages

1. **Parse** — Read scan report from any SAST tool (Semgrep, Bandit, custom)
2. **Filter** — Remove false positives using heuristic + pattern matching
3. **Locate** — Find vulnerable code with surrounding context
4. **Agent** — Generate fix using LangGraph + LangChain with feedback loop
5. **Validate** — Syntax check & compile verification
6. **Review** — Optional human approval (interactive mode)
7. **Patch** — Generate git-compatible `.patch` diff
8. **Report** — Create Markdown documentation per vulnerability

---

## Tests

```bash
# Run all tests
pytest tests/test_pipeline.py -v

# 15 tests covering: parser, fp_filter, locator, validator,
# patch_generator, reporter, reviewer, and end-to-end dry run
```

---

## Requirements

- Python 3.10+
- LangChain & LangGraph
- Streamlit (for web UI)
- OpenAI or Anthropic API key
- git (for patch application)

---

## License

MIT License
