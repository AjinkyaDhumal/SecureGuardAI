"""
SecureGuard AI - Fix Templates Module

This module contains vulnerability-specific prompt templates for the LLM agent.
Each template defines:
- Vulnerability type and category
- Fix strategy (concise description)
- Detailed prompt with examples
- Strict instructions: "Return ONLY valid code"

Templates can be customized via config/vuln_config.yaml.

Usage:
    from prompts.fix_templates import FixTemplateRegistry

    registry = FixTemplateRegistry()
    template = registry.get_template('sql_injection')
    prompt = registry.build_prompt('sql_injection', code_context, vulnerability_info)
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from pathlib import Path
import yaml


# Strict instruction that MUST be included in every template
STRICT_CODE_INSTRUCTION = """
CRITICAL INSTRUCTIONS:
1. Return ONLY valid, working code
2. Do NOT include explanations, comments about the fix, or markdown
3. Do NOT include ```python or ``` code blocks
4. Preserve the original code structure and style
5. Make minimal changes - fix ONLY the vulnerability
6. Ensure the fix compiles/runs without errors
"""


@dataclass
class FixTemplate:
    """Represents a vulnerability fix template."""
    vuln_type: str
    category: str
    severity: str
    owasp: str
    fix_strategy: str
    template: str
    cwe_ids: List[str] = field(default_factory=list)
    examples: Dict[str, str] = field(default_factory=dict)

    def get_full_prompt(self, code_context: str = "", vuln_info: Dict[str, Any] = None) -> str:
        """
        Build the full prompt with code context and strict instructions.

        Args:
            code_context: The code snippet to fix
            vuln_info: Additional vulnerability information

        Returns:
            Complete prompt string for the LLM
        """
        vuln_info = vuln_info or {}

        prompt_parts = [
            self.template.strip(),
            "",
            STRICT_CODE_INSTRUCTION.strip(),
        ]

        if code_context:
            prompt_parts.extend([
                "",
                "CODE TO FIX:",
                "```",
                code_context,
                "```",
            ])

        if vuln_info.get('description'):
            prompt_parts.extend([
                "",
                f"VULNERABILITY DETAILS: {vuln_info['description']}",
            ])

        if vuln_info.get('line_number'):
            prompt_parts.append(f"VULNERABLE LINE: {vuln_info['line_number']}")

        prompt_parts.extend([
            "",
            "Return ONLY the fixed code:",
        ])

        return "\n".join(prompt_parts)


# Vulnerability fix templates - Core types
VULNERABILITY_TEMPLATES: Dict[str, Dict[str, Any]] = {
    # ============ INJECTION CATEGORY ============
    "sql_injection": {
        "category": "Injection",
        "severity": "HIGH",
        "owasp": "A03:2021-Injection",
        "fix_strategy": "String concat in queries → parameterized statements",
        "template": """
You are fixing a SQL Injection vulnerability.

VULNERABILITY PATTERN:
- String concatenation or f-strings used in SQL queries
- User input directly embedded in query strings

FIX STRATEGY:
- Use parameterized queries with placeholders (?, %s, :param)
- Pass user input as separate parameters tuple/dict
- NEVER concatenate user input into SQL strings

EXAMPLE:
BAD:  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
GOOD: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

Return ONLY the fixed code. No explanations.
"""
    },

    "command_injection": {
        "category": "Injection",
        "severity": "CRITICAL",
        "owasp": "A03:2021-Injection",
        "fix_strategy": "shell=True with user input → list args, no shell",
        "template": """
You are fixing a Command Injection vulnerability.

VULNERABILITY PATTERN:
- subprocess.call/run/Popen with shell=True and user input
- os.system() with user input
- String concatenation in shell commands

FIX STRATEGY:
- Use subprocess with shell=False (default)
- Pass command as list of arguments
- Use shlex.quote() if shell is absolutely required
- Validate/sanitize user input against allowlist

EXAMPLE:
BAD:  subprocess.run(f"ls {user_dir}", shell=True)
GOOD: subprocess.run(["ls", user_dir], shell=False)

Return ONLY the fixed code. No explanations.
"""
    },

    "ldap_injection": {
        "category": "Injection",
        "severity": "HIGH",
        "owasp": "A03:2021-Injection",
        "fix_strategy": "Unsanitized LDAP search → escape + safe library",
        "template": """
You are fixing an LDAP Injection vulnerability.

VULNERABILITY PATTERN:
- User input directly in LDAP filter strings
- No escaping of special LDAP characters

FIX STRATEGY:
- Use ldap3 library's escape_filter_chars() function
- Or use ldap.filter.escape_filter_chars()
- Validate input against expected format

EXAMPLE:
BAD:  filter = f"(uid={username})"
GOOD: filter = f"(uid={ldap3.utils.conv.escape_filter_chars(username)})"

Return ONLY the fixed code. No explanations.
"""
    },

    "xpath_injection": {
        "category": "Injection",
        "severity": "HIGH",
        "owasp": "A03:2021-Injection",
        "fix_strategy": "String concat in XPath → parameterized XPath",
        "template": """
You are fixing an XPath Injection vulnerability.

VULNERABILITY PATTERN:
- User input concatenated into XPath expressions
- No validation of XPath special characters

FIX STRATEGY:
- Use parameterized XPath with variables
- Escape special characters: ' " [ ] / @ = *
- Use lxml's XPath with variables parameter

EXAMPLE:
BAD:  tree.xpath(f"//user[@name='{username}']")
GOOD: tree.xpath("//user[@name=$name]", name=username)

Return ONLY the fixed code. No explanations.
"""
    },

    # ============ WEB CATEGORY ============
    "xss": {
        "category": "Web",
        "severity": "HIGH",
        "owasp": "A03:2021-Injection",
        "fix_strategy": "Unescaped output → HTML escape, auto-escaping template",
        "template": """
You are fixing a Cross-Site Scripting (XSS) vulnerability.

VULNERABILITY PATTERN:
- User input rendered directly in HTML without escaping
- innerHTML or document.write with user data
- Template rendering without auto-escape

FIX STRATEGY:
- Use html.escape() for Python output
- Enable auto-escaping in templates (Jinja2: autoescape=True)
- Use textContent instead of innerHTML in JavaScript
- Implement Content-Security-Policy headers

EXAMPLE:
BAD:  return f"<div>{user_input}</div>"
GOOD: return f"<div>{html.escape(user_input)}</div>"

Return ONLY the fixed code. No explanations.
"""
    },

    "csrf": {
        "category": "Web",
        "severity": "MEDIUM",
        "owasp": "A01:2021-Broken Access Control",
        "fix_strategy": "Missing token → CSRF middleware generation",
        "template": """
You are fixing a Cross-Site Request Forgery (CSRF) vulnerability.

VULNERABILITY PATTERN:
- State-changing endpoints without CSRF token validation
- Missing CSRF middleware in forms

FIX STRATEGY:
- Add CSRF token to all forms
- Validate CSRF token on server side
- Use framework's built-in CSRF protection
- Set SameSite cookie attribute

EXAMPLE (Flask):
BAD:  @app.route('/transfer', methods=['POST'])
GOOD: from flask_wtf.csrf import CSRFProtect; csrf = CSRFProtect(app)

Return ONLY the fixed code. No explanations.
"""
    },

    "open_redirect": {
        "category": "Web",
        "severity": "MEDIUM",
        "owasp": "A01:2021-Broken Access Control",
        "fix_strategy": "Unvalidated redirect → whitelist allowed URLs",
        "template": """
You are fixing an Open Redirect vulnerability.

VULNERABILITY PATTERN:
- Redirect URL taken from user input without validation
- No whitelist of allowed redirect destinations

FIX STRATEGY:
- Validate redirect URL against whitelist of allowed domains
- Use relative URLs only
- Check that URL starts with '/' and not '//'
- Parse URL and verify host matches allowed list

EXAMPLE:
BAD:  return redirect(request.args.get('next'))
GOOD:
    next_url = request.args.get('next', '/')
    if not is_safe_url(next_url):
        next_url = '/'
    return redirect(next_url)

Return ONLY the fixed code. No explanations.
"""
    },

    "xxe": {
        "category": "Web",
        "severity": "HIGH",
        "owasp": "A05:2021-Security Misconfiguration",
        "fix_strategy": "External entity processing → disable in parser config",
        "template": """
You are fixing an XML External Entity (XXE) vulnerability.

VULNERABILITY PATTERN:
- XML parser with external entity processing enabled
- lxml or xml.etree without secure configuration

FIX STRATEGY:
- Disable external entity processing
- Use defusedxml library
- Set resolve_entities=False in lxml
- Disable DTD processing

EXAMPLE:
BAD:  tree = etree.parse(xml_file)
GOOD:
    from defusedxml import ElementTree
    tree = ElementTree.parse(xml_file)
    # OR
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    tree = etree.parse(xml_file, parser)

Return ONLY the fixed code. No explanations.
"""
    },

    # ============ FILE & DATA CATEGORY ============
    "path_traversal": {
        "category": "File & Data",
        "severity": "HIGH",
        "owasp": "A01:2021-Broken Access Control",
        "fix_strategy": "User input in file path → basename + base dir check",
        "template": """
You are fixing a Path Traversal vulnerability.

VULNERABILITY PATTERN:
- User input used directly in file paths
- No validation for ../ sequences
- No restriction to base directory

FIX STRATEGY:
- Use os.path.basename() to strip directory components
- Resolve path and verify it's within allowed base directory
- Use pathlib for safer path operations

EXAMPLE:
BAD:  open(f"/uploads/{filename}")
GOOD:
    safe_name = os.path.basename(filename)
    full_path = os.path.realpath(os.path.join(BASE_DIR, safe_name))
    if not full_path.startswith(os.path.realpath(BASE_DIR)):
        raise ValueError("Invalid path")
    open(full_path)

Return ONLY the fixed code. No explanations.
"""
    },

    "insecure_deserialization": {
        "category": "File & Data",
        "severity": "CRITICAL",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "fix_strategy": "pickle.loads untrusted data → JSON + type validation",
        "template": """
You are fixing an Insecure Deserialization vulnerability.

VULNERABILITY PATTERN:
- pickle.loads() on untrusted data
- yaml.load() without safe_load
- Deserializing user-controlled data

FIX STRATEGY:
- Use JSON instead of pickle for untrusted data
- Use yaml.safe_load() instead of yaml.load()
- Implement strict type validation after deserialization
- Sign serialized data with HMAC

EXAMPLE:
BAD:  data = pickle.loads(user_data)
GOOD: data = json.loads(user_data)

BAD:  config = yaml.load(file)
GOOD: config = yaml.safe_load(file)

Return ONLY the fixed code. No explanations.
"""
    },

    "arbitrary_file_upload": {
        "category": "File & Data",
        "severity": "HIGH",
        "owasp": "A04:2021-Insecure Design",
        "fix_strategy": "No MIME/ext check → whitelist + rename on upload",
        "template": """
You are fixing an Arbitrary File Upload vulnerability.

VULNERABILITY PATTERN:
- No validation of uploaded file type
- No restriction on file extensions
- Original filename used without sanitization

FIX STRATEGY:
- Whitelist allowed file extensions
- Validate MIME type matches extension
- Generate random filename on server
- Store outside web root

EXAMPLE:
BAD:  file.save(os.path.join(UPLOAD_DIR, file.filename))
GOOD:
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    ext = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Invalid file type")
    safe_name = f"{uuid.uuid4().hex}.{ext}"
    file.save(os.path.join(UPLOAD_DIR, safe_name))

Return ONLY the fixed code. No explanations.
"""
    },

    "log_injection": {
        "category": "File & Data",
        "severity": "MEDIUM",
        "owasp": "A09:2021-Security Logging and Monitoring Failures",
        "fix_strategy": "Raw input in log → sanitize, strip newlines",
        "template": """
You are fixing a Log Injection vulnerability.

VULNERABILITY PATTERN:
- User input logged without sanitization
- Newlines/control characters in log messages
- Log forging possible

FIX STRATEGY:
- Strip newlines and control characters from user input
- Use structured logging (JSON format)
- Encode special characters

EXAMPLE:
BAD:  logger.info(f"User login: {username}")
GOOD:
    safe_username = username.replace('\\n', '').replace('\\r', '')
    logger.info("User login: %s", safe_username)

Return ONLY the fixed code. No explanations.
"""
    },

    # ============ AUTH & CRYPTO CATEGORY ============
    "hardcoded_secrets": {
        "category": "Auth & Crypto",
        "severity": "HIGH",
        "owasp": "A02:2021-Cryptographic Failures",
        "fix_strategy": "Literal API key in source → os.getenv + .env file",
        "template": """
You are fixing a Hardcoded Secrets vulnerability.

VULNERABILITY PATTERN:
- API keys, passwords, tokens hardcoded in source
- Secrets committed to version control

FIX STRATEGY:
- Move secrets to environment variables
- Use os.getenv() or python-dotenv
- Add .env to .gitignore
- Use secrets management service in production

EXAMPLE:
BAD:  API_KEY = "sk-1234567890abcdef"
GOOD:
    import os
    from dotenv import load_dotenv
    load_dotenv()
    API_KEY = os.getenv("API_KEY")

Return ONLY the fixed code. No explanations.
"""
    },

    "weak_hashing": {
        "category": "Auth & Crypto",
        "severity": "HIGH",
        "owasp": "A02:2021-Cryptographic Failures",
        "fix_strategy": "MD5/SHA1 for passwords → bcrypt / argon2 / PBKDF2",
        "template": """
You are fixing a Weak Hashing vulnerability.

VULNERABILITY PATTERN:
- MD5 or SHA1 used for password hashing
- No salt used with hash
- Fast hash functions for passwords

FIX STRATEGY:
- Use bcrypt, argon2, or PBKDF2 for passwords
- These include salt automatically
- Use appropriate work factor

EXAMPLE:
BAD:  password_hash = hashlib.md5(password.encode()).hexdigest()
GOOD:
    import bcrypt
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    # To verify:
    bcrypt.checkpw(password.encode(), stored_hash)

Return ONLY the fixed code. No explanations.
"""
    },

    "broken_jwt_auth": {
        "category": "Auth & Crypto",
        "severity": "CRITICAL",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "fix_strategy": "verify=False → enable all JWT verifications",
        "template": """
You are fixing a Broken JWT Authentication vulnerability.

VULNERABILITY PATTERN:
- JWT verification disabled (verify=False)
- Algorithm not specified (allows 'none')
- Secret key too weak

FIX STRATEGY:
- Always verify JWT signatures
- Explicitly specify allowed algorithms
- Use strong secret keys
- Validate all claims (exp, iss, aud)

EXAMPLE:
BAD:  jwt.decode(token, options={"verify_signature": False})
GOOD:
    jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
        options={"require": ["exp", "iss"]}
    )

Return ONLY the fixed code. No explanations.
"""
    },

    "weak_randomness": {
        "category": "Auth & Crypto",
        "severity": "HIGH",
        "owasp": "A02:2021-Cryptographic Failures",
        "fix_strategy": "random.randint for tokens → secrets.token_hex(32)",
        "template": """
You are fixing a Weak Randomness vulnerability.

VULNERABILITY PATTERN:
- random module used for security-sensitive values
- Predictable token/session ID generation

FIX STRATEGY:
- Use secrets module for cryptographic randomness
- secrets.token_hex() for tokens
- secrets.token_urlsafe() for URL-safe tokens
- os.urandom() for raw bytes

EXAMPLE:
BAD:  token = str(random.randint(100000, 999999))
GOOD:
    import secrets
    token = secrets.token_hex(32)

Return ONLY the fixed code. No explanations.
"""
    },

    # ============ CODE & CONFIG CATEGORY ============
    "insecure_eval": {
        "category": "Code & Config",
        "severity": "CRITICAL",
        "owasp": "A03:2021-Injection",
        "fix_strategy": "eval(user_input) → ast.literal_eval or refactor",
        "template": """
You are fixing an Insecure eval/exec vulnerability.

VULNERABILITY PATTERN:
- eval() or exec() with user input
- Dynamic code execution from untrusted source

FIX STRATEGY:
- Use ast.literal_eval() for safe literal evaluation
- Refactor to avoid dynamic code execution
- Use specific parsers (json.loads, etc.)

EXAMPLE:
BAD:  result = eval(user_expression)
GOOD:
    import ast
    result = ast.literal_eval(user_expression)
    # OR refactor to use specific operations

Return ONLY the fixed code. No explanations.
"""
    },

    "debug_mode_prod": {
        "category": "Code & Config",
        "severity": "MEDIUM",
        "owasp": "A05:2021-Security Misconfiguration",
        "fix_strategy": "debug=True hardcoded → environment variable control",
        "template": """
You are fixing a Debug Mode in Production vulnerability.

VULNERABILITY PATTERN:
- debug=True hardcoded in application
- Detailed error messages exposed
- Debug endpoints accessible

FIX STRATEGY:
- Control debug mode via environment variable
- Default to False (production-safe)
- Use different configs for dev/prod

EXAMPLE:
BAD:  app.run(debug=True)
GOOD:
    import os
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    app.run(debug=DEBUG)

Return ONLY the fixed code. No explanations.
"""
    },

    "permissive_cors": {
        "category": "Code & Config",
        "severity": "MEDIUM",
        "owasp": "A05:2021-Security Misconfiguration",
        "fix_strategy": "Allow-Origin: * → restrict to known trusted origins",
        "template": """
You are fixing an Overly Permissive CORS vulnerability.

VULNERABILITY PATTERN:
- Access-Control-Allow-Origin: *
- Credentials allowed with wildcard origin
- No origin validation

FIX STRATEGY:
- Whitelist specific trusted origins
- Validate Origin header against allowlist
- Don't use wildcard with credentials

EXAMPLE:
BAD:  response.headers['Access-Control-Allow-Origin'] = '*'
GOOD:
    ALLOWED_ORIGINS = ['https://trusted-site.com', 'https://app.example.com']
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin

Return ONLY the fixed code. No explanations.
"""
    },

    "missing_security_headers": {
        "category": "Code & Config",
        "severity": "MEDIUM",
        "owasp": "A05:2021-Security Misconfiguration",
        "fix_strategy": "No CSP/HSTS → security header middleware",
        "template": """
You are fixing Missing Security Headers vulnerability.

VULNERABILITY PATTERN:
- No Content-Security-Policy header
- No Strict-Transport-Security header
- Missing X-Frame-Options, X-Content-Type-Options

FIX STRATEGY:
- Add security headers middleware
- Implement CSP, HSTS, X-Frame-Options
- Use flask-talisman or similar library

EXAMPLE:
GOOD (Flask):
    from flask_talisman import Talisman
    Talisman(app, content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'"
    })

GOOD (Manual):
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

Return ONLY the fixed code. No explanations.
"""
    },

    # ============ RESOURCE & MEMORY CATEGORY ============
    "buffer_overflow": {
        "category": "Resource & Memory",
        "severity": "CRITICAL",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "fix_strategy": "strcpy no bounds → strncpy with explicit size",
        "template": """
You are fixing a Buffer Overflow vulnerability (C/C++).

VULNERABILITY PATTERN:
- strcpy, sprintf, gets without bounds checking
- Fixed-size buffer with unchecked input

FIX STRATEGY:
- Use strncpy, snprintf with explicit size limits
- Use safe string functions (_s variants)
- Validate input length before copy

EXAMPLE:
BAD:  strcpy(buffer, user_input);
GOOD: strncpy(buffer, user_input, sizeof(buffer) - 1);
      buffer[sizeof(buffer) - 1] = '\\0';

Return ONLY the fixed code. No explanations.
"""
    },

    "use_after_free": {
        "category": "Resource & Memory",
        "severity": "CRITICAL",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "fix_strategy": "ptr used after free → NULL after free, smart pointers",
        "template": """
You are fixing a Use After Free vulnerability (C/C++).

VULNERABILITY PATTERN:
- Pointer used after memory is freed
- Dangling pointer references

FIX STRATEGY:
- Set pointer to NULL after free
- Use smart pointers (unique_ptr, shared_ptr)
- Clear references before freeing

EXAMPLE:
BAD:
    free(ptr);
    ptr->value = 0;  // Use after free!

GOOD:
    free(ptr);
    ptr = NULL;
    // OR use smart pointers in C++

Return ONLY the fixed code. No explanations.
"""
    },

    "integer_overflow": {
        "category": "Resource & Memory",
        "severity": "HIGH",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "fix_strategy": "No overflow check → bounds check before arithmetic",
        "template": """
You are fixing an Integer Overflow vulnerability.

VULNERABILITY PATTERN:
- Arithmetic operations without overflow checks
- Size calculations that can wrap around

FIX STRATEGY:
- Check bounds before arithmetic operations
- Use safe integer libraries
- Validate input ranges

EXAMPLE (Python - less common but possible):
BAD:  size = width * height  # Could overflow in C
GOOD:
    if width > MAX_SIZE // height:
        raise ValueError("Size too large")
    size = width * height

Return ONLY the fixed code. No explanations.
"""
    },

    "redos": {
        "category": "Resource & Memory",
        "severity": "MEDIUM",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "fix_strategy": "Catastrophic backtracking regex → rewrite pattern",
        "template": """
You are fixing a ReDoS (Regular Expression Denial of Service) vulnerability.

VULNERABILITY PATTERN:
- Regex with nested quantifiers: (a+)+, (a|a)+
- Overlapping alternations
- Catastrophic backtracking possible

FIX STRATEGY:
- Simplify regex to avoid nested quantifiers
- Use atomic groups or possessive quantifiers
- Set timeout on regex operations
- Use re2 library for guaranteed linear time

EXAMPLE:
BAD:  re.match(r'^(a+)+$', user_input)
GOOD: re.match(r'^a+$', user_input)

BAD:  re.match(r'^([a-zA-Z]+)*$', input)
GOOD: re.match(r'^[a-zA-Z]*$', input)

Return ONLY the fixed code. No explanations.
"""
    },
}


class FixTemplateRegistry:
    """
    Registry for vulnerability fix templates.

    Loads templates from built-in definitions and optional YAML config.
    Provides methods to fetch templates and build prompts for the agent.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the template registry.

        Args:
            config_path: Optional path to vuln_config.yaml for customization
        """
        self.templates: Dict[str, FixTemplate] = {}
        self.config: Dict[str, Any] = {}
        self.enabled_types: List[str] = []

        # Load built-in templates
        self._load_builtin_templates()

        # Load config if provided
        if config_path:
            self.load_config(config_path)

    def _load_builtin_templates(self) -> None:
        """Load all built-in vulnerability templates."""
        for vuln_type, data in VULNERABILITY_TEMPLATES.items():
            self.templates[vuln_type] = FixTemplate(
                vuln_type=vuln_type,
                category=data['category'],
                severity=data['severity'],
                owasp=data['owasp'],
                fix_strategy=data['fix_strategy'],
                template=data['template'],
                cwe_ids=data.get('cwe_ids', []),
                examples=data.get('examples', {})
            )

        # By default, all templates are enabled
        self.enabled_types = list(self.templates.keys())

    def load_config(self, config_path: str) -> None:
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to vuln_config.yaml
        """
        path = Path(config_path)
        if not path.exists():
            return

        try:
            with open(path, 'r') as f:
                self.config = yaml.safe_load(f) or {}

            # Update enabled types from config
            if 'vulnerabilities' in self.config:
                self.enabled_types = self.config['vulnerabilities']

            # Load custom templates if specified
            if 'custom_types' in self.config and self.config['custom_types']:
                self._load_custom_templates(self.config['custom_types'])

            # Apply severity overrides
            if 'severity_override' in self.config and self.config['severity_override']:
                self._apply_severity_overrides(self.config['severity_override'])

        except Exception as e:
            print(f"[FixTemplateRegistry] Error loading config: {e}")

    def _load_custom_templates(self, custom_types: Dict[str, Any]) -> None:
        """Load custom vulnerability types from config."""
        for vuln_type, data in custom_types.items():
            if isinstance(data, dict):
                self.templates[vuln_type] = FixTemplate(
                    vuln_type=vuln_type,
                    category=data.get('category', 'Custom'),
                    severity=data.get('severity', 'MEDIUM'),
                    owasp=data.get('owasp', ''),
                    fix_strategy=data.get('fix_strategy', ''),
                    template=data.get('template', ''),
                    cwe_ids=data.get('cwe_ids', []),
                )

    def _apply_severity_overrides(self, overrides: Dict[str, str]) -> None:
        """Apply severity overrides from config."""
        for vuln_type, severity in overrides.items():
            if vuln_type in self.templates:
                self.templates[vuln_type].severity = severity

    def get_template(self, vuln_type: str) -> Optional[FixTemplate]:
        """
        Get the fix template for a vulnerability type.

        Args:
            vuln_type: The vulnerability type identifier

        Returns:
            FixTemplate object or None if not found
        """
        return self.templates.get(vuln_type.lower())

    def get_template_dict(self, vuln_type: str) -> Optional[Dict[str, Any]]:
        """
        Get template as dictionary (for backward compatibility).

        Args:
            vuln_type: The vulnerability type identifier

        Returns:
            Dict with template details or None if not found
        """
        return VULNERABILITY_TEMPLATES.get(vuln_type.lower())

    def build_prompt(
        self,
        vuln_type: str,
        code_context: str = "",
        vuln_info: Dict[str, Any] = None
    ) -> str:
        """
        Build a complete prompt for the LLM agent.

        Args:
            vuln_type: The vulnerability type
            code_context: Code snippet to fix
            vuln_info: Additional vulnerability information

        Returns:
            Complete prompt string
        """
        template = self.get_template(vuln_type)

        if template:
            return template.get_full_prompt(code_context, vuln_info)

        # Fallback generic prompt
        return self._build_generic_prompt(code_context, vuln_info)

    def _build_generic_prompt(
        self,
        code_context: str = "",
        vuln_info: Dict[str, Any] = None
    ) -> str:
        """Build a generic fix prompt for unknown vulnerability types."""
        vuln_info = vuln_info or {}

        prompt_parts = [
            "You are fixing a security vulnerability.",
            "",
            "Analyze the code context and generate a minimal, targeted fix.",
            "Follow security best practices for this type of vulnerability.",
            "",
            STRICT_CODE_INSTRUCTION.strip(),
        ]

        if code_context:
            prompt_parts.extend([
                "",
                "CODE TO FIX:",
                "```",
                code_context,
                "```",
            ])

        if vuln_info.get('description'):
            prompt_parts.append(f"\nVULNERABILITY: {vuln_info['description']}")

        prompt_parts.extend([
            "",
            "Return ONLY the fixed code:",
        ])

        return "\n".join(prompt_parts)

    def is_enabled(self, vuln_type: str) -> bool:
        """Check if a vulnerability type is enabled."""
        return vuln_type.lower() in [t.lower() for t in self.enabled_types]

    def list_enabled_types(self) -> List[str]:
        """Get list of enabled vulnerability types."""
        return self.enabled_types.copy()

    def list_all_types(self) -> List[str]:
        """Get list of all available vulnerability types."""
        return list(self.templates.keys())

    def get_types_by_category(self, category: str) -> List[str]:
        """Get vulnerability types in a specific category."""
        return [
            vuln_type
            for vuln_type, template in self.templates.items()
            if template.category.lower() == category.lower()
        ]

    def get_categories(self) -> List[str]:
        """Get list of all categories."""
        return list(set(t.category for t in self.templates.values()))

    def get_fix_strategy(self, vuln_type: str) -> str:
        """Get the fix strategy for a vulnerability type."""
        template = self.get_template(vuln_type)
        return template.fix_strategy if template else ""


# Convenience functions for backward compatibility
def get_fix_template(vuln_type: str) -> Optional[Dict[str, Any]]:
    """
    Get the fix template for a specific vulnerability type.

    Args:
        vuln_type: The vulnerability type identifier

    Returns:
        Dict with template details or None if not found
    """
    return VULNERABILITY_TEMPLATES.get(vuln_type.lower())


def get_template_prompt(vuln_type: str) -> str:
    """
    Get just the prompt template string for a vulnerability type.

    Args:
        vuln_type: The vulnerability type identifier

    Returns:
        The template prompt string or a generic prompt if not found
    """
    template = get_fix_template(vuln_type)
    if template:
        return template['template']

    return """
You are fixing a security vulnerability.

Analyze the code context and generate a minimal, targeted fix.
Follow security best practices for this type of vulnerability.

Return ONLY the fixed code. No explanations.
"""


def list_vulnerability_types() -> List[str]:
    """
    Get a list of all supported vulnerability types.

    Returns:
        List of vulnerability type identifiers
    """
    return list(VULNERABILITY_TEMPLATES.keys())


def get_vulnerabilities_by_category(category: str) -> List[str]:
    """
    Get all vulnerability types in a specific category.

    Args:
        category: The category name (e.g., 'Injection', 'Web')

    Returns:
        List of vulnerability type identifiers in that category
    """
    return [
        vuln_type
        for vuln_type, template in VULNERABILITY_TEMPLATES.items()
        if template['category'].lower() == category.lower()
    ]


if __name__ == "__main__":
    import json

    print("=" * 60)
    print("SecureGuard AI - Fix Templates Module Test")
    print("=" * 60)

    # Test the registry
    registry = FixTemplateRegistry()

    print(f"\nTotal vulnerability types: {len(registry.list_all_types())}")

    print("\nVulnerability types by category:")
    for category in sorted(registry.get_categories()):
        vulns = registry.get_types_by_category(category)
        print(f"  {category}: {len(vulns)} types")
        for v in vulns:
            template = registry.get_template(v)
            print(f"    - {v} ({template.severity})")

    # Test the 5 core templates
    print("\n" + "=" * 60)
    print("Testing 5 Core Templates")
    print("=" * 60)

    core_types = ['sql_injection', 'xss', 'command_injection', 'path_traversal', 'hardcoded_secrets']

    for vuln_type in core_types:
        template = registry.get_template(vuln_type)
        print(f"\n--- {vuln_type.upper()} ---")
        print(f"Category: {template.category}")
        print(f"Severity: {template.severity}")
        print(f"OWASP: {template.owasp}")
        print(f"Fix Strategy: {template.fix_strategy}")

    # Test prompt building
    print("\n" + "=" * 60)
    print("Sample Prompt (SQL Injection)")
    print("=" * 60)

    sample_code = '''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()'''

    vuln_info = {
        'description': 'SQL injection via f-string in query',
        'line_number': 2,
        'file_path': 'app/database.py'
    }

    prompt = registry.build_prompt('sql_injection', sample_code, vuln_info)
    print(prompt)

    print("\n" + "=" * 60)
    print("Fix Templates test completed!")
    print("=" * 60)
