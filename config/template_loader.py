"""
SecureGuard AI - Template Loader Module

This module loads vulnerability configuration from YAML and maps
vulnerability types to their corresponding fix templates.

Usage:
    from config.template_loader import TemplateLoader
    
    loader = TemplateLoader()
    template = loader.get_template_for_vuln('sql_injection')
    prompt = loader.build_fix_prompt('sql_injection', code_context, vuln_info)
"""

import os
import sys
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, field

import yaml

# Ensure parent directory is in path for imports
_parent_dir = Path(__file__).parent.parent
if str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))


@dataclass
class VulnConfig:
    """Configuration for a single vulnerability type."""
    vuln_type: str
    template_source: str  # 'builtin' or path to custom template
    fix_strategy: str
    priority: int
    category: str = ""
    severity: str = "MEDIUM"
    enabled: bool = True


@dataclass
class TemplateConfig:
    """Global template configuration."""
    strict_code_output: bool = True
    include_examples: bool = True
    max_context_lines: int = 50


class TemplateLoader:
    """
    Loads vulnerability configuration and maps vuln_type to templates.
    
    This class:
    1. Loads config/vuln_config.yaml
    2. Maps vulnerability types to template identifiers
    3. Provides access to fix templates for the agent
    """
    
    DEFAULT_CONFIG_PATH = "config/vuln_config.yaml"
    
    def __init__(self, config_path: Optional[str] = None, base_dir: Optional[str] = None):
        """
        Initialize the template loader.
        
        Args:
            config_path: Path to vuln_config.yaml (relative or absolute)
            base_dir: Base directory for resolving relative paths
        """
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).parent.parent
        self.config_path = config_path or str(self.base_dir / self.DEFAULT_CONFIG_PATH)
        
        self.config: Dict[str, Any] = {}
        self.vuln_configs: Dict[str, VulnConfig] = {}
        self.template_config = TemplateConfig()
        self.enabled_types: List[str] = []
        self.categories: Dict[str, Dict[str, Any]] = {}
        
        # Lazy-loaded template registry
        self._template_registry = None
        
        # Load configuration
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from YAML file."""
        config_file = Path(self.config_path)
        
        if not config_file.exists():
            # Try relative to base_dir
            config_file = self.base_dir / self.config_path
        
        if not config_file.exists():
            print(f"[TemplateLoader] Config not found: {config_file}, using defaults")
            self._load_defaults()
            return
        
        try:
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f) or {}
            
            self._parse_config()
            print(f"[TemplateLoader] Loaded config from {config_file}")
            
        except Exception as e:
            print(f"[TemplateLoader] Error loading config: {e}")
            self._load_defaults()
    
    def _parse_config(self) -> None:
        """Parse the loaded configuration."""
        # Parse template settings
        settings = self.config.get('settings', {})
        template_settings = settings.get('template_settings', {})
        
        self.template_config = TemplateConfig(
            strict_code_output=template_settings.get('strict_code_output', True),
            include_examples=template_settings.get('include_examples', True),
            max_context_lines=template_settings.get('max_context_lines', 50)
        )
        
        # Parse enabled vulnerability types
        self.enabled_types = self.config.get('vulnerabilities', [])
        
        # Parse categories
        self.categories = self.config.get('categories', {})
        
        # Parse template mappings
        template_mappings = self.config.get('template_mappings', {})
        
        for vuln_type, mapping in template_mappings.items():
            if isinstance(mapping, dict):
                # Find category for this vuln_type
                category = self._find_category(vuln_type)
                
                self.vuln_configs[vuln_type] = VulnConfig(
                    vuln_type=vuln_type,
                    template_source=mapping.get('template', 'builtin'),
                    fix_strategy=mapping.get('fix_strategy', ''),
                    priority=mapping.get('priority', 2),
                    category=category,
                    enabled=vuln_type in self.enabled_types
                )
    
    def _find_category(self, vuln_type: str) -> str:
        """Find the category for a vulnerability type."""
        for cat_key, cat_data in self.categories.items():
            if isinstance(cat_data, dict):
                types = cat_data.get('types', [])
                if vuln_type in types:
                    return cat_data.get('name', cat_key)
        return "Unknown"
    
    def _load_defaults(self) -> None:
        """Load default configuration when YAML is not available."""
        default_types = [
            'sql_injection', 'xss', 'command_injection', 
            'path_traversal', 'hardcoded_secrets'
        ]
        
        self.enabled_types = default_types
        
        for vuln_type in default_types:
            self.vuln_configs[vuln_type] = VulnConfig(
                vuln_type=vuln_type,
                template_source='builtin',
                fix_strategy='',
                priority=1,
                enabled=True
            )
    
    @property
    def template_registry(self):
        """Lazy-load the template registry."""
        if self._template_registry is None:
            from prompts.fix_templates import FixTemplateRegistry
            self._template_registry = FixTemplateRegistry(self.config_path)
        return self._template_registry
    
    def get_vuln_config(self, vuln_type: str) -> Optional[VulnConfig]:
        """
        Get configuration for a vulnerability type.
        
        Args:
            vuln_type: The vulnerability type identifier
            
        Returns:
            VulnConfig or None if not found
        """
        return self.vuln_configs.get(vuln_type.lower())
    
    def get_template_for_vuln(self, vuln_type: str) -> Optional[Any]:
        """
        Get the fix template for a vulnerability type.
        
        Args:
            vuln_type: The vulnerability type identifier
            
        Returns:
            FixTemplate object or None if not found
        """
        config = self.get_vuln_config(vuln_type)
        
        if not config:
            # Try to get from registry directly
            return self.template_registry.get_template(vuln_type)
        
        if config.template_source == 'builtin':
            return self.template_registry.get_template(vuln_type)
        else:
            # Load custom template from file
            return self._load_custom_template(config.template_source, vuln_type)
    
    def _load_custom_template(self, template_path: str, vuln_type: str) -> Optional[Any]:
        """Load a custom template from file."""
        from prompts.fix_templates import FixTemplate
        
        full_path = self.base_dir / template_path
        
        if not full_path.exists():
            print(f"[TemplateLoader] Custom template not found: {full_path}")
            return None
        
        try:
            content = full_path.read_text()
            
            return FixTemplate(
                vuln_type=vuln_type,
                category="Custom",
                severity="MEDIUM",
                owasp="",
                fix_strategy="Custom fix strategy",
                template=content
            )
        except Exception as e:
            print(f"[TemplateLoader] Error loading custom template: {e}")
            return None
    
    def build_fix_prompt(
        self,
        vuln_type: str,
        code_context: str = "",
        vuln_info: Dict[str, Any] = None
    ) -> str:
        """
        Build a complete fix prompt for the agent.
        
        Args:
            vuln_type: The vulnerability type
            code_context: Code snippet to fix
            vuln_info: Additional vulnerability information
            
        Returns:
            Complete prompt string
        """
        return self.template_registry.build_prompt(vuln_type, code_context, vuln_info)
    
    def is_enabled(self, vuln_type: str) -> bool:
        """Check if a vulnerability type is enabled."""
        return vuln_type.lower() in [t.lower() for t in self.enabled_types]
    
    def get_enabled_types(self) -> List[str]:
        """Get list of enabled vulnerability types."""
        return self.enabled_types.copy()
    
    def get_fix_strategy(self, vuln_type: str) -> str:
        """Get the fix strategy for a vulnerability type."""
        config = self.get_vuln_config(vuln_type)
        if config and config.fix_strategy:
            return config.fix_strategy
        
        # Fall back to template registry
        return self.template_registry.get_fix_strategy(vuln_type)
    
    def get_priority(self, vuln_type: str) -> int:
        """Get the priority for a vulnerability type (1=highest)."""
        config = self.get_vuln_config(vuln_type)
        return config.priority if config else 2
    
    def get_types_by_priority(self, priority: int) -> List[str]:
        """Get vulnerability types with a specific priority."""
        return [
            vuln_type
            for vuln_type, config in self.vuln_configs.items()
            if config.priority == priority and config.enabled
        ]
    
    def get_types_by_category(self, category: str) -> List[str]:
        """Get vulnerability types in a specific category."""
        return self.template_registry.get_types_by_category(category)
    
    def get_all_categories(self) -> List[str]:
        """Get list of all categories."""
        return list(set(
            config.category for config in self.vuln_configs.values()
            if config.category
        ))
    
    def get_settings(self) -> Dict[str, Any]:
        """Get global settings from config."""
        return self.config.get('settings', {})
    
    def get_scanner_mapping(self, scanner: str, rule_id: str) -> Optional[str]:
        """
        Map a scanner rule ID to a vulnerability type.
        
        Args:
            scanner: Scanner name (e.g., 'bandit', 'semgrep')
            rule_id: Scanner-specific rule ID
            
        Returns:
            Vulnerability type or None if not mapped
        """
        scanner_mappings = self.config.get('scanner_mappings', {})
        scanner_rules = scanner_mappings.get(scanner.lower(), {})
        
        if isinstance(scanner_rules, dict):
            return scanner_rules.get(rule_id)
        
        return None


# Singleton instance for convenience
_default_loader: Optional[TemplateLoader] = None


def get_template_loader(config_path: Optional[str] = None) -> TemplateLoader:
    """
    Get the default template loader instance.
    
    Args:
        config_path: Optional config path (only used on first call)
        
    Returns:
        TemplateLoader instance
    """
    global _default_loader
    
    if _default_loader is None:
        _default_loader = TemplateLoader(config_path)
    
    return _default_loader


def get_template(vuln_type: str) -> Optional[Any]:
    """
    Convenience function to get a template.
    
    Args:
        vuln_type: The vulnerability type
        
    Returns:
        FixTemplate or None
    """
    return get_template_loader().get_template_for_vuln(vuln_type)


def build_prompt(vuln_type: str, code_context: str = "", vuln_info: Dict[str, Any] = None) -> str:
    """
    Convenience function to build a fix prompt.
    
    Args:
        vuln_type: The vulnerability type
        code_context: Code to fix
        vuln_info: Additional info
        
    Returns:
        Complete prompt string
    """
    return get_template_loader().build_fix_prompt(vuln_type, code_context, vuln_info)


if __name__ == "__main__":
    import json
    
    print("=" * 60)
    print("SecureGuard AI - Template Loader Test")
    print("=" * 60)
    
    # Initialize loader
    loader = TemplateLoader()
    
    print(f"\nEnabled vulnerability types: {len(loader.get_enabled_types())}")
    
    # Test the 5 core types
    core_types = ['sql_injection', 'xss', 'command_injection', 'path_traversal', 'hardcoded_secrets']
    
    print("\n--- Core Vulnerability Types ---")
    for vuln_type in core_types:
        config = loader.get_vuln_config(vuln_type)
        template = loader.get_template_for_vuln(vuln_type)
        
        print(f"\n{vuln_type.upper()}:")
        print(f"  Enabled: {loader.is_enabled(vuln_type)}")
        print(f"  Priority: {loader.get_priority(vuln_type)}")
        print(f"  Fix Strategy: {loader.get_fix_strategy(vuln_type)}")
        print(f"  Template: {'Found' if template else 'Not found'}")
    
    # Test prompt building
    print("\n" + "=" * 60)
    print("Testing Prompt Building")
    print("=" * 60)
    
    sample_code = '''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()'''
    
    vuln_info = {
        'description': 'SQL injection via f-string',
        'line_number': 2
    }
    
    prompt = loader.build_fix_prompt('sql_injection', sample_code, vuln_info)
    print("\nGenerated prompt preview (first 500 chars):")
    print(prompt[:500] + "...")
    
    # Test scanner mapping
    print("\n" + "=" * 60)
    print("Testing Scanner Mappings")
    print("=" * 60)
    
    test_mappings = [
        ('bandit', 'B608'),
        ('bandit', 'B102'),
        ('bandit', 'B303'),
    ]
    
    for scanner, rule_id in test_mappings:
        vuln_type = loader.get_scanner_mapping(scanner, rule_id)
        print(f"  {scanner}:{rule_id} -> {vuln_type or 'Not mapped'}")
    
    # Test priority grouping
    print("\n" + "=" * 60)
    print("Vulnerability Types by Priority")
    print("=" * 60)
    
    for priority in [1, 2, 3]:
        types = loader.get_types_by_priority(priority)
        print(f"\n  Priority {priority}: {len(types)} types")
        for t in types[:5]:  # Show first 5
            print(f"    - {t}")
        if len(types) > 5:
            print(f"    ... and {len(types) - 5} more")
    
    print("\n" + "=" * 60)
    print("Template Loader test completed!")
    print("=" * 60)
