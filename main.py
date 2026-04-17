#!/usr/bin/env python3
"""
SecureGuard AI - Main Entry Point

AI Security Vulnerability Detection & Code Remediation Agent

This is the single entry point that wires all modules together.
Usage: python main.py --scan report.json --repo ./myproject

Pipeline:
  parse → filter → locate → agent → validate → review → patch → report

Outputs:
- /output/*.patch - Git-compatible patch files
- /output/*.md - Markdown reports
"""

import argparse
import sys
import os
import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Import core modules
from parser import ScanReportParser, parse_scan_report
from fp_filter import FalsePositiveFilter, filter_false_positives
from locator import CodeLocator, locate_vulnerability
from validator import FixValidator, validate_fix
from patch_generator import PatchGenerator, generate_patch
from reporter import ReportGenerator, generate_report
from reviewer import FixReviewer, ReviewMode, review_fix

# Import agent modules
from agent.agent import RemediationAgent, AgentConfig


def print_banner():
    """Print the SecureGuard AI banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗           ║
║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝           ║
║   ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗             ║
║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝             ║
║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗           ║
║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝           ║
║                                                               ║
║   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗                    ║
║   ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗                   ║
║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║                   ║
║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║                   ║
║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝                   ║
║    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                    ║
║                                                               ║
║   AI Security Vulnerability Detection & Code Remediation      ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="SecureGuard AI - AI Security Vulnerability Detection & Code Remediation Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --scan report.json --repo ./myproject
  python main.py --scan bandit_output.json --repo ./app --mode automatic
  python main.py --scan semgrep.json --repo . --output ./fixes
        """
    )

    parser.add_argument(
        '--scan', '-s',
        type=str,
        required=True,
        help='Path to the security scan report (JSON format)'
    )

    parser.add_argument(
        '--repo', '-r',
        type=str,
        default='.',
        help='Path to the repository to fix (default: current directory)'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        default='output',
        help='Output directory for patches and reports (default: output)'
    )

    parser.add_argument(
        '--mode', '-m',
        type=str,
        choices=['interactive', 'automatic'],
        default='interactive',
        help='Review mode: interactive (default) or automatic'
    )

    parser.add_argument(
        '--max-retries',
        type=int,
        default=3,
        help='Maximum retry attempts per vulnerability (default: 3)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Parse and analyze only, do not generate fixes'
    )

    parser.add_argument(
        '--filter-only',
        action='store_true',
        help='Only run false positive filtering, do not fix'
    )

    return parser.parse_args()


def log_progress(stage: int, total_stages: int, message: str, verbose: bool = True):
    """Print progress log with stage indicator."""
    if verbose:
        print(f"[{stage}/{total_stages}] {message}")


def run_pipeline(
    scan_path: str,
    repo_path: str,
    output_dir: str,
    mode: str = 'interactive',
    max_retries: int = 3,
    verbose: bool = False,
    dry_run: bool = False,
    filter_only: bool = False
) -> Dict[str, Any]:
    """
    Run the full SecureGuard AI pipeline.

    Pipeline: parse → filter → locate → agent → validate → review → patch → report

    Args:
        scan_path: Path to scan report
        repo_path: Path to repository
        output_dir: Output directory
        mode: Review mode ('interactive' or 'automatic')
        max_retries: Max retry attempts per vulnerability
        verbose: Verbose output
        dry_run: Parse only, no fixes
        filter_only: Filter only, no fixes

    Returns:
        Dict with pipeline results
    """
    start_time = datetime.now()

    results = {
        'total_vulnerabilities': 0,
        'false_positives': 0,
        'fixes_attempted': 0,
        'fixes_verified': 0,
        'fixes_unverified': 0,
        'fixes_approved': 0,
        'fixes_rejected': 0,
        'patches_generated': 0,
        'reports_generated': 0,
        'vulnerabilities': [],
        'errors': []
    }

    # Ensure output directory exists
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # ========================================================================
    # STAGE 1: PARSE - Read scan report
    # ========================================================================
    print("\n" + "=" * 70)
    print("📥 STAGE 1: PARSE - Reading scan report")
    print("=" * 70)

    try:
        parser = ScanReportParser()
        vulnerabilities = parser.parse(scan_path)
        results['total_vulnerabilities'] = len(vulnerabilities)
        print(f"[Parse] ✓ Found {len(vulnerabilities)} vulnerabilities")

        if verbose:
            for v in vulnerabilities[:5]:
                print(f"  • {v.get('vuln_type', 'unknown')} in {v.get('file_path', 'unknown')}:{v.get('line_number', 0)}")
            if len(vulnerabilities) > 5:
                print(f"  ... and {len(vulnerabilities) - 5} more")
    except Exception as e:
        print(f"[Parse] ✗ Error: {e}")
        results['errors'].append(f"Parse error: {e}")
        return results

    if not vulnerabilities:
        print("[Parse] No vulnerabilities found in report")
        return results

    # ========================================================================
    # STAGE 2: FILTER - Remove false positives
    # ========================================================================
    print("\n" + "=" * 70)
    print("🔍 STAGE 2: FILTER - Removing false positives")
    print("=" * 70)

    fp_filter = FalsePositiveFilter(verbose=verbose)
    filtered_vulns = fp_filter.filter_vulnerabilities(vulnerabilities, repo_path)

    # Get actionable vulnerabilities (not false positives)
    actionable = [v for v in filtered_vulns if not v.get('is_false_positive', False)]
    results['false_positives'] = len(filtered_vulns) - len(actionable)

    print(f"[Filter] ✓ Actionable: {len(actionable)}, False positives: {results['false_positives']}")

    if filter_only:
        print("\n[Filter] Filter-only mode enabled, stopping pipeline")
        results['vulnerabilities'] = filtered_vulns
        return results

    if dry_run:
        print("\n[DryRun] Dry run mode enabled, stopping pipeline")
        results['vulnerabilities'] = filtered_vulns
        return results

    if not actionable:
        print("[Filter] No actionable vulnerabilities after filtering")
        results['vulnerabilities'] = filtered_vulns
        return results

    # ========================================================================
    # Initialize pipeline components
    # ========================================================================
    print("\n" + "=" * 70)
    print("⚙️  Initializing pipeline components...")
    print("=" * 70)

    locator = CodeLocator(repo_path, verbose=verbose)
    validator = FixValidator(repo_path=repo_path, verbose=verbose)
    patch_gen = PatchGenerator(output_dir=output_dir, verbose=verbose)
    report_gen = ReportGenerator(output_dir=output_dir, verbose=verbose)
    reviewer = FixReviewer(
        ReviewMode.AUTOMATIC if mode == 'automatic' else ReviewMode.INTERACTIVE
    )

    # Initialize agent (may fail if no API key)
    agent = None
    agent_config = AgentConfig(
        max_attempts=max_retries,
        verbose=verbose
    )

    try:
        agent = RemediationAgent(agent_config)
        if agent.initialize():
            print(f"[Agent] ✓ Initialized with {agent_config.llm_model}")
        else:
            print(f"[Agent] ⚠ Could not initialize LLM (no API key?)")
            print(f"[Agent]   Set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env")
    except Exception as e:
        print(f"[Agent] ⚠ Agent initialization failed: {e}")

    # ========================================================================
    # STAGES 3-8: Process each vulnerability
    # ========================================================================
    for i, vuln in enumerate(actionable, 1):
        print(f"\n{'=' * 70}")
        print(f"🔧 PROCESSING VULNERABILITY {i}/{len(actionable)}")
        print(f"   Type: {vuln.get('vuln_type', 'unknown')}")
        print(f"   File: {vuln.get('file_path', 'unknown')}:{vuln.get('line_number', 0)}")
        print(f"{'=' * 70}")

        try:
            # ==== STAGE 3: LOCATE ====
            print(f"\n[3/8] 📍 LOCATE - Finding vulnerable code")
            vuln = locator.locate(vuln)

            if vuln.get('locate_error'):
                print(f"[Locate] ✗ Error: {vuln['locate_error']}")
                results['vulnerabilities'].append(vuln)
                continue

            original_code = vuln.get('file_content', '') or locator.get_file_content(vuln.get('file_path', ''))
            print(f"[Locate] ✓ Found code context ({len(vuln.get('code_snippet', ''))} chars)")

            # ==== STAGE 4: AGENT (FIX GENERATION) ====
            print(f"\n[4/8] 🤖 AGENT - Generating fix")
            results['fixes_attempted'] += 1

            if agent and agent.llm:
                # Use feedback loop for better fixes
                try:
                    fix_result = agent.process_with_feedback(vuln)
                    vuln.update(fix_result)
                    print(f"[Agent] ✓ Fix generated (status: {fix_result.get('status', 'unknown')})")
                except Exception as e:
                    print(f"[Agent] ✗ Error generating fix: {e}")
                    vuln['agent_error'] = str(e)
                    vuln['status'] = 'AGENT_ERROR'
            else:
                print(f"[Agent] ⚠ No LLM available, skipping fix generation")
                vuln['status'] = 'NO_LLM'
                results['vulnerabilities'].append(vuln)
                continue

            # ==== STAGE 5: VALIDATE ====
            print(f"\n[5/8] ✅ VALIDATE - Running tests")

            proposed_fix = vuln.get('proposed_fix', '') or vuln.get('fix', '') or vuln.get('best_fix', '')
            if proposed_fix:
                validation_result = validator.validate(vuln, proposed_fix)
                vuln.update(validation_result)

                status = vuln.get('status', 'UNKNOWN')
                if status == 'VERIFIED':
                    results['fixes_verified'] += 1
                    print(f"[Validate] ✓ Fix verified (tests passed)")
                else:
                    results['fixes_unverified'] += 1
                    print(f"[Validate] ⚠ Fix status: {status}")
            else:
                vuln['status'] = 'NO_FIX_GENERATED'
                print(f"[Validate] ✗ No fix to validate")

            # ==== STAGE 6: REVIEW ====
            print(f"\n[6/8] 👁️  REVIEW - Developer approval")
            vuln = reviewer.review(vuln)

            decision = vuln.get('review_decision', 'rejected')
            if decision == 'approved':
                results['fixes_approved'] += 1
                print(f"[Review] ✓ Fix approved")
            else:
                results['fixes_rejected'] += 1
                print(f"[Review] ✗ Fix {decision}")
                results['vulnerabilities'].append(vuln)
                continue

            # ==== STAGE 7: PATCH ====
            print(f"\n[7/8] 📝 PATCH - Generating git diff")

            if original_code and proposed_fix:
                vuln = patch_gen.generate(vuln, original_code, proposed_fix)
                if vuln.get('patch_file_path'):
                    results['patches_generated'] += 1
                    print(f"[Patch] ✓ Generated: {vuln.get('patch_filename')}")
                else:
                    print(f"[Patch] ⚠ No patch generated")
            else:
                print(f"[Patch] ✗ Missing original code or fix")

            # ==== STAGE 8: REPORT ====
            print(f"\n[8/8] 📄 REPORT - Generating documentation")
            vuln = report_gen.generate(vuln)
            if vuln.get('report_file_path'):
                results['reports_generated'] += 1
                print(f"[Report] ✓ Generated: {vuln.get('report_filename')}")

            results['vulnerabilities'].append(vuln)

        except Exception as e:
            print(f"\n[Error] ✗ Failed to process vulnerability: {e}")
            vuln['pipeline_error'] = str(e)
            results['errors'].append(f"Vulnerability {i}: {e}")
            results['vulnerabilities'].append(vuln)

    # ========================================================================
    # Generate summary report
    # ========================================================================
    print("\n" + "=" * 70)
    print("📊 GENERATING SUMMARY REPORT")
    print("=" * 70)

    try:
        summary_path = report_gen.generate_summary_report(results['vulnerabilities'])
        print(f"[Summary] ✓ Generated: {summary_path}")
    except Exception as e:
        print(f"[Summary] ✗ Error: {e}")

    # Calculate duration
    duration = datetime.now() - start_time
    results['duration_seconds'] = duration.total_seconds()

    # Save results JSON
    results_path = output_path / f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(results_path, 'w') as f:
            # Convert non-serializable items
            serializable_results = {
                k: v for k, v in results.items()
                if k != 'vulnerabilities'
            }
            serializable_results['vulnerability_count'] = len(results['vulnerabilities'])
            json.dump(serializable_results, f, indent=2, default=str)
        print(f"[Results] ✓ Saved: {results_path}")
    except Exception as e:
        print(f"[Results] ⚠ Could not save results: {e}")

    return results


def print_summary(results: Dict[str, Any]):
    """Print pipeline execution summary."""
    print("\n" + "=" * 70)
    print("╔" + "═" * 68 + "╗")
    print("║" + " SECUREGUARD AI - EXECUTION SUMMARY ".center(68) + "║")
    print("╚" + "═" * 68 + "╝")

    duration = results.get('duration_seconds', 0)
    duration_str = f"{int(duration // 60)}m {int(duration % 60)}s" if duration >= 60 else f"{duration:.1f}s"

    print(f"""
📊 STATISTICS
   ─────────────────────────────────────────
   Total Vulnerabilities:  {results['total_vulnerabilities']}
   False Positives:        {results['false_positives']}
   ─────────────────────────────────────────
   Fixes Attempted:        {results['fixes_attempted']}
   Fixes Verified:         {results['fixes_verified']}
   Fixes Unverified:       {results['fixes_unverified']}
   ─────────────────────────────────────────
   Fixes Approved:         {results.get('fixes_approved', 0)}
   Fixes Rejected:         {results.get('fixes_rejected', 0)}
   ─────────────────────────────────────────
   Patches Generated:      {results['patches_generated']}
   Reports Generated:      {results['reports_generated']}
   ─────────────────────────────────────────
   Duration:               {duration_str}
""")

    if results['fixes_attempted'] > 0:
        accuracy = (results['fixes_verified'] / results['fixes_attempted']) * 100
        print(f"   Fix Accuracy:          {accuracy:.1f}%")

    if results.get('errors'):
        print(f"\n⚠️  ERRORS ({len(results['errors'])}):")
        for err in results['errors'][:5]:
            print(f"   • {err}")
        if len(results['errors']) > 5:
            print(f"   ... and {len(results['errors']) - 5} more")

    print("\n" + "=" * 70)


def main():
    """Main entry point."""
    print_banner()

    args = parse_arguments()

    print(f"\n📁 Scan Report: {args.scan}")
    print(f"📂 Repository:  {args.repo}")
    print(f"📤 Output:      {args.output}")
    print(f"🔧 Mode:        {args.mode}")
    print(f"🔄 Max Retries: {args.max_retries}")

    # Validate inputs
    scan_path = Path(args.scan)
    repo_path = Path(args.repo)
    output_path = Path(args.output)

    if not scan_path.exists():
        print(f"\n❌ Error: Scan report not found: {args.scan}")
        sys.exit(1)

    if not repo_path.exists():
        print(f"\n❌ Error: Repository not found: {args.repo}")
        sys.exit(1)

    # Create output directory
    output_path.mkdir(parents=True, exist_ok=True)
    print(f"\n📂 Output directory: {output_path.absolute()}")

    # Run pipeline
    try:
        results = run_pipeline(
            scan_path=str(scan_path.absolute()),
            repo_path=str(repo_path.absolute()),
            output_dir=str(output_path.absolute()),
            mode=args.mode,
            max_retries=args.max_retries,
            verbose=args.verbose,
            dry_run=args.dry_run,
            filter_only=args.filter_only
        )

        print_summary(results)

        # Final status
        print("\n" + "=" * 70)
        if results['patches_generated'] > 0:
            print("✅ SecureGuard AI completed successfully!")
            print(f"\n📁 OUTPUT FILES:")
            print(f"   Patches: {output_path.absolute()}/*.patch")
            print(f"   Reports: {output_path.absolute()}/*.md")
            print(f"\n💡 To apply patches:")
            print(f"   git apply {output_path}/<patch_file>.patch")
        elif results['fixes_verified'] > 0:
            print("✅ Fixes verified but not approved for patching.")
            print("   Run in interactive mode to review and approve fixes.")
        elif results['total_vulnerabilities'] > 0:
            print("⚠️  No verified fixes generated.")
            print("   Check the output for details on why fixes failed.")
        else:
            print("ℹ️  No vulnerabilities found in scan report.")
        print("=" * 70)

        # Exit with appropriate code
        sys.exit(0 if results['patches_generated'] > 0 else 1)

    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
