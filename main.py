"""CLI entry point for the IaC Security Review Agent."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from checks import run_checks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Review a Terraform file for common AWS security misconfigurations.")
    parser.add_argument("terraform_file", help="Path to a .tf file to review")
    parser.add_argument("--no-ai", action="store_true", help="Run static checks only; do not call the Anthropic API")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = Path(args.terraform_file)

    if path.suffix.lower() != ".tf":
        print("Error: input must be a Terraform .tf file.", file=sys.stderr)
        return 2
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2

    load_dotenv()
    terraform_text = path.read_text(encoding="utf-8")
    findings = run_checks(terraform_text)

    print("=" * 72)
    print("IaC SECURITY REVIEW")
    print("=" * 72)
    print(f"File: {path}")
    print(f"Static findings: {len(findings)}")

    if findings:
        print("\nDetected issues:")
        for finding in findings:
            print(f"  [{finding['severity']}] {finding['rule_id']} - line {finding['line']}: {finding['title']}")
            print(f"      {finding['evidence']}")
    else:
        print("\nNo static findings detected.")

    if args.no_ai:
        return 0

    if not os.getenv("ANTHROPIC_API_KEY"):
        print("\nAI explanation skipped: ANTHROPIC_API_KEY is not set.")
        print("Run with --no-ai for a static-only review, or configure the API key.")
        return 0

    print("\n" + "=" * 72)
    print("AI REVIEW COMMENTS")
    print("=" * 72)
    try:
        from agent import explain_findings
        print(explain_findings(findings, str(path)))
    except Exception as exc:
        print(f"AI review failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
