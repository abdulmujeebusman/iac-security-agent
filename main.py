"""CLI entry point for the IaC Security Review Agent."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from agent import strip_control_chars  # agent imports the Strands SDK lazily
from checks import SEVERITY_RANK, run_checks

MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Review a Terraform file for common AWS security misconfigurations."
    )
    parser.add_argument("terraform_file", help="Path to a .tf file to review")
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Run static checks only; do not call the AI API",
    )
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "none"),
        default="none",
        help=(
            "Exit with status 1 if any finding is at or above this severity "
            "(for CI gates). Default: none"
        ),
    )
    return parser.parse_args(argv)


def should_fail(findings: list[dict], threshold: str) -> bool:
    if threshold == "none":
        return False
    limit = SEVERITY_RANK[threshold.upper()]
    return any(SEVERITY_RANK.get(f["severity"], 99) <= limit for f in findings)


def read_terraform(path: Path) -> str:
    """Read a Terraform file, rejecting anything that isn't a sane text file."""
    if path.suffix.lower() != ".tf":
        raise ValueError("input must be a Terraform .tf file.")
    if not path.is_file():
        raise FileNotFoundError(f"file not found: {path}")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"file is larger than {MAX_FILE_BYTES // 1024} KiB: {path}")
    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"file is not valid UTF-8 text: {path}") from exc


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    path = Path(args.terraform_file)

    try:
        terraform_text = read_terraform(path)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    load_dotenv()
    findings = run_checks(terraform_text)
    exit_code = EXIT_FINDINGS if should_fail(findings, args.fail_on) else EXIT_OK

    print("=" * 72)
    print("IaC SECURITY REVIEW")
    print("=" * 72)
    print(f"File: {path}")
    print(f"Static findings: {len(findings)}")

    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = finding["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    if severity_counts:
        print("\nSeverity summary:")
        for severity in SEVERITY_RANK:
            if severity in severity_counts:
                print(f"  {severity:<10} {severity_counts[severity]}")

    if findings:
        print("\nDetected issues:")
        for finding in findings:
            print(
                f"  [{finding['severity']}] {finding['rule_id']} - "
                f"line {finding['line']}: {finding['title']}"
            )
            print(f"      {finding['evidence']}")
    else:
        print("\nNo static findings detected.")

    if args.no_ai or not findings:
        return exit_code

    if not os.getenv("OPENROUTER_API_KEY"):
        print("\nAI explanation skipped: OPENROUTER_API_KEY is not set.")
        print("Run with --no-ai for a static-only review, or configure the API key.")
        return exit_code

    print("\n" + "=" * 72)
    print("AI REVIEW COMMENTS")
    print("=" * 72)

    try:
        from agent import explain_findings

        print(explain_findings(findings, str(path)))
    except Exception as exc:  # AI is best-effort; never mask static results.
        message = str(exc)
        api_key = os.getenv("OPENROUTER_API_KEY", "")
        if api_key:
            message = message.replace(api_key, "<redacted>")
        message = strip_control_chars(message)
        print(f"AI review unavailable: {type(exc).__name__}: {message[:300]}", file=sys.stderr)
        print("Static security findings above remain valid.")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
