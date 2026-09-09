"""Simple, explainable security checks for Terraform source files.

These checks intentionally use lightweight regex/text matching. They are not a
replacement for a full Terraform parser or a production security scanner.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Callable


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    line: int
    evidence: str

    def to_dict(self) -> dict:
        return asdict(self)


def _line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _evidence(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1].strip()[:180] if 0 < line <= len(lines) else ""


def _matches(pattern: str, text: str, flags: int = re.IGNORECASE) -> list[tuple[int, str]]:
    return [(_line_number(text, m.start()), m.group(0)) for m in re.finditer(pattern, text, flags)]


def check_public_s3(text: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = r"(?:acl\s*=\s*\"public-(?:read|read-write)\"|acl\s*=\s*\"authenticated-read\")"
    for line, _ in _matches(pattern, text):
        findings.append(Finding("S3_PUBLIC_ACL", "HIGH", "S3 bucket may be publicly accessible", line, _evidence(text, line)))

    # Explicitly disabled public-access-block settings are also risky.
    pattern = r"(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false"
    for line, _ in _matches(pattern, text):
        findings.append(Finding("S3_PUBLIC_ACCESS_BLOCK_DISABLED", "HIGH", "S3 public-access protection is disabled", line, _evidence(text, line)))
    return findings


def check_open_ingress(text: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = r"(?:cidr_blocks|cidr_block)\s*=\s*\[?\s*\"0\.0\.0\.0/0\""
    for line, _ in _matches(pattern, text):
        findings.append(Finding("OPEN_INGRESS", "HIGH", "Network ingress is open to the entire IPv4 internet", line, _evidence(text, line)))
    return findings


def check_wildcard_iam(text: str) -> list[Finding]:
    findings: list[Finding] = []
    # Catch common Terraform IAM policy shapes without attempting to parse HCL.
    patterns = [
        r"actions?\s*=\s*\[\s*\"\*\"\s*\]",
        r"resources?\s*=\s*\[\s*\"\*\"\s*\]",
        r'\"Action\"\s*:\s*\"\*\"',
        r'\"Resource\"\s*:\s*\"\*\"',
        r'(?i)\bAction\s*=\s*\"\*\"',
        r'(?i)\bResource\s*=\s*\"\*\"',
    ]
    seen: set[tuple[int, str]] = set()
    for pattern in patterns:
        for line, _ in _matches(pattern, text):
            key = (line, pattern)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding("IAM_WILDCARD", "HIGH", "IAM policy grants a wildcard action or resource", line, _evidence(text, line)))
    return findings


def check_unencrypted_storage(text: str) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        r"encrypted\s*=\s*false",
        r"storage_encrypted\s*=\s*false",
    ]
    for pattern in patterns:
        for line, _ in _matches(pattern, text):
            findings.append(Finding("UNENCRYPTED_STORAGE", "HIGH", "Storage encryption is explicitly disabled", line, _evidence(text, line)))
    return findings


def check_hardcoded_secrets(text: str) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        r"(?i)aws_access_key_id\s*=\s*\"AKIA[0-9A-Z]{16}\"",
        r"(?i)aws_secret_access_key\s*=\s*\"[^\"]{20,}\"",
    ]
    for pattern in patterns:
        for line, _ in _matches(pattern, text):
            findings.append(Finding("HARDCODED_SECRET", "CRITICAL", "A credential-like value appears hardcoded in Terraform", line, _evidence(text, line)))

    # Common demo/development mistake: a sensitive Terraform variable has a
    # literal default instead of being supplied from a secret store/TF_VAR.
    variable_pattern = re.compile(
        r'variable\s+"[^"]*(?:password|passwd|secret|api[_-]?key|token)[^"]*"\s*\{(.*?)\}',
        re.IGNORECASE | re.DOTALL,
    )
    for match in variable_pattern.finditer(text):
        default_match = re.search(r'default\s*=\s*"[^"\n]{8,}"', match.group(1), re.IGNORECASE)
        if default_match:
            line = _line_number(text, match.start() + default_match.start())
            findings.append(Finding("HARDCODED_SECRET", "CRITICAL", "A sensitive Terraform variable has a literal default value", line, _evidence(text, line)))
    return findings


def check_missing_logging(text: str) -> list[Finding]:
    """Flag S3 buckets that do not appear to configure access logging.

    This is deliberately conservative: it only flags a bucket resource when
    the resource block has no logging block at all.
    """
    findings: list[Finding] = []
    resource_pattern = re.compile(r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{', re.IGNORECASE)
    for match in resource_pattern.finditer(text):
        start = match.end()
        depth = 1
        i = start
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        block = text[start : i - 1]
        if not re.search(r"\blogging\s*\{", block, re.IGNORECASE):
            line = _line_number(text, match.start())
            findings.append(Finding("S3_LOGGING_MISSING", "MEDIUM", "S3 bucket has no access-logging configuration", line, _evidence(text, line)))
    return findings


CHECKS: tuple[Callable[[str], list[Finding]], ...] = (
    check_public_s3,
    check_open_ingress,
    check_wildcard_iam,
    check_unencrypted_storage,
    check_hardcoded_secrets,
    check_missing_logging,
)


def run_checks(terraform_text: str) -> list[dict]:
    """Run all checks and return JSON-friendly finding dictionaries."""
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(terraform_text))
    findings.sort(key=lambda item: (item.line, item.severity, item.rule_id))
    return [finding.to_dict() for finding in findings]
