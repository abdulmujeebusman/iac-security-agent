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
    resource: str | None = None
    resource_type: str | None = None
    resource_name: str | None = None
    target_resource: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _evidence(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1].strip()[:180] if 0 < line <= len(lines) else ""

def _resource_context(
    text: str, line: int
) -> tuple[str | None, str | None, str | None]:
    """Return the Terraform block containing a line."""
    lines = text.splitlines()

    if not 0 < line <= len(lines):
        return None, None, None

    target_index = line - 1
    block_pattern = re.compile(
        r'^\s*(resource|variable)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{',
        re.IGNORECASE,
    )

    candidates: list[tuple[int, int, str, str | None, str]] = []

    for index, source_line in enumerate(lines):
        match = block_pattern.match(source_line)
        if not match:
            continue

        depth = 0
        end_index = index

        for current in range(index, len(lines)):
            depth += lines[current].count("{")
            depth -= lines[current].count("}")

            if depth == 0:
                end_index = current
                break

        if index <= target_index <= end_index:
            kind = match.group(1).lower()
            first_name = match.group(2)
            second_name = match.group(3)

            if kind == "resource" and second_name:
                resource = f"{first_name}.{second_name}"
                resource_type = first_name
                resource_name = second_name
            else:
                resource = f"{kind}.{first_name}"
                resource_type = kind
                resource_name = first_name

            candidates.append(
                (index, end_index, resource, resource_type, resource_name)
            )

    if not candidates:
        return None, None, None

    # Use the smallest containing block.
    candidates.sort(key=lambda item: item[1] - item[0])

    _, _, resource, resource_type, resource_name = candidates[0]
    return resource, resource_type, resource_name


def _matches(pattern: str, text: str, flags: int = re.IGNORECASE) -> list[tuple[int, str]]:
    return [(_line_number(text, m.start()), m.group(0)) for m in re.finditer(pattern, text, flags)]


def check_public_s3(text: str) -> list[Finding]:
    findings: list[Finding] = []

    pattern = r"(?:acl\s*=\s*\"public-(?:read|read-write)\"|acl\s*=\s*\"authenticated-read\")"
    for line, _ in _matches(pattern, text):
        findings.append(
            Finding(
                "S3_PUBLIC_ACL",
                "HIGH",
                "S3 bucket may be publicly accessible",
                line,
                _evidence(text, line),
            )
        )

    # Explicitly disabled public-access-block settings are also risky.
    pattern = (
        r"(?:block_public_acls|block_public_policy|ignore_public_acls|"
        r"restrict_public_buckets)\s*=\s*false"
    )
    for line, _ in _matches(pattern, text):
        findings.append(
            Finding(
                "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
                "HIGH",
                "S3 public-access protection is disabled",
                line,
                _evidence(text, line),
            )
        )

    # Link aws_s3_bucket_public_access_block resources to the bucket they control.
    resource_pattern = re.compile(
        r'resource\s+"aws_s3_bucket_public_access_block"\s+"([^"]+)"\s*\{'
        r"(.*?)"
        r"\}",
        re.IGNORECASE | re.DOTALL,
    )

    for match in resource_pattern.finditer(text):
        block = match.group(2)
        bucket_match = re.search(
            r"bucket\s*=\s*aws_s3_bucket\.([A-Za-z0-9_-]+)\.id",
            block,
            re.IGNORECASE,
        )

        if not bucket_match:
            continue

        target_resource = f"aws_s3_bucket.{bucket_match.group(1)}"

        start_line = _line_number(text, match.start())
        end_line = _line_number(text, match.end())

        for finding in findings:
            if (
                finding.rule_id == "S3_PUBLIC_ACCESS_BLOCK_DISABLED"
                and start_line <= finding.line <= end_line
            ):
                finding.target_resource = target_resource

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
    findings: list[Finding] = []

    bucket_pattern = re.compile(
        r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*\{',
        re.IGNORECASE,
    )

    # Buckets that have logging configured either inline or
    # through a separate aws_s3_bucket_logging resource.
    configured_buckets: set[str] = set()

    # Detect inline logging blocks.
    for match in bucket_pattern.finditer(text):
        bucket_name = match.group(1)

        depth = 1
        i = match.end()

        while i < len(text) and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1

        block = text[match.end() : i - 1]

        if re.search(r"\blogging\s*\{", block, re.IGNORECASE):
            configured_buckets.add(bucket_name)

    # Detect separate aws_s3_bucket_logging resources.
    logging_pattern = re.compile(
        r'resource\s+"aws_s3_bucket_logging"\s+"[^"]+"\s*\{'
        r"(.*?)"
        r"\}",
        re.IGNORECASE | re.DOTALL,
    )

    for match in logging_pattern.finditer(text):
        block = match.group(1)

        bucket_match = re.search(
            r"bucket\s*=\s*aws_s3_bucket\.([A-Za-z0-9_-]+)\.id",
            block,
            re.IGNORECASE,
        )

        if bucket_match:
            configured_buckets.add(bucket_match.group(1))

    # Report buckets that have neither inline logging nor
    # a separate aws_s3_bucket_logging resource.
    for match in bucket_pattern.finditer(text):
        bucket_name = match.group(1)

        if bucket_name in configured_buckets:
            continue

        line = _line_number(text, match.start())

        findings.append(
            Finding(
                "S3_LOGGING_MISSING",
                "MEDIUM",
                "S3 bucket has no access-logging configuration",
                line,
                _evidence(text, line),
            )
        )

    return findings
    for match in logging_pattern.finditer(text):
        block = match.group(2)

        bucket_match = re.search(
            r"bucket\s*=\s*aws_s3_bucket\.([A-Za-z0-9_-]+)\.id",
            block,
            re.IGNORECASE,
        )

        if bucket_match:
            configured_buckets.add(bucket_match.group(1))

    # Remove false positives for buckets configured through
    # a separate aws_s3_bucket_logging resource.
    filtered: list[Finding] = []

    for finding in findings:
        resource_name = finding.resource_name

        # resource_name is populated later by run_checks(), so extract
        # the bucket name directly from the finding evidence/resource line.
        if resource_name in configured_buckets:
            continue

        filtered.append(finding)

    return filtered

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

    for finding in findings:
        (
            finding.resource,
            finding.resource_type,
            finding.resource_name,
        ) = _resource_context(terraform_text, finding.line)

    return [finding.to_dict() for finding in findings]
