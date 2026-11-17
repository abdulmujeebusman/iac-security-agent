"""Simple, explainable security checks for Terraform source files.

These checks intentionally use lightweight regex/text matching. They are not a
replacement for a full Terraform parser or a production security scanner.

Hardening notes:
- Comments are blanked out (positions preserved) before most checks run, so a
  commented-out ``acl = "public-read"`` is not reported and comment text never
  ends up in finding evidence.
- Secret checks run on the *original* text, because a credential committed in a
  comment is still a leaked credential. Their evidence is always redacted so the
  secret is never printed to logs or sent to the LLM.
- Block boundaries are found with brace matching instead of non-greedy regexes,
  so nested blocks (``validation {}``, ``versioning {}``) don't truncate a body.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Callable

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

MAX_EVIDENCE_CHARS = 180
REDACTED = "<redacted>"


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


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

_HEREDOC_START = re.compile(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n")


def strip_comments(text: str) -> str:
    """Blank out HCL comments (``#``, ``//``, ``/* */``) preserving positions.

    Every removed character is replaced by a space (newlines are kept), so line
    numbers and character offsets in the result match the original text.
    Comment markers inside quoted strings and heredocs are left alone.
    """
    out = list(text)
    i, n = 0, len(text)

    def blank(start: int, end: int) -> None:
        for k in range(start, end):
            if out[k] not in "\r\n":
                out[k] = " "

    while i < n:
        ch = text[i]

        if ch == '"':
            i += 1
            while i < n and text[i] != '"' and text[i] != "\n":
                i += 2 if text[i] == "\\" else 1
            i += 1
            continue

        if ch == "<" and text.startswith("<<", i):
            heredoc = _HEREDOC_START.match(text, i)
            if heredoc:
                marker = heredoc.group(1)
                end = re.compile(rf"^[ \t]*{re.escape(marker)}[ \t]*$", re.MULTILINE)
                closing = end.search(text, heredoc.end())
                i = closing.end() if closing else n
                continue

        if ch == "#" or text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end == -1 else end
            blank(i, end)
            i = end
            continue

        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            blank(i, end)
            i = end
            continue

        i += 1

    return "".join(out)


def _line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _clean(value: str) -> str:
    """Remove control characters so evidence can't smuggle terminal escapes."""
    return "".join(c if c.isprintable() else " " for c in value)


def _evidence(text: str, line: int) -> str:
    lines = text.splitlines()
    if not 0 < line <= len(lines):
        return ""
    return _clean(lines[line - 1].strip())[:MAX_EVIDENCE_CHARS]


def _redacted_evidence(text: str, line: int) -> str:
    lines = text.splitlines()
    if not 0 < line <= len(lines):
        return ""
    value = lines[line - 1].strip()
    value = re.sub(r'"[^"]*"', f'"{REDACTED}"', value)
    value = re.sub(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", REDACTED, value)
    if re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", value):
        value = f"-----BEGIN PRIVATE KEY----- {REDACTED}"
    return _clean(value)[:MAX_EVIDENCE_CHARS]


def _block_end(text: str, open_brace: int) -> int:
    """Return the index just past the ``}`` matching ``text[open_brace]``."""
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def _enclosing_blocks(text: str, position: int) -> list[tuple[str, int]]:
    """Return ``(header, open_brace_index)`` for each block around ``position``.

    Ordered innermost first. ``header`` is the text on the line before ``{``,
    e.g. ``ingress`` or ``resource "aws_security_group" "web"``.
    """
    blocks: list[tuple[str, int]] = []
    depth = 0
    for i in range(position - 1, -1, -1):
        ch = text[i]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth == 0:
                line_start = text.rfind("\n", 0, i) + 1
                blocks.append((text[line_start:i].strip(), i))
            else:
                depth -= 1
    return blocks


def _resource_header(header: str) -> tuple[str, str] | None:
    match = re.match(r'resource\s+"([^"]+)"\s+"([^"]+)"', header)
    return (match.group(1), match.group(2)) if match else None


def _iter_blocks(text: str, kind: str, type_pattern: str = r"[^\"]+"):
    """Yield ``(match, body)`` for ``kind "type" ["name"] { ... }`` blocks."""
    pattern = re.compile(
        rf'^[ \t]*{kind}\s+"({type_pattern})"(?:\s+"([^"]+)")?\s*\{{',
        re.IGNORECASE | re.MULTILINE,
    )
    for match in pattern.finditer(text):
        open_brace = match.end() - 1
        yield match, text[open_brace + 1 : _block_end(text, open_brace) - 1]


def _resource_context(
    text: str, line: int
) -> tuple[str | None, str | None, str | None]:
    """Return the innermost ``resource``/``variable`` block containing a line."""
    lines = text.splitlines(keepends=True)
    if not 0 < line <= len(lines):
        return None, None, None

    position = sum(len(item) for item in lines[: line - 1])
    # Look from the end of the line so attributes on the header line count too.
    position += len(lines[line - 1].rstrip("\r\n"))

    for header, _ in _enclosing_blocks(text, position):
        match = re.match(r'(resource|data|variable)\s+"([^"]+)"(?:\s+"([^"]+)")?', header)
        if not match:
            continue
        kind, first, second = match.group(1).lower(), match.group(2), match.group(3)
        if kind in {"resource", "data"} and second:
            prefix = "data." if kind == "data" else ""
            return f"{prefix}{first}.{second}", first, second
        return f"{kind}.{first}", kind, first

    return None, None, None


def _matches(pattern: str, text: str, flags: int = re.IGNORECASE) -> list[tuple[int, str]]:
    return [(_line_number(text, m.start()), m.group(0)) for m in re.finditer(pattern, text, flags)]


_BUCKET_REF = re.compile(
    r"\bbucket\s*=\s*aws_s3_bucket\.([A-Za-z0-9_-]+)\.(?:id|bucket)\b", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_public_s3(text: str) -> list[Finding]:
    findings: list[Finding] = []

    patterns = [
        r"\bacl\s*=\s*\"(?:public-read|public-read-write|authenticated-read)\"",
        # Grants to the AllUsers / AuthenticatedUsers groups are public ACLs too.
        r"acs\.amazonaws\.com/groups/global/(?:AllUsers|AuthenticatedUsers)",
    ]
    for pattern in patterns:
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
        r"\b(?:block_public_acls|block_public_policy|ignore_public_acls|"
        r"restrict_public_buckets)\s*=\s*false\b"
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
    for match, body in _iter_blocks(text, "resource", "aws_s3_bucket_public_access_block"):
        bucket_match = _BUCKET_REF.search(body)
        if not bucket_match:
            continue

        target_resource = f"aws_s3_bucket.{bucket_match.group(1)}"
        start_line = _line_number(text, match.start())
        end_line = start_line + body.count("\n") + 1

        for finding in findings:
            if (
                finding.rule_id == "S3_PUBLIC_ACCESS_BLOCK_DISABLED"
                and start_line <= finding.line <= end_line
            ):
                finding.target_resource = target_resource

    return findings


_OPEN_CIDR = re.compile(r'"(0\.0\.0\.0/0|::/0)"')
_CIDR_ATTRIBUTE = re.compile(
    r"\b(cidr_blocks|ipv6_cidr_blocks|cidr_block|ipv6_cidr_block|cidr_ipv4|cidr_ipv6)"
    r"\s*=\s*(\[[^\]]*\]|\"[^\"\n]*\")",
    re.IGNORECASE,
)


def _is_ingress(text: str, position: int) -> bool:
    """Decide whether a CIDR attribute at ``position`` controls inbound traffic."""
    blocks = _enclosing_blocks(text, position)
    if not blocks:
        return False

    inner_header, open_brace = blocks[0]
    inner_word = inner_header.split()[0].lower() if inner_header.split() else ""

    # dynamic "ingress" { content { cidr_blocks = ... } }
    if inner_word == "content" and len(blocks) > 1:
        dynamic = re.match(r'dynamic\s+"([^"]+)"', blocks[1][0])
        if dynamic:
            inner_word = dynamic.group(1).lower()

    if inner_word == "ingress":
        return True
    if inner_word in {"egress", "route"}:
        return False

    resource = _resource_header(inner_header)
    if not resource:
        return False

    resource_type, _ = resource
    body = text[open_brace : _block_end(text, open_brace)]

    if resource_type == "aws_vpc_security_group_ingress_rule":
        return True
    if resource_type == "aws_security_group_rule":
        return bool(re.search(r'\btype\s*=\s*"ingress"', body, re.IGNORECASE))
    if resource_type == "aws_network_acl_rule":
        egress = re.search(r"\begress\s*=\s*(true|false)", body, re.IGNORECASE)
        return not (egress and egress.group(1).lower() == "true")
    return False


def check_open_ingress(text: str) -> list[Finding]:
    findings: list[Finding] = []

    for match in _CIDR_ATTRIBUTE.finditer(text):
        open_cidr = _OPEN_CIDR.search(match.group(2))
        if not open_cidr or not _is_ingress(text, match.start()):
            continue

        line = _line_number(text, match.start(2) + open_cidr.start())
        if open_cidr.group(1) == "::/0":
            title = "Network ingress is open to the entire IPv6 internet"
        else:
            title = "Network ingress is open to the entire IPv4 internet"
        findings.append(Finding("OPEN_INGRESS", "HIGH", title, line, _evidence(text, line)))

    return findings


_IAM_ATTRIBUTE = re.compile(
    r'"?\b(actions?|resources?)"?\s*[=:]\s*(\[[^\]]*\]|"[^"\n]*")',
    re.IGNORECASE,
)
_IAM_WILDCARD_VALUE = re.compile(r'"\*(?::\*)?"')


def check_wildcard_iam(text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[int] = set()

    # Catches `Action = "*"`, `"Action": "*"`, `actions = ["s3:GetObject", "*"]`.
    for match in _IAM_ATTRIBUTE.finditer(text):
        wildcard = _IAM_WILDCARD_VALUE.search(match.group(2))
        if not wildcard:
            continue
        line = _line_number(text, match.start(2) + wildcard.start())
        if line in seen:
            continue
        seen.add(line)
        findings.append(
            Finding(
                "IAM_WILDCARD",
                "HIGH",
                "IAM policy grants a wildcard action or resource",
                line,
                _evidence(text, line),
            )
        )
    return findings


def check_unencrypted_storage(text: str) -> list[Finding]:
    findings: list[Finding] = []
    # `\b` stops `encrypted` from also matching inside `storage_encrypted`.
    for line, _ in _matches(r"\b(?:storage_)?encrypted\s*=\s*false\b", text):
        findings.append(
            Finding(
                "UNENCRYPTED_STORAGE",
                "HIGH",
                "Storage encryption is explicitly disabled",
                line,
                _evidence(text, line),
            )
        )
    return findings


_SENSITIVE_NAME = r"(?:password|passwd|secret|api[_-]?key|token|private[_-]?key|access[_-]?key|secret[_-]?key)"
_LITERAL_SECRET = re.compile(
    rf'\b[A-Za-z0-9_]*{_SENSITIVE_NAME}\s*=\s*"([^"\n]*)"',
    re.IGNORECASE,
)


def _looks_literal(value: str, min_length: int = 8) -> bool:
    """True for a hard-coded value; False for interpolations or short/empty values."""
    return len(value) >= min_length and "${" not in value


def check_hardcoded_secrets(text: str) -> list[Finding]:
    """Detect credentials. Runs on the original text; evidence is redacted."""
    findings: list[Finding] = []
    seen: set[int] = set()

    def add(line: int, title: str) -> None:
        if line in seen:
            return
        seen.add(line)
        findings.append(
            Finding("HARDCODED_SECRET", "CRITICAL", title, line, _redacted_evidence(text, line))
        )

    for line, _ in _matches(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", text, 0):
        add(line, "An AWS access key ID appears hardcoded in Terraform")

    for line, _ in _matches(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", text, 0):
        add(line, "A private key appears hardcoded in Terraform")

    for match in _LITERAL_SECRET.finditer(text):
        if _looks_literal(match.group(1)):
            add(
                _line_number(text, match.start()),
                "A credential-like value appears hardcoded in Terraform",
            )

    # A sensitive variable (by name or `sensitive = true`) with a literal
    # default instead of being supplied from a secret store / TF_VAR_*.
    for match, body in _iter_blocks(text, "variable"):
        name_is_sensitive = re.search(_SENSITIVE_NAME, match.group(1), re.IGNORECASE)
        marked_sensitive = re.search(r"\bsensitive\s*=\s*true\b", body, re.IGNORECASE)
        if not (name_is_sensitive or marked_sensitive):
            continue

        default = re.search(r'\bdefault\s*=\s*"([^"\n]*)"', body, re.IGNORECASE)
        if default and _looks_literal(default.group(1), 1 if marked_sensitive else 8):
            body_start = match.end()
            add(
                _line_number(text, body_start + default.start()),
                "A sensitive Terraform variable has a literal default value",
            )

    return findings


def check_missing_logging(text: str) -> list[Finding]:
    findings: list[Finding] = []

    # Buckets with logging configured inline or via aws_s3_bucket_logging.
    configured_buckets: set[str] = set()

    for _, body in _iter_blocks(text, "resource", "aws_s3_bucket_logging"):
        bucket_match = _BUCKET_REF.search(body)
        if bucket_match:
            configured_buckets.add(bucket_match.group(1))

    for match, body in _iter_blocks(text, "resource", "aws_s3_bucket"):
        bucket_name = match.group(2)
        if not bucket_name:
            continue
        if bucket_name in configured_buckets or re.search(r"\blogging\s*\{", body, re.IGNORECASE):
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


# Checks that run on comment-stripped text.
CHECKS: tuple[Callable[[str], list[Finding]], ...] = (
    check_public_s3,
    check_open_ingress,
    check_wildcard_iam,
    check_unencrypted_storage,
    check_missing_logging,
)

# Checks that must also see comments (a secret in a comment is still leaked).
RAW_CHECKS: tuple[Callable[[str], list[Finding]], ...] = (
    check_hardcoded_secrets,
)


def run_checks(terraform_text: str) -> list[dict]:
    """Run all checks and return JSON-friendly finding dictionaries."""
    stripped = strip_comments(terraform_text)
    findings: list[Finding] = []

    for check in CHECKS:
        findings.extend(check(stripped))
    for check in RAW_CHECKS:
        findings.extend(check(terraform_text))

    findings.sort(
        key=lambda item: (item.line, SEVERITY_RANK.get(item.severity, 99), item.rule_id)
    )

    for finding in findings:
        (
            finding.resource,
            finding.resource_type,
            finding.resource_name,
        ) = _resource_context(stripped, finding.line)

    return [finding.to_dict() for finding in findings]
