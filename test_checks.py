from pathlib import Path

from checks import run_checks


SAMPLES_DIR = Path(__file__).parent / "samples"


def test_bad_example_detects_expected_findings():
    terraform = (SAMPLES_DIR / "bad_example.tf").read_text(encoding="utf-8")

    findings = run_checks(terraform)

    rule_ids = [finding["rule_id"] for finding in findings]

    assert len(findings) == 12
    assert rule_ids.count("S3_LOGGING_MISSING") == 2
    assert rule_ids.count("S3_PUBLIC_ACL") == 1
    assert rule_ids.count("S3_PUBLIC_ACCESS_BLOCK_DISABLED") == 4
    assert rule_ids.count("OPEN_INGRESS") == 1
    assert rule_ids.count("IAM_WILDCARD") == 2
    assert rule_ids.count("UNENCRYPTED_STORAGE") == 1
    assert rule_ids.count("HARDCODED_SECRET") == 1


def test_good_example_has_no_findings():
    terraform = (SAMPLES_DIR / "good_example.tf").read_text(encoding="utf-8")

    findings = run_checks(terraform)

    assert findings == []


def test_s3_public_access_block_has_target_resource():
    terraform = (SAMPLES_DIR / "bad_example.tf").read_text(encoding="utf-8")

    findings = run_checks(terraform)

    s3_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "S3_PUBLIC_ACCESS_BLOCK_DISABLED"
    ]

    assert len(s3_findings) == 4

    for finding in s3_findings:
        assert finding["resource"] == "aws_s3_bucket_public_access_block.demo"
        assert finding["target_resource"] == "aws_s3_bucket.demo"


def test_findings_include_resource_context():
    terraform = (SAMPLES_DIR / "bad_example.tf").read_text(encoding="utf-8")

    findings = run_checks(terraform)

    iam_findings = [
        finding for finding in findings if finding["rule_id"] == "IAM_WILDCARD"
    ]

    assert len(iam_findings) == 2

    for finding in iam_findings:
        assert finding["resource"] == "aws_iam_policy.admin_like"
        assert finding["resource_type"] == "aws_iam_policy"
        assert finding["resource_name"] == "admin_like"

from main import main


def test_cli_no_ai(capsys, monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(SAMPLES_DIR / "good_example.tf"), "--no-ai"],
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "IaC SECURITY REVIEW" in captured.out
    assert "Static findings: 0" in captured.out
    assert "No static findings detected." in captured.out


def test_cli_missing_file(capsys, monkeypatch):
    missing_file = SAMPLES_DIR / "does_not_exist.tf"

    monkeypatch.setattr(
        "sys.argv",
        ["main.py", str(missing_file), "--no-ai"],
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "file not found" in captured.err

def test_security_findings_have_required_fields():
    terraform = (SAMPLES_DIR / "bad_example.tf").read_text(encoding="utf-8")

    findings = run_checks(terraform)

    required_fields = {
        "rule_id",
        "severity",
        "title",
        "line",
        "evidence",
        "resource",
        "resource_type",
        "resource_name",
        "target_resource",
    }

    for finding in findings:
        assert required_fields.issubset(finding.keys())
        assert finding["rule_id"]
        assert finding["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert finding["line"] > 0
        assert finding["evidence"]


def test_findings_are_sorted_by_line():
    terraform = (SAMPLES_DIR / "bad_example.tf").read_text(encoding="utf-8")

    findings = run_checks(terraform)

    lines = [finding["line"] for finding in findings]

    assert lines == sorted(lines)


def test_expected_severity_levels():
    terraform = (SAMPLES_DIR / "bad_example.tf").read_text(encoding="utf-8")

    findings = run_checks(terraform)

    severities = {
        finding["rule_id"]: finding["severity"]
        for finding in findings
    }

    assert severities["S3_LOGGING_MISSING"] == "MEDIUM"
    assert severities["S3_PUBLIC_ACL"] == "HIGH"
    assert severities["S3_PUBLIC_ACCESS_BLOCK_DISABLED"] == "HIGH"
    assert severities["OPEN_INGRESS"] == "HIGH"
    assert severities["IAM_WILDCARD"] == "HIGH"
    assert severities["UNENCRYPTED_STORAGE"] == "HIGH"
    assert severities["HARDCODED_SECRET"] == "CRITICAL"

def test_separate_s3_bucket_logging_resource_is_recognized():
    terraform = """
resource "aws_s3_bucket" "demo" {
  bucket = "demo-bucket"
}

resource "aws_s3_bucket_logging" "demo" {
  bucket = aws_s3_bucket.demo.id

  target_bucket = "log-bucket"
  target_prefix = "log/"
}
"""

    findings = run_checks(terraform)

    logging_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "S3_LOGGING_MISSING"
    ]

    assert logging_findings == []