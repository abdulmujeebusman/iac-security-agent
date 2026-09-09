# IaC Security Review Agent

An AI-assisted Terraform security reviewer built with the **Strands Agents SDK**.
It combines deterministic static checks with an LLM explanation layer so developers get useful, plain-English pull-request-style feedback instead of a list of rule IDs.

> **Hackathon track:** Professional Agents  
> **Primary audience:** DevOps, platform and cloud engineers reviewing AWS infrastructure as code.

## What it does

Give the agent a Terraform `.tf` file. It:

1. Scans the file with simple, deterministic Python checks.
2. Converts matches into structured findings containing a rule ID, severity, line number, title and evidence.
3. Sends those findings to a **Strands Agents** agent using Claude through Anthropic's API.
4. Turns each finding into a concise security explanation and suggested Terraform-oriented fix.

The LLM is deliberately **not** responsible for detecting the initial problems. That keeps the security checks predictable and makes the project easy to explain and extend.

## Architecture

```text
             Terraform .tf file
                     |
                     v
        +--------------------------+
        |  Static security checks  |
        |   Python + regex/text    |
        +------------+-------------+
                     |
                     v
             Structured findings
                     |
                     v
        +--------------------------+
        |      Strands Agent       |
        |   security-review prompt |
        +------------+-------------+
                     |
                     v
             Claude via Anthropic
                     |
                     v
          Plain-English review
          + suggested remediation
```

Strands Agents is used as the agent framework, while the Anthropic provider lets this project call Claude directly without using Amazon Bedrock.

## Checks included

| Rule | What it looks for | Severity |
|---|---|---|
| `S3_PUBLIC_ACL` | Public S3 ACLs such as `public-read` | High |
| `S3_PUBLIC_ACCESS_BLOCK_DISABLED` | Disabled S3 public-access protection | High |
| `OPEN_INGRESS` | `0.0.0.0/0` network ingress | High |
| `IAM_WILDCARD` | Wildcard IAM actions/resources | High |
| `UNENCRYPTED_STORAGE` | Explicitly disabled EBS/RDS encryption | High |
| `HARDCODED_SECRET` | Credential-like hardcoded values | Critical |
| `S3_LOGGING_MISSING` | S3 bucket without a logging block | Medium |

These are intentionally lightweight checks for a hackathon demo. They are **not** a complete Terraform parser or a replacement for production security scanners.

## Project structure

```text
iac-security-agent/
├── .env                  # local API key; never commit this
├── .gitignore
├── requirements.txt
├── README.md
├── main.py               # CLI entry point
├── checks.py             # deterministic security rules
├── agent.py              # Strands + Anthropic agent
└── samples/
    └── bad_example.tf    # intentionally insecure demo input
```

## Setup

### 1. Create a virtual environment

Python 3.10+ is required.

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Anthropic

Create `.env` in the project root:

```env
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

You can optionally choose another supported Claude model:

```env
ANTHROPIC_MODEL=claude-sonnet-4-6
```

**Never commit `.env` or expose your API key in the public repository.**

## Run the demo

From the project root:

```bash
python main.py samples/bad_example.tf
```

To demonstrate only the deterministic scanner without making an API call:

```bash
python main.py samples/bad_example.tf --no-ai
```

## Example output

The exact Claude wording will vary, but a run will look conceptually like this:

```text
========================================================================
IaC SECURITY REVIEW
========================================================================
File: samples/bad_example.tf
Static findings: 8

Detected issues:
  [HIGH] S3_PUBLIC_ACL - line 6: S3 bucket may be publicly accessible
  [HIGH] S3_PUBLIC_ACCESS_BLOCK_DISABLED - line 11: S3 public-access protection is disabled
  [HIGH] OPEN_INGRESS - line 22: Network ingress is open to the entire IPv4 internet
  [HIGH] IAM_WILDCARD - line 34: IAM policy grants a wildcard action or resource
  [HIGH] IAM_WILDCARD - line 35: IAM policy grants a wildcard action or resource
  [HIGH] UNENCRYPTED_STORAGE - line 42: Storage encryption is explicitly disabled
  [CRITICAL] HARDCODED_SECRET - line 46: A credential-like value appears hardcoded in Terraform
  [MEDIUM] S3_LOGGING_MISSING - line 49: S3 bucket has no access-logging configuration

========================================================================
AI REVIEW COMMENTS
========================================================================
Overall assessment: The file contains several high-impact security issues...

## S3 public access
This bucket can be read publicly...
Suggested fix: remove the public ACL and enable S3 Block Public Access...
```

## Why use an agent here?

A traditional scanner is good at finding known patterns, but its output can be difficult for less experienced engineers to interpret. The agent adds a human-friendly explanation layer:

- **Static checks decide what was detected.**
- **The Strands agent explains what the finding means.**
- **Claude suggests a practical remediation path.**
- **The final output reads like a senior engineer's review comment.**

This separation also makes the system easier to reason about during a live demo: the audience can see exactly where deterministic security logic ends and AI reasoning begins.

## Limitations

This is a hackathon-sized reviewer, not a production IaC security platform. Regex/text checks can produce false positives or miss Terraform constructs that a full HCL parser would understand. It also does not validate the resulting AWS infrastructure or replace tools such as policy scanners and IaC linters.

The goal is to demonstrate a simple, understandable agent architecture that can turn structured security findings into useful engineering feedback.

## Hackathon submission description

**What:** An AI-assisted Infrastructure-as-Code Security Review Agent for Terraform. It detects common AWS security misconfigurations using deterministic static checks, then uses a Strands Agents SDK agent and Claude to explain each finding in plain English and suggest a practical fix.

**Who:** DevOps, platform, cloud and security engineers who review Terraform before infrastructure changes reach AWS.

**How:** Terraform is first scanned by lightweight Python checks for issues such as public S3 access, open network ingress, wildcard IAM permissions, unencrypted storage, hardcoded credentials and missing S3 logging. The structured findings are then passed to a Strands agent, which acts like a senior engineer writing concise pull-request review comments. The project uses the Anthropic provider directly rather than Amazon Bedrock.

## License

MIT
