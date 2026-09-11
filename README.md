# IaC Security Review Agent

An AI-assisted Terraform security reviewer built with the **Strands Agents SDK**.

The agent combines deterministic security checks with an AI explanation layer. It detects common Terraform security misconfigurations, then turns the structured findings into concise, pull-request-style feedback with practical remediation guidance.

> **Hackathon:** AWS Agents for Humans 2026
> **Track:** Professional Agents
> **Audience:** DevOps, cloud, platform and security engineers

## What it does

Give the agent a Terraform `.tf` file and it:

1. Scans the configuration using deterministic Python security checks.
2. Produces structured findings with a rule ID, severity, line number, title and evidence.
3. Passes those findings to a **Strands Agent**.
4. Uses an LLM through **OpenRouter** to explain the detected issues.
5. Produces concise, developer-friendly security review comments and remediation guidance.

The AI is **not responsible for detecting vulnerabilities**. The static scanner determines what was found, while the agent explains those findings.

This separation keeps detection predictable, makes the system easier to test, and reduces the risk of the LLM inventing vulnerabilities that were never detected.

## Architecture

```text
                 Terraform .tf file
                         |
                         v
              +----------------------+
              |  Static Security     |
              |  Checks              |
              |  Python + regex/text |
              +----------+-----------+
                         |
                         v
               Structured findings
                         |
                         v
              +----------------------+
              |    Strands Agent     |
              |  Explanation Layer    |
              +----------+-----------+
                         |
                         v
                LLM via OpenRouter
                         |
                         v
             Plain-English review
             + remediation guidance
```

### Design principle

**Detection and explanation are separate.**

The deterministic scanner decides what security issues exist in the supplied findings. The Strands agent does not perform another security scan. It explains only the findings it receives.

## Security checks

| Rule                              | What it detects                                     | Severity |
| --------------------------------- | --------------------------------------------------- | -------- |
| `S3_PUBLIC_ACL`                   | Public S3 ACLs such as `public-read`                | High     |
| `S3_PUBLIC_ACCESS_BLOCK_DISABLED` | Disabled S3 public-access protection                | High     |
| `OPEN_INGRESS`                    | IPv4 ingress open to `0.0.0.0/0`                    | High     |
| `IAM_WILDCARD`                    | Wildcard IAM actions or resources                   | High     |
| `UNENCRYPTED_STORAGE`             | Explicitly disabled EBS/RDS encryption              | High     |
| `HARDCODED_SECRET`                | Sensitive Terraform variables with literal defaults | Critical |
| `S3_LOGGING_MISSING`              | S3 buckets without access logging                   | Medium   |

The checks are intentionally lightweight and focused on demonstrating the agent architecture. This project is **not a complete Terraform parser or a replacement for production IaC security tooling**.

## Project structure

```text
iac-security-agent/
├── .gitignore
├── README.md
├── requirements.txt
├── main.py                  # CLI entry point
├── checks.py                # deterministic security rules
├── agent.py                 # Strands agent + LLM integration
├── test_checks.py            # automated tests
└── samples/
    ├── bad_example.tf        # intentionally insecure example
    └── good_example.tf       # secure example
```

## Requirements

* Python 3.10+
* An OpenRouter API key for AI-powered reviews

The static scanner can be used without an API key.

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/abdulmujeebusman/iac-security-agent.git
cd iac-security-agent
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure OpenRouter

Create a `.env` file in the project root:

```env
OPENROUTER_API_KEY=your_openrouter_api_key_here
OPENROUTER_MODEL=google/gemma-4-31b-it:free
```

The model can be changed to another compatible OpenRouter model.

**Never commit `.env` or expose your API key.**

## Run the reviewer

### AI-powered review

```bash
python main.py samples/bad_example.tf
```

The static findings are generated first, then passed to the Strands Agent for explanation.

### Static-only review

```bash
python main.py samples/bad_example.tf --no-ai
```

This runs the deterministic checks without making an API request.

### Review a clean configuration

```bash
python main.py samples/good_example.tf --no-ai
```

The included secure example should produce:

```text
Static findings: 0

No static findings detected.
```

### Example insecure configuration

The included vulnerable example currently produces findings across several categories, including:

```text
[MEDIUM] S3_LOGGING_MISSING
[HIGH] S3_PUBLIC_ACL
[HIGH] S3_PUBLIC_ACCESS_BLOCK_DISABLED
[HIGH] OPEN_INGRESS
[HIGH] IAM_WILDCARD
[HIGH] UNENCRYPTED_STORAGE
[CRITICAL] HARDCODED_SECRET
```

Multiple findings can be generated for a single configuration when different insecure settings are detected.

## Testing

Run the automated test suite:

```bash
python -m pytest -q
```

The current test suite covers the security rules, finding structure, resource context, severity levels, ordering, CLI behavior and separate S3 logging resources.

## Why use an agent?

A traditional scanner can identify a misconfiguration, but the raw result may not tell a developer what the finding means or what should be changed.

This project adds an explanation layer:

* **Static checks detect the configured condition.**
* **Structured findings provide the evidence and context.**
* **The Strands Agent explains the finding.**
* **The LLM provides concise remediation guidance.**
* **The final output resembles a useful pull-request security review.**

The agent is deliberately grounded in the scanner's findings rather than being asked to independently scan the entire Terraform file. This makes the boundary between deterministic security logic and AI reasoning clear during development and demonstration.

## Limitations

This is a hackathon-sized security reviewer, not a production IaC security platform.

The current checks use lightweight text and regular-expression matching, so they may produce false positives or miss Terraform constructs that a full HCL parser would understand.

The project also does not:

* Validate deployed AWS infrastructure
* Perform a complete Terraform semantic analysis
* Replace dedicated IaC security scanners
* Guarantee that a Terraform configuration is secure

The goal is to demonstrate a practical agent architecture that combines **deterministic security detection with useful AI-assisted developer feedback**.

## Hackathon submission

### What

An AI-assisted Infrastructure-as-Code Security Review Agent for Terraform. It detects common AWS infrastructure security misconfigurations using deterministic static checks, then uses a Strands Agents SDK agent to turn those findings into concise, human-readable security review comments.

### Who

DevOps, cloud, platform and security engineers who review Terraform configurations before infrastructure changes are deployed.

### How

A Terraform file is first analyzed by lightweight Python checks for issues such as public S3 access, open network ingress, wildcard IAM permissions, unencrypted storage, hardcoded sensitive values and missing S3 logging.

The resulting findings are passed to a Strands Agent through an LLM endpoint. The agent is restricted to explaining the supplied findings rather than performing a second vulnerability scan. It produces developer-friendly explanations and practical remediation guidance.

## License

MIT
