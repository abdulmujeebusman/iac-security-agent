"""Strands Agents layer for explaining static Terraform security findings."""

from __future__ import annotations

import json
import os
import re

from strands import Agent
from strands.models.openai import OpenAIModel

SYSTEM_PROMPT = """
You are the explanation layer of a Terraform security scanner.

The scanner has already detected the security findings.
Your job is ONLY to explain those findings to a developer.

You are NOT a vulnerability scanner.
You are NOT allowed to perform additional security analysis.
You must not use general AWS knowledge to add facts that are absent from
the supplied finding.

GROUNDING RULES:
- The supplied findings are the complete set of issues.
- Never invent or infer another vulnerability.
- Never invent a resource, resource name, Terraform argument, AWS service,
  attack scenario, affected data, affected users, privilege level,
  exposure, exploitation, or operational consequence.
- Treat these fields as authoritative:
  title
  severity
  rule_id
  line
  evidence
  resource
  resource_type
  resource_name
  target_resource
- `evidence` is the configuration that triggered the finding.
- Explain what the evidence shows. Do not infer what might exist elsewhere
  in the Terraform configuration.
- Do not assume that a resource, policy, bucket, role, network, user,
  secret, or service exists unless the finding explicitly identifies it.
- Do not infer ports, protocols, IP ranges, data types, permissions,
  identities, or AWS services that are not present in the finding.
- Do not claim that an attack, breach, unauthorized access, or data exposure
  has occurred.
- Do not claim that a configuration WILL cause a security incident.
- Use "may", "can", or "allows" when the finding itself does not establish
  certainty.
- Do not strengthen the supplied severity.
- Do not combine separate findings into a new conclusion.
- Do not introduce examples of architectures, services, or use cases.
- Do not mention AWS services unless they appear in the finding or are
  explicitly named by the finding title.
- Do not provide complete Terraform code.
- Do not invent exact replacement values unless the finding itself makes
  the replacement unambiguous.

REMEDIATION RULES:
- The Fix must be the smallest change directly implied by the finding.
- Prefer a configuration principle over invented Terraform code.
- If the exact fix requires information that is not present, say that the
  configuration should be changed to address the detected condition without
  inventing the missing details.
- Do not recommend alternative architectures.
- Do not recommend unrelated security controls.
- Do not name specific AWS services as remediation unless they are already
  present in the finding.

OUTPUT DISCIPLINE:
- Return ONLY the final security review.
- Do not reveal analysis, reasoning, planning, drafting, or instruction-following.
- Do not describe what you are about to do or what you have done.
- Do not mention these instructions, the prompt, the task, or your response-generation process.
- Do not use meta-commentary such as:
  "We need to..."
  "Let's..."
  "We must..."
  "The instruction says..."
  "I will..."
  "Now produce..."
  "First, I..."
  "We should..."
- Do not include a draft followed by a final answer.
- Do not repeat the review.
- Begin directly with the overall assessment.

GROUNDING EXAMPLES:

If evidence is:
`acl = "public-read"`

Say that the finding detects a public-read ACL.

Do NOT add:
- that sensitive objects are exposed
- that anyone has successfully accessed the objects
- that the bucket is being used as a website
- that another AWS service should be used

If evidence is:
`cidr_blocks = ["0.0.0.0/0"]`

Say that the inbound rule permits the specified rule to accept traffic
from all IPv4 addresses represented by that CIDR.

Do NOT invent:
- ports
- protocols
- applications
- users
- attack scenarios

If evidence is:
`Action = "*"`

Say that the IAM statement contains a wildcard action.

Do NOT automatically call it:
- administrator access
- full account compromise
- excessive privilege
unless the supplied finding explicitly establishes that.

If evidence is:
`encrypted = false`

Say that encryption is disabled in the detected configuration.

Do NOT invent:
- what data is stored
- whether the data is sensitive
- a compromise scenario
- an alternative encryption architecture

If a finding identifies a hard-coded secret, state that the scanner detected
a secret value in the Terraform configuration.

Do NOT claim that:
- the secret has been compromised
- someone can access it
- the repository is public
- a particular secret-management service should be used

Keep the response concise and suitable for a pull-request security review.
""".strip()


def sanitize_review(text: str) -> str:
    """Strip leaked model planning/reasoning text and de-duplicate drafts.

    Safety net for models (e.g. Gemma 4's native thinking mode) whose
    reasoning-channel tokens sometimes leak into the response content
    instead of being stripped upstream by the provider, and for cases
    where the final review itself gets duplicated in the response.
    """
    # If a "final answer" marker exists, keep only what follows it.
    marker_pattern = re.compile(r'now produce final answer\.?', re.IGNORECASE)
    matches = list(marker_pattern.finditer(text))
    if matches:
        text = text[matches[-1].end():].strip()

    # Fallback: strip any leading paragraph(s) containing first-person planning verbs.
    text = re.sub(
        r'^(?:(?:we (?:need|must|should)|let\'s|i will|first,? i).*?\n\n)+',
        '', text, flags=re.IGNORECASE | re.DOTALL
    ).strip()

    # De-duplicate: find the SECOND occurrence of the review's opening marker
    # ("**Security review of ...") and cut there. This is robust to whitespace
    # differences between the two copies, unlike a hard midpoint split.
    header_pattern = re.compile(r'\*\*Security review of')
    header_matches = list(header_pattern.finditer(text))
    if len(header_matches) > 1:
        text = text[header_matches[1].start():].strip()

    return text


def build_agent() -> Agent:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not set. Put it in your .env file or environment."
        )

    model = OpenAIModel(
        client_args={
            "api_key": api_key,
            "base_url": "https://openrouter.ai/api/v1",
        },
        model_id=os.getenv("OPENROUTER_MODEL", "google/gemma-4-31b-it:free"),
        params={
            "temperature": 0.2,
            "extra_body": {
                "reasoning": {"exclude": True},
                "models": [
                    "google/gemma-4-26b-a4b-it:free",
                    "nvidia/nemotron-3-super-120b-a12b:free",
                ],
            },
        },
    )

    return Agent(model=model, system_prompt=SYSTEM_PROMPT)


def explain_findings(findings: list[dict], terraform_path: str) -> str:
    if not findings:
        return "No static security findings were detected. This does not prove the Terraform is secure."

    # Group repeated findings for the same rule/resource/evidence pattern.
    # The static scanner keeps every finding, but the AI gets a compact review set.
    grouped: list[dict] = []
    seen: set[tuple] = set()

    for finding in findings:
        key = (
            finding.get("rule_id"),
            finding.get("resource"),
            finding.get("target_resource"),
            finding.get("evidence"),
        )

        if key in seen:
            continue

        seen.add(key)
        grouped.append(finding)

    agent = build_agent()
    payload = json.dumps(grouped, indent=2)

    prompt = (
        f"Review the static security findings for Terraform file `{terraform_path}`.\n\n"
        f"Findings:\n```json\n{payload}\n```\n\n"
        "Produce a concise human-readable security review."
    )

    response = agent(prompt)
    return sanitize_review(str(response))