"""Strands Agents layer for explaining static Terraform security findings."""

from __future__ import annotations

import json
import os

from strands import Agent
from strands.models.anthropic import AnthropicModel

SYSTEM_PROMPT = """
You are an experienced cloud security and DevOps engineer reviewing Terraform.
You receive findings produced by deterministic static checks. Do not invent
additional findings and do not claim that the checks prove a vulnerability.

For every finding:
1. Explain the security risk in plain English for a developer.
2. Explain why it matters in an AWS environment.
3. Suggest a concise Terraform-oriented fix.
4. Mention when a finding may be intentional or needs context.

Write like a senior engineer leaving useful pull-request review comments.
Prioritize clarity over jargon. Keep the response concise enough for a CLI
report. Start with a short overall assessment, then use one section per finding.
""".strip()


def build_agent() -> Agent:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set. Put it in your .env file or environment.")

    model = AnthropicModel(
        client_args={"api_key": api_key},
        model_id=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
        max_tokens=1800,
        params={"temperature": 0.2},
    )
    return Agent(model=model, system_prompt=SYSTEM_PROMPT)


def explain_findings(findings: list[dict], terraform_path: str) -> str:
    if not findings:
        return "No static security findings were detected. This does not prove the Terraform is secure."

    agent = build_agent()
    payload = json.dumps(findings, indent=2)
    prompt = (
        f"Review the static security findings for Terraform file `{terraform_path}`.\n\n"
        f"Findings:\n```json\n{payload}\n```\n\n"
        "Produce a concise human-readable security review."
    )
    response = agent(prompt)
    return str(response)
