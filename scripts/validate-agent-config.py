#!/usr/bin/env python3
"""Validate the staged or installed Codex custom-agent configuration."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
STAGING_CONFIG = REPO / "docs/codex/config.toml"
INSTALLED_CONFIG = REPO / ".codex/config.toml"
EXPECTED_ROLES = {
    "security-architect",
    "go-engineer",
    "architecture-reviewer",
    "maintenance-agent",
}
ROOT_AGENT_KEYS = {"enabled", "max_concurrent_threads_per_session"}
ROLE_KEYS = {"description", "config_file"}
LAYER_KEYS = {"model", "model_reasoning_effort", "developer_instructions"}
MODELS = {"gpt-6-astra", "gpt-6.1-sol", "gpt-6-luna"}
EFFORTS = {"low", "medium", "high", "xhigh"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> int:
    config_path = INSTALLED_CONFIG if INSTALLED_CONFIG.is_file() else STAGING_CONFIG
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    agents = config.get("agents")
    require(isinstance(agents, dict), "[agents] table is required")
    require(set(agents) <= ROOT_AGENT_KEYS | EXPECTED_ROLES,
            f"unknown [agents] keys: {sorted(set(agents) - ROOT_AGENT_KEYS - EXPECTED_ROLES)}")
    require(agents.get("enabled") is True, "agents.enabled must be true")
    count = agents.get("max_concurrent_threads_per_session")
    require(type(count) is int and count == 4,
            "agents.max_concurrent_threads_per_session must be integer 4")

    roles = set(agents) - ROOT_AGENT_KEYS
    require(roles == EXPECTED_ROLES,
            f"role set mismatch: expected {sorted(EXPECTED_ROLES)}, got {sorted(roles)}")
    for role_name in sorted(roles):
        role = agents[role_name]
        require(isinstance(role, dict), f"[agents.{role_name}] must be a table")
        require(set(role) == ROLE_KEYS,
                f"[agents.{role_name}] keys must be {sorted(ROLE_KEYS)}")
        require(isinstance(role["description"], str) and role["description"].strip(),
                f"[agents.{role_name}].description must be nonempty text")
        config_file = role["config_file"]
        require(isinstance(config_file, str) and config_file,
                f"[agents.{role_name}].config_file must be a path")
        layer_path = (config_path.parent / config_file).resolve()
        require(layer_path.is_relative_to(config_path.parent.resolve()),
                f"role config escapes config directory: {config_file}")
        require(layer_path.is_file(), f"missing role config: {layer_path}")
        layer = tomllib.loads(layer_path.read_text(encoding="utf-8"))
        require(set(layer) == LAYER_KEYS,
                f"{layer_path} keys must be exactly {sorted(LAYER_KEYS)}")
        require(layer["model"] in MODELS,
                f"{layer_path}: unsupported model {layer['model']!r}")
        require(layer["model_reasoning_effort"] in EFFORTS,
                f"{layer_path}: unsupported reasoning effort {layer['model_reasoning_effort']!r}")
        require(isinstance(layer["developer_instructions"], str)
                and layer["developer_instructions"].strip(),
                f"{layer_path}: developer_instructions must be nonempty text")

    print(f"Valid agent configuration: {config_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        print(f"Invalid agent configuration: {exc}", file=sys.stderr)
        raise SystemExit(1)
