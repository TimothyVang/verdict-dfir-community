#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
exec uv run --directory services/agent_mcp python -m findevil_agent_mcp.server
