"""ITARCHECK MCP server — exposes scan_path() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import sys

from itarcheck.core import scan_path, summarize


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-itarcheck[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import]
    except ImportError:
        print(
            "Install the MCP extra: pip install 'cognis-itarcheck[mcp]'",
            file=sys.stderr,
        )
        return 1
    app = FastMCP("itarcheck")

    @app.tool()
    def itarcheck_scan(target: str) -> str:
        """Flag potential ITAR/EAR export-controlled terms in a file or directory.

        Returns a JSON object with findings, counts, and a summary string.
        """
        if not target or not target.strip():
            return json.dumps({"error": "target path must not be empty"})
        try:
            result = scan_path(target)
        except FileNotFoundError as exc:
            return json.dumps({"error": str(exc)})
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        except OSError as exc:
            return json.dumps({"error": f"could not access path: {exc}"})
        payload = result.to_dict()
        payload["summary"] = summarize(result)
        return json.dumps(payload)

    app.run()
    return 0
