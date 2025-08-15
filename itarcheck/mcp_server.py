"""ITARCHECK MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from itarcheck.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-itarcheck[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-itarcheck[mcp]'")
        return 1
    app = FastMCP("itarcheck")

    @app.tool()
    def itarcheck_scan(target: str) -> str:
        """Flags potential ITAR/EAR export-controlled terms and USML categories in code, datasheets, and docs.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
