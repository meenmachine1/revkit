"""The ``revkit-mcp`` command: the MCP server (``revkit.mcp_server``), or
``revkit-mcp setup``, which registers it with coding agents
(``revkit.mcp_setup``) and needs no ``mcp`` package."""

from __future__ import annotations

import sys
from typing import Optional


def main(argv: Optional[list[str]] = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["setup"]:
        from revkit import mcp_setup

        sys.exit(mcp_setup.main(args[1:]))
    try:
        from revkit import mcp_server
    except ModuleNotFoundError as e:
        if e.name and e.name.split(".")[0] in ("mcp", "mcp_types"):
            sys.exit("revkit-mcp: the MCP server needs the mcp package: pip install 'revkit[mcp]'")
        raise
    mcp_server.main(args)


if __name__ == "__main__":
    main()
