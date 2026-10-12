"""Executable entrypoint for the J-AXON Agent."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from jaxon_agent import PROGRAM_NAME, __version__
from jaxon_agent.identity import IdentityInitializationError, initialize_identity


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested Agent command."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        print(f"{PROGRAM_NAME} {__version__}")
        return 0

    parser = argparse.ArgumentParser(prog="jaxon-agent")
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("initialize", help="Create or inspect local Agent identity")
    initialize.add_argument("--agent-id", required=True)
    initialize.add_argument("--state-dir", required=True)
    parsed = parser.parse_args(arguments)

    try:
        result = initialize_identity(parsed.agent_id, parsed.state_dir)
    except IdentityInitializationError as exception:
        print(str(exception), file=sys.stderr)
        return 2
    print(result.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
