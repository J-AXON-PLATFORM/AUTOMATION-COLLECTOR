"""Executable entrypoint for the J-AXON Discovery Executor."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from jaxon_discovery_executor import PROGRAM_NAME, __version__
from jaxon_discovery_executor.identity import (
    ExecutorIdentityInitializationError,
    initialize_identity,
)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested Discovery Executor command."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        print(f"{PROGRAM_NAME} {__version__}")
        return 0

    parser = argparse.ArgumentParser(prog="jaxon-discovery-executor")
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser(
        "initialize", help="Create or inspect local Discovery Executor identity"
    )
    initialize.add_argument("--executor-id", required=True)
    initialize.add_argument("--state-dir", required=True)
    parsed = parser.parse_args(arguments)

    try:
        result = initialize_identity(parsed.executor_id, parsed.state_dir)
    except ExecutorIdentityInitializationError as exception:
        print(str(exception), file=sys.stderr)
        return 2
    print(result.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
