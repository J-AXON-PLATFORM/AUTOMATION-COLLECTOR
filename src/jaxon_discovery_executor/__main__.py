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
from jaxon_discovery_executor.sftp import (
    ExecutorSftpConfigurationError,
    ExecutorSftpVerificationError,
    configure_sftp,
    verify_sftp,
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
    configure = commands.add_parser(
        "configure-sftp", help="Store pinned Discovery Executor SFTP connection data"
    )
    configure.add_argument("--state-dir", required=True)
    configure.add_argument("--host", required=True)
    configure.add_argument("--port", required=True, type=int)
    configure.add_argument("--username", required=True)
    configure.add_argument("--host-key", required=True)
    verify = commands.add_parser(
        "verify-sftp", help="Verify the pinned Discovery Executor SFTP connection"
    )
    verify.add_argument("--state-dir", required=True)
    parsed = parser.parse_args(arguments)

    try:
        if parsed.command == "initialize":
            result = initialize_identity(parsed.executor_id, parsed.state_dir)
        elif parsed.command == "configure-sftp":
            result = configure_sftp(
                parsed.state_dir,
                parsed.host,
                parsed.port,
                parsed.username,
                parsed.host_key,
            )
        else:
            result = verify_sftp(parsed.state_dir)
    except (
        ExecutorIdentityInitializationError,
        ExecutorSftpConfigurationError,
        ExecutorSftpVerificationError,
    ) as exception:
        print(str(exception), file=sys.stderr)
        return 2
    print(result.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
