"""Executable entrypoint for the J-AXON Agent."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from jaxon_agent import PROGRAM_NAME, __version__
from jaxon_agent.identity import IdentityInitializationError, initialize_identity
from jaxon_agent.sftp import (
    SftpConfigurationError,
    SftpVerificationError,
    configure_sftp,
    verify_sftp,
)
from jaxon_agent.snapshot import SnapshotError, send_snapshot


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
    configure = commands.add_parser("configure-sftp", help="Store trusted SFTP connection data")
    configure.add_argument("--state-dir", required=True)
    configure.add_argument("--host", required=True)
    configure.add_argument("--port", required=True, type=int)
    configure.add_argument("--username", required=True)
    configure.add_argument("--host-key", required=True)
    verify = commands.add_parser("verify-sftp", help="Verify the configured SFTP connection")
    verify.add_argument("--state-dir", required=True)
    snapshot = commands.add_parser("send-snapshot", help="Collect and send one technical snapshot")
    snapshot.add_argument("--state-dir", required=True)
    parsed = parser.parse_args(arguments)

    try:
        if parsed.command == "initialize":
            result = initialize_identity(parsed.agent_id, parsed.state_dir)
        elif parsed.command == "configure-sftp":
            result = configure_sftp(
                parsed.state_dir, parsed.host, parsed.port, parsed.username, parsed.host_key
            )
        elif parsed.command == "verify-sftp":
            result = verify_sftp(parsed.state_dir)
        else:
            result = send_snapshot(parsed.state_dir)
    except (
        IdentityInitializationError,
        SftpConfigurationError,
        SftpVerificationError,
        SnapshotError,
    ) as exception:
        print(str(exception), file=sys.stderr)
        return 2
    print(result.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
