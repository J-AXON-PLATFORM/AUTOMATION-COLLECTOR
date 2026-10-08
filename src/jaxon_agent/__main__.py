"""Executable entrypoint for the J-AXON Agent."""

from jaxon_agent import PROGRAM_NAME, __version__


def main() -> int:
    """Print the program identity and return a successful exit status."""
    print(f"{PROGRAM_NAME} {__version__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
