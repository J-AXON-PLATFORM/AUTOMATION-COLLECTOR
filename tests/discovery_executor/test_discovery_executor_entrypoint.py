import subprocess
import sys

import pytest

import jaxon_discovery_executor
from jaxon_discovery_executor.__main__ import main


def test_discovery_executor_identity() -> None:
    assert jaxon_discovery_executor.PROGRAM_NAME == "J-AXON Discovery Executor"
    assert jaxon_discovery_executor.__version__ == "0.1.0"


def test_discovery_executor_main(capsys: pytest.CaptureFixture[str]) -> None:
    assert main() == 0
    assert capsys.readouterr().out == "J-AXON Discovery Executor 0.1.0\n"


def test_discovery_executor_module_entrypoint() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "jaxon_discovery_executor"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout == "J-AXON Discovery Executor 0.1.0\n"
    assert result.stdout != "J-AXON Agent 0.1.0\n"
