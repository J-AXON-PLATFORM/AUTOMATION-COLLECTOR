import subprocess
import sys

import pytest

import jaxon_agent
from jaxon_agent.__main__ import main


def test_agent_identity() -> None:
    assert jaxon_agent.PROGRAM_NAME == "J-AXON Agent"
    assert jaxon_agent.__version__ == "0.1.0"


def test_agent_main(capsys: pytest.CaptureFixture[str]) -> None:
    assert main() == 0
    assert capsys.readouterr().out == "J-AXON Agent 0.1.0\n"


def test_agent_module_entrypoint() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "jaxon_agent"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout == "J-AXON Agent 0.1.0\n"
    assert "Discovery Executor" not in result.stdout
