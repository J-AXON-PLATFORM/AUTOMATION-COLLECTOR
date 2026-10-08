# J-AXON Automation Collector

Fundacion tecnica de los dos programas Python de J-AXON:

- **J-AXON Agent**: futuro proceso instalado en equipos administrados.
- **J-AXON Discovery Executor**: futuro ejecutor de trabajos de descubrimiento en equipos designados.

Son programas diferentes. No comparten entrypoint, identidad SSH ni configuracion operacional. La documentacion canonica del sistema vive en el repositorio `BACKEND`, bajo `doc/`.

## Requisitos

- Python `3.14.8`.
- uv `0.12.24`.

El proyecto exige esas versiones mediante `.python-version`, `requires-python` y `tool.uv.required-version`.

## Instalacion reproducible

```bash
uv python install 3.14.8
uv sync --locked
```

Las dependencias runtime estan vacias. Ruff, pytest y pip-audit son herramientas de desarrollo fijadas exactamente en `pyproject.toml` y bloqueadas en `uv.lock`.

## Entry points

```bash
uv run jaxon-agent
uv run jaxon-discovery-executor
```

Tambien pueden comprobarse como modulos:

```bash
uv run python -m jaxon_agent
uv run python -m jaxon_discovery_executor
```

## Validacion

```bash
uv lock --check
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv build
uv run pip-audit
```

## Limites actuales

Esta fundacion solo identifica y ejecuta ambos programas. Todavia no implementa SFTP, Paramiko, contratos JSON Schema, snapshots, polling, spool, tareas remotas, recopilacion del sistema, discovery de red, enrolamiento, claves SSH, servicios del sistema operativo ni packaging con PyInstaller.

Cuando se incorporen identidades SSH, el Agent y el Discovery Executor deberan usar claves y buzones independientes.
