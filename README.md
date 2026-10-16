# J-AXON Automation Collector

Fundacion tecnica de los dos programas Python de J-AXON:

- **J-AXON Agent**: futuro proceso instalado en equipos administrados.
- **J-AXON Discovery Executor**: futuro ejecutor de trabajos de descubrimiento en equipos designados.

Son programas diferentes. No comparten entrypoint, identidad SSH ni configuracion operacional. La documentacion canonica del sistema vive en el repositorio `BACKEND`, bajo `doc/`.

## Requisitos

- Python `3.14.8`.
- uv `0.12.24`.
- Sistema POSIX con ownership y modos de archivo Unix; este corte no garantiza ACL de Windows.

El proyecto exige esas versiones mediante `.python-version`, `requires-python` y `tool.uv.required-version`.

## Instalacion reproducible

```bash
uv python install 3.14.8
uv sync --locked
```

Las dependencias runtime `jsonschema` y `referencing` validan localmente los contratos Agent. `cryptography` genera y valida el keypair Ed25519 y Paramiko 5.0.0 verifica la conexion SFTP con la host key fijada. Ruff, pytest y pip-audit son herramientas de desarrollo fijadas exactamente en `pyproject.toml` y bloqueadas en `uv.lock`.

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

## Inicializacion local del Agent

Tras pre-registrar un Agent desde la aplicacion web, su identidad local se crea sin conectividad:

```bash
uv run jaxon-agent initialize \
  --agent-id 8b90cfac-9304-4a11-9422-7c834431f920 \
  --state-dir /ruta/privada/jaxon-agent
```

El comando exige un UUIDv4 y un directorio privado `0700`, crea archivos `0600`, nunca sobrescribe una identidad y devuelve JSON con el `agentId`, la ruta publica, la huella SHA-256 y la clave publica OpenSSH copiable. La clave privada permanece en el directorio local y nunca se imprime ni se envia por red.

## Configuracion y verificacion SFTP

Tras activar el Agent desde la aplicacion web, almacene los cuatro datos de conexion devueltos por el backend y verifique el acceso:

```bash
uv run jaxon-agent configure-sftp \
  --state-dir /ruta/privada/jaxon-agent \
  --host 127.0.0.1 \
  --port 2022 \
  --username agent-8b90cfac-9304-4a11-9422-7c834431f920 \
  --host-key 'ssh-ed25519 AAAA...'
uv run jaxon-agent verify-sftp --state-dir /ruta/privada/jaxon-agent
```

La configuracion es idempotente y no sustituye silenciosamente valores. La verificacion acepta solo la host key Ed25519 fijada y la private key de esa identidad, deshabilita SSH Agent y busqueda de claves externas, y abre realmente el subsistema SFTP con timeouts `10/10/60` segundos.

## Snapshot tecnico puntual

Un Agent inicializado, configurado y activado puede recoger, validar y transferir un unico snapshot minimo:

```bash
uv run jaxon-agent send-snapshot --state-dir /ruta/privada/jaxon-agent
```

El comando funciona solo en POSIX/Linux. Obtiene el `agentId` de la identidad local, recoge exclusivamente hostname, sistema operativo, arquitectura, CPU logica, memoria y volumen raiz, y valida offline los bytes JSON contra Agent 1.0 antes de conectar. La transferencia usa la private key local exacta y la host key fijada, crea un archivo `/snapshots/{messageId}.json.part` de forma exclusiva y finaliza con rename a `.json` en el mismo directorio. No persiste el payload localmente, no imprime datos tecnicos ni claves y no implementa polling, retries, spool, tareas o procesamiento Collector.

## Validacion

```bash
uv lock --check
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv build
uv run pip-audit
uv run python scripts/sync_agent_contracts.py verify
```

## Contratos Agent

`contracts/agent/1.0/` es una copia vendorizada de la fuente canónica situada en `BACKEND/doc/contracts/agent/1.0/`. El manifest verifica cada archivo y el bundle completo mediante SHA-256.

```bash
uv run python scripts/sync_agent_contracts.py sync --source ../backend/doc/contracts/agent/1.0
uv run python scripts/sync_agent_contracts.py check --source ../backend/doc/contracts/agent/1.0
uv run python scripts/sync_agent_contracts.py verify
```

El validador `jaxon_agent.contracts` resuelve todos los `$ref` offline. Valida bytes y tamaño antes de parsear, acepta únicamente la versión `1.0` y separa mensajes emitidos por Agent de tareas recibidas. No registra el payload cuando informa un error.

## Limites actuales

El Agent incorpora inicializacion local Ed25519, verificacion puntual de conexion SFTP y un snapshot tecnico puntual. Todavia no implementa polling, retries, spool, tareas reales, procesamiento Collector, discovery de red, revocacion, rotacion, servicios del sistema operativo ni packaging con PyInstaller.

El Discovery Executor continua sin identidad o conexion SFTP funcional y debera usar una clave y un buzon independientes del Agent.
