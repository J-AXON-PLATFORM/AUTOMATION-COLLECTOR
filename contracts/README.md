# Copias vendorizadas de contratos

`agent/1.0/` es una copia byte a byte de la fuente canónica:

`J-AXON-PLATFORM/BACKEND:doc/contracts/agent/1.0/`

No editar manualmente el bundle. Usar `scripts/sync_agent_contracts.py` y verificar el manifest SHA-256. La CI valida la integridad local sin clonar backend ni usar secretos cross-repo.

`discovery/1.0/` es la copia byte a byte del contrato Discovery Job canónico:

`J-AXON-PLATFORM/BACKEND:doc/contracts/discovery/1.0/`

Se sincroniza y verifica con `scripts/sync_discovery_contracts.py`. El validador es local y offline; no añade polling, ejecución, escaneo ni Results.
