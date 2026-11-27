# CLAUDE.md — Contexto de sesión de AntFish Backend

Resumen compacto del trabajo hecho hasta 2026-11-16. **Lee primero `AGENTS.md`** (reglas del proyecto y precedencia de fuentes; sigue vigente y manda sobre este archivo) y luego esto. No contiene secretos.

## Proyecto
Backend FastAPI (Python 3.14 en el venv) + MongoDB (Motor/PyMongo) + Redis que analiza SMS/URLs sospechosas (phishing/smishing) y devuelve score 0-100 con semáforo (`bajo|medio|alto|critico`). App móvil Flutter (no se recalcula score en el cliente).

- Docs de diseño en `docs/` (**ignorada por git**, solo local): `contexto-AntFish.md` (§5 reglas, §9 arquitectura, §11 decisiones), `arquitectura_backend_v2.json`, `antfish_modelo_nosql.json`, `reglas-negocio.md` (RN-01..26), `casos-de-uso.md`, `requerimientos.md`, `mapeo-requerimientos.md` (requisito → archivo). AGENTS.md cita nombres distintos (`CONTEXTO_AntFish_V2.md`, ADR); el ADR **no existe** en `docs/`.
- Capas: `api → services → (engine | clients | repositories)`; `engine/` puro (solo stdlib); `api/` nunca importa repositories/clients/engine directamente (la excepción actual: `api/deps.py` usa `core.security` y el container).

## Comandos
```bash
docker compose up -d                 # completo (mongo, mongo-users, redis); NO basta "up -d mongo redis"
python -m app.repositories.mongo.init_db   # migraciones+siembra, usa MONGODB_MIGRATION_URL (usuario antfish_migrator)
python -m pytest tests/unit -q       # 111 pruebas, sin red
# Integración (Docker): Redis (con requirepass desde 2026-11-22: REDIS_PASSWORD en .env) -> REDIS_TEST_URL (def. redis://localhost:6379/15; con clave: redis://:<clave>@localhost:6379/15); Mongo -> MONGO_URI con usuario root
python -m pytest tests/integration -q
```
`ruff check . && ruff format --check . && mypy app && lint-imports` **instalados y en verde** (2026-11-16; config en `pyproject.toml`, contratos de capas incluidos; se añadieron `__init__.py` a paquetes que eran namespace). Dependencias fijadas en `requirements.txt` / `requirements-dev.txt` (reemplazan al antiguo `requeriments.txt`).

## Estado de implementación
| Área | Estado |
|---|---|
| Auth: `register`, `verify-email`, `login` | Listos (Argon2id, códigos 6 dígitos con `secrets`, HMAC en Redis, respuestas uniformes) |
| Análisis `POST /analysis` + historial/detalle/borrado (RF-05.1), `GET /metrics/me` (RF-05.2) | Listos; persistencia ACID (UnitOfWork, `respuestas_apis`, `$inc` métricas) |
| `api/deps.py` `get_current_user` | Listo (JWT access, `iat >= password_changed_at`, 403 `ACCOUNT_NOT_VERIFIED`, 401 otros estados) |
| Motor heurístico (RF-02.3/02.4), scoring, recomendaciones | Listo |
| Clientes Web Risk y VirusTotal | **Verificados contra APIs reales** (URLs de prueba dan positivo) |
| PhishTank | **Retirado (2026-11-16)**: `container.py` ya no lo cablea (comentado; `phishtank_client=None` aunque `PHISHTANK_ENABLED=true`). Código, config, regla `API_PHISHTANK` y enum de Mongo se conservan. Sustituto por decidir |
| Caché de reputación RF-04 (`rep:{url_normalizada}`, TTL 3600) | Listo |
| Rate limit y cuota dual | Listo (ver decisiones) |
| Catálogo de reglas/marcas (`rules_repository`, `rules_provider`, `initial_data.json`) | Listo |
| `docker-compose.yml`, usuarios Mongo, `init_db` | Listo y verificado (en stack aislado) |

## Decisiones tomadas (con el usuario) — no reabrir sin preguntar
- **Persistencia falla → HTTP 503** (`PersistenceError`); la app **no arranca** si Mongo no es replica set (`hello.setName`).
- **Secretos obligatorios** sin default: `HMAC_PEPPER`, `JWT_SECRET`, `JWT_REFRESH_SECRET` (≥32 chars, no placeholders, JWT distintos). `hide_input_in_errors=True`.
- **Rate limit (cierra DP-04, ventana fija 60 s, Lua atómico):** `rl:auth:{endpoint}:{ip}` 5/min (login, register; **fail-closed**→503), `rl:analysis:{user_id}` 20/min (**fail-open**), `reenvio:{user_id}` 3/hora compartido (D17, fail-closed; se aplica en `generate_and_save_code`). 429 con `Retry-After`. IP = `request.client.host`; en producción uvicorn con `--proxy-headers --forwarded-allow-ips=<proxy>`.
- **Cuotas por API** (`cuota:{api}:pm|daily`, atómicas, fail-open; agotada → estado `rate_limit`/`analisis_parcial`): VirusTotal 4/500, Web Risk 60/5000, PhishTank 20/2000 (supuestos conservadores; env `QUOTA_*`). VT a 4/min provoca resultados parciales con muchas consultas.
- **Caché:** se escribe solo si **todas las APIs habilitadas** respondieron `ok`; entrada válida solo si contiene todas las habilitadas (si se activa PhishTank, las viejas se descartan); hit no consume cuota y no escribe `respuestas_apis`; Redis caído = fail-open.
- **Catálogo Mongo → motor:** se lee `activa`, listas (TLDs, acortadores), filtro `marcas_codigos` (vacío = todas) y marcas. **Los puntos NUNCA vienen de Mongo** (RN-03..05 fijos en `engine/rule_catalog.py`; si difieren se ignoran y se avisa). Regex de texto quedan en código (ReDoS). Desactivar `URL_SUBDOMINIO_ENGANOSO` no quita el override de marca (`suplantacion_marca`). Se cargan reglas/marcas inactivas también (se desvía de P4). Respaldo: valores internos si Mongo falla/vacío/ inválido, conserva último catálogo bueno, reintenta a los 30 s; TTL 3600 s.
- **`initial_data.json`** (12 reglas, 21 marcas): generado desde constantes del motor (prueba de coherencia en `tests/unit/test_initial_data.py`). **10 marcas nuevas sembradas INACTIVAS** (telcel, imss, infonavit, cfe, correos_mexico, liverpool, bancoppel, bancoazteca, scotiabank, inbursa) hasta que el usuario valide dominios oficiales; `cfe`/`imss`/`sat` pueden dar falsos positivos (match por subcadena).
- **Mongo:** dos usuarios de mínimo privilegio creados por el servicio `mongo-users` (idempotente): `antfish_app` (readWrite en `antfish_db`, usado por la API vía `MONGODB_URL`) y `antfish_migrator` (+dbAdmin, solo `init_db` vía `MONGODB_MIGRATION_URL`). Replica set `rs0` con keyfile, miembro `localhost:27017`.
- **Seguridad aplicada:** `/docs`/`/redoc`/`openapi` apagados con `ENVIRONMENT=production`; hash señuelo Argon2 en login (anti-enumeración por tiempo); JWT exige `exp,iat,sub`; `.gitignore` reescrito; `context/` movido a `docs/` y sacado del repo; `.pyc` fuera del índice. Repo privado.

## Variables de entorno (solo nombres; valores en `.env`, ignorado)
`ENVIRONMENT`, `MONGODB_URL`, `MONGODB_MIGRATION_URL`, `DATABASE_NAME`, `REDIS_URL`, `HMAC_PEPPER`, `JWT_SECRET`, `JWT_REFRESH_SECRET`, `RESEND_API_KEY`, `GOOGLE_WEB_RISK_API_KEY`, `VIRUSTOTAL_API_KEY`, `PHISHTANK_API_KEY`, `PHISHTANK_ENABLED`, `MONGO_ROOT_USER/PASSWORD`, `MONGO_APP_USER/PASSWORD`, `MONGO_MIGRATOR_USER/PASSWORD`, `QUOTA_*`, `RATE_LIMIT_*`, `REPUTATION_CACHE_TTL_SECONDS`, `RULES_CACHE_TTL_SECONDS`, `RULES_RETRY_SECONDS`. Plantilla: `.env.example`. **No leer ni imprimir `.env`** (el clasificador de permisos lo bloquea y es sensible); para editarlo, hacerlo por script sin mostrar valores.

## Pendiente (orden sugerido)
1. **Auth:** hechos `register`, `verify-email`, `resend-code`, `login`, `refresh`, `forgot`, `reset`, `DELETE /auth/me` (solo local; Google → 501) y `POST /auth/google` (código listo; `google-auth==2.62.2` ya instalado y fijado (2026-11-16; decodificación verificada con un certificado RSA local); y poner `GOOGLE_CLIENT_ID` en `.env`). **`DELETE /auth/me` (2026-11-16):** con `password_hash` (incluye locales con Google vinculado) se pide `password`; cuentas solo Google piden `id_token` del mismo `google_sub` (403 `INVALID_CREDENTIALS`/`INVALID_TOKEN`, 503 si Google cae). **Contrato de error global:** todo error es `{"code","detail"}` (`app/api/errors.py`, `api_error()` para códigos específicos: `INVALID_TOKEN`, `EMAIL_NOT_VERIFIED`, `ACCOUNT_CONFLICT`, `INVALID_CREDENTIALS`, `ACCOUNT_NOT_VERIFIED`; genéricos por estado HTTP, `RATE_LIMIT_EXCEEDED`, `VALIDATION_ERROR`). `login` y `google` devuelven además `user {email,nombre,proveedor_auth}`. Docs en `docs/` sin sincronizar con esto. Pendiente: probar `/auth/google` con un token real (esperando `GOOGLE_CLIENT_ID` de frontend). `tests/integration/test_delete_account_mongo.py` **pasa** contra Mongo real (4 pruebas, con MONGO_URI root).
2. ~~`GET /health` real~~ **Hecho** (`services/health_service.py`, `api/v1/health.py`; ADR #79 propuesto).
3. **RNF-01:** las 2 URLs de un SMS se consultan en serie (~1.0-1.2 s por URL). **Decisión del usuario (2026-11-16): NO paralelizar** mientras el tiempo de respuesta no aumente demasiado; no reabrir sin medir.
4. ~~Instalar/correr ruff, mypy, import-linter~~ **Hecho**; **CI montado (sin commitear aún):** `.github/workflows/ci.yml` (ruff, format, mypy, lint-imports, pytest unit, gitleaks) y `.pre-commit-config.yaml` (ruff+gitleaks; instalar con `pre-commit install`). Falta activarlo en GitHub y, si se quiere, exigirlo para merge a `main`.
5. **PhishTank:** decidir sustituirlo (URLhaus/OpenPhish), feed local o eliminarlo (cambia RF-02.2/RN-02, requiere ADR).
6. Endurecimiento restante: migrar Motor→PyMongo async (Motor deprecado; AGENTS.md pide PyMongo async), logger JSON con escape, `except Exception` residuales (clientes), Dockerfile, Redis con contraseña/TLS, Mongo 3 nodos o Atlas con TLS, credenciales fuera del healthcheck, secretos en gestor, `docker-compose` para producción.
7. Opcional: `scripts/seed_rules.py` (en `/scripts`, ignorado); limpiar historial git de `context/` y `.pyc` (`git filter-repo`, solo si se pide).

## Documentación sincronizada (2026-11-16)
Actualizados en `docs/`: `contexto-AntFish.md` v2.2, `arquitectura_backend_v2.json` v2.3 (DP-04 cerrada), `reglas-negocio.md` v2.2, `casos-de-uso.md` v2.2, `mapeo-requerimientos.md`. Las entradas de ADR están en `docs/ADR-pendientes-de-registrar.md` (#72-#78 **propuestos**; el ADR oficial no está en el repo: pedir ruta al usuario y confirmar numeración). Pendiente de aprobación: `forgot` no responde 429 (contradice la redacción literal de §9.7). Faltan por documentar cuando se implementen: `DELETE /auth/me` y `POST /auth/google` (ADR #78 reservado). `antfish_modelo_nosql.json` no cambió.

## Estado de git
Casi todo el trabajo de esta sesión está **sin commitear** (`git status`; el usuario ha ido staging/commiteando por su cuenta). No hacer commit sin que lo pida; citar RF/RN en los mensajes y terminar con la línea `Co-Authored-By` indicada por el entorno.

## Trampas aprendidas
- **Servicio de Windows `MongoDB` (standalone) ocupaba el puerto 27017** y respondía en lugar del contenedor (síntoma: "No replica set members available" / auth fallida). Se detuvo con `Stop-Service MongoDB` (admin). Verificar con `docker ps` que muestre `127.0.0.1:27017->27017/tcp`.
- Con `MONGO_PORT` distinto de 27017 el replica set (miembro `localhost:27017`) redirige al puerto equivocado; para pruebas aisladas usar `directConnection=true`.
- **Heredocs largos de bash con Python embebido fallan** (EOF/comillas): usar las herramientas Write/Edit o un script en el scratchpad. Cuidado con `replace` por subcadena (una vez se editó la línea equivocada; las pruebas lo detectaron).
- `PyMongo 4.19`: `IndexModel.name` no existe → `model.document["name"]`; `index_information()` devuelve claves como lista de pares (ya corregido en `init_db`).
- Pydantic imprime `input_value` en errores: mantener `hide_input_in_errors`.
- Imitar un navegador para saltar Cloudflare de PhishTank se rechazó (es evasión de una protección).
- Tests: `tests/conftest.py` genera secretos aleatorios por ejecución (no hay secretos fijos en el repo). Pruebas de integración dejan claves de cuota efímeras en Redis db 15.
- Stack aislado para probar compose/Mongo sin tocar el real: `docker compose -p aftest --env-file <archivo temporal con puertos 27099/6399 y credenciales aleatorias> up -d --wait`, esperar a que `mongo-users` termine, probar con `directConnection=true`, y `down -v` al final.

- **`localhost` en Windows tarda ~2 s en conectar Redis** (intenta IPv6 `::1` primero): `/health` daba `degradado` falso con el timeout de 2 s. Usar `REDIS_URL=redis://127.0.0.1:6379/0` en `.env` local (no afecta a Docker/producción).

## Metodología acordada con el usuario
1. Explorar docs y código; **preguntar (AskUserQuestion) las decisiones que cambien contratos, modelo, TTL, políticas fail-open/closed, dependencias o infraestructura**; el resto se decide y se declara como supuesto.
2. Para problemas con varias soluciones, presentar alternativas (ToT) y esperar elección antes de actuar.
3. Implementar con pruebas (unitarias con fakes; integración con Redis/Mongo reales cuando aplique), verificar contra servicios reales y reportar con honestidad qué se probó y qué no.
4. Cierre de cada tarea: resumen breve (qué cambió, supuestos, pendientes, documentación sin sincronizar) y proponer el siguiente paso.
5. Responder en español, conciso. Nunca guardar texto de SMS ni secretos en logs/BD/caché; nunca hacer peticiones a las URLs analizadas.
