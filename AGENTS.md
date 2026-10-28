# AGENTS.md: AntFish

Instrucciones para cualquier agente de IA que trabaje en este repositorio. Son cortas a propósito: el detalle vive en `docs/CONTEXTO_AntFish_V2.md`. **Léelo antes de escribir código.**

## Proyecto

AntFish analiza SMS y URLs sospechosas (phishing/smishing) y devuelve un score de 0 a 100 con semáforo de riesgo. Backend FastAPI (Python) + MongoDB + Redis. App Flutter. Modelo de datos en `docs/antfish_modelo_nosql.json`.

## Fuentes de verdad y precedencia

1. `docs/CONTEXTO_AntFish_V2.md`, secciones 1 a 8 (requerimientos): **inmutables** salvo decisión formalmente aprobada por el equipo y registrada en el ADR.
2. `docs/CONTEXTO_AntFish_V2.md`, secciones 9 a 11 (arquitectura y decisiones resueltas).
3. Registro Definitivo de Decisiones Técnicas y de Arquitectura (ADR) (`docs/DESICIONES TECNICAS/decisiones_t_cnicas_de_arquitectura_y_dise_o_antfish.md`).
4. Arquitectura backend (`docs/MODELADO-AGENTS/arquitectura_backend_v2.json`).
5. Modelo de datos NoSQL (`docs/MODELADO-AGENTS/antfish_modelo_nosql.json`).
6. Este archivo.

Si dos fuentes se contradicen, **detente y pregunta**. No elijas tú.

## Comandos

```bash
docker compose up -d mongo redis      # dependencias locales
pytest tests/unit                     # rápido, sin red
pytest tests/integration              # requiere Docker
ruff check . && ruff format --check . # lint y formato
mypy app                              # tipos
lint-imports                          # regla de capas (import-linter)
```

## Arquitectura (resumen)

Capas: `api → services → (engine | clients | repositories)`, más `core` transversal.

* `engine/` es **puro**: solo librería estándar, sin I/O, sin imports del resto de `app`.
* `api/` nunca importa `repositories`, `clients` ni `engine`: pasa siempre por `services`.
* `clients` y `repositories` solo pueden importar `engine.models` y `core`.
* Tabla completa en CONTEXTO §9.3. Se verifica con `lint-imports`.

## Siempre

* Type hints en todo código de `app/`.
* I/O asíncrono (`httpx.AsyncClient`, PyMongo async, `redis.asyncio`).
* Cambios pequeños y enfocados; un tema por cambio.
* Todo cambio en `engine/` lleva sus pruebas unitarias.
* Citar el ID del requerimiento (RF-xx, RNF-xx) o de la regla (RN-xx) que se implementa, en el mensaje del commit o PR.
* Declarar explícitamente cualquier supuesto que hiciste.
* Correr `ruff`, `mypy`, `lint-imports` y `pytest tests/unit` antes de dar algo por terminado.

## Preguntar antes de hacer

* Agregar o actualizar dependencias.
* Cambiar el modelo de datos, índices, `$jsonSchema` o TTL.
* Cambiar contratos de la API (rutas, request, response).
* Cambiar flujos de autenticación o contratos de verificación/recuperación.
* Cambiar los límites operativos: vigencia de código 10 min, máx. 5 intentos, máx. 3 reenvíos por hora.
* Cambiar las políticas de resiliencia fail-open (reputación/cuota) y fail-closed (autenticación/verificación).
* Cambiar los TTL de índices o almacenes efímeros (I8 TTL 30 días, I11 TTL 48 h, etc.).
* Tocar `Dockerfile`, `docker-compose.yml` o CI.
* Modificar las decisiones de diseño resueltas en la sección 11 de CONTEXTO o en el ADR.
* Crear carpetas o capas nuevas.

## Nunca

**Reglas de negocio**
* Modificar puntos por regla, topes de capa, umbrales de la escala, o la fórmula de score y cortocircuito (CONTEXTO §5). Son requerimientos.
* Analizar más de 2 URLs por mensaje SMS (se seleccionan las 2 de mayor riesgo sintáctico).
* Recalcular el score en la app Flutter. Lo decide el backend.

**Privacidad y seguridad**
* Guardar el texto de un SMS (base de datos, caché, archivos) ni escribirlo en logs. Solo `mensaje_hash` y `urls_extraidas`.
* Registrar contraseñas, tokens, claves de API ni parámetros de query de URLs analizadas.
* Guardar o registrar en logs códigos de verificación o ID tokens de Google.
* Enviar un código de verificación o recuperación sin control de rate limit.
* Responder distinto según exista o no un correo en `/auth/password/forgot`, `/auth/verify-email` y `/auth/password/reset` (las respuestas deben ser uniformes para evitar la enumeración de usuarios).
* Permitir login o emitir tokens a cuentas en estado `pendiente_verificacion` o `eliminada`.
* Operar el subsistema de verificación o autenticación en fail-open (siempre debe ser fail-closed).
* Poner secretos en el código, en tests o en el repositorio. Solo variables de entorno.
* **Hacer una petición a la URL analizada** (ni HEAD, ni redirecciones, ni captura de pantalla). Solo se consultan las APIs de reputación.
* Usar SHA-256 simple para `mensaje_hash` (debe ser HMAC-SHA256 con secreto del servidor) ni guardar contraseñas con algo distinto de Argon2id.
* Desactivar la verificación TLS ni exponer trazas internas en las respuestas.

**Caché y rendimiento**
* Guardar en caché de Redis (`rep:{url_normalizada}`) si alguna API externa falló o superó la cuota (solo se cachea cuando las 3 APIs responden `ok`).
* Hacer I/O bloqueante en el event loop (`requests`, `time.sleep`, drivers síncronos).
* Saltarse Redis para consultar las APIs externas (RF-04).

**Calidad**
* Capturar excepciones con `except:` o `except Exception:` sin relanzar o manejar de forma explícita.
* Usar `print`. Usar el logger de `core/logging.py`.
* Debilitar, borrar o saltar un test para que pase, ni hacer mock del código que el test pretende probar. Si un test falla, arregla el código o pregunta.

**Alcance**
* Inventar endpoints, campos, colecciones o requerimientos que no estén en CONTEXTO o en el modelo de datos.
* Reescribir, borrar o "limpiar" `docs/` sin que se pida (salvo en sincronizaciones documentales explícitas según la sección "Mantener la documentación sincronizada").
* Importar entre capas violando la regla de dependencias, ni "arreglarlo" editando `.importlinter`.

## Convenciones

* Código Python en inglés; nombres de colecciones, campos persistidos, códigos de regla y textos al usuario en español (el mapeo vive en `repositories/` y `api/schemas/`).
* Enums en minúsculas:
  * `bajo|medio|alto|critico` (nivel de riesgo)
  * `sms|url` (tipo de entrada)
  * `ok|timeout|rate_limit|error` (estado de fuentes de reputación)
  * `pendiente_verificacion|activa|suspendida|eliminada` (estado de cuenta)
  * `local|google` (proveedor de autenticación)
  * `lista_negra|suplantacion_marca` (motivo de cortocircuito)
  * `verificacion|recuperacion` (tipo de código en Redis)
* Cada cliente externo tiene timeout propio (configurable); una API caída degrada el análisis, nunca lo rompe (RNF-02).

## Mantener la documentación sincronizada

Todo cambio en el modelo de datos, índices, `$jsonSchema`, endpoints, reglas de negocio o decisiones técnicas obliga, en el mismo cambio, a:
1. Agregar una entrada numerada en el ADR (Decisión / Por qué).
2. Actualizar los documentos afectados conforme a la siguiente matriz:

| Si cambias... | Actualiza... |
|---|---|
| Modelo NoSQL, índices o validaciones | docs/MODELADO-AGENTS/antfish_modelo_nosql.json, docs/MODELADO-AGENTS/arquitectura_backend_v2.json, ADR, docs/MODELADO-AGENTS/CONTEXTO_AntFish_V2.md §10, scripts/init_antfish_db.js |
| Reglas de negocio o fórmulas de scoring | `docs/CONTEXTO/Reglas de negocio AntFIsh.md`, `docs/MODELADO-AGENTS/antfish_modelo_nosql.json`, `docs/MODELADO-AGENTS/CONTEXTO_AntFish_V2.md` §5 |
| Endpoints, contratos de API o flujos auth | `docs/MODELADO-AGENTS/CONTEXTO_AntFish_V2.md` §7 y §9.6, `docs/MODELADO-AGENTS/arquitectura_backend_v2.json`, ADR, Casos de uso |
| Decisiones de arquitectura o cierre de DP | ADR, `docs/MODELADO-AGENTS/arquitectura_backend_v2.json` (mover DP a confirmadas), `docs/MODELADO-AGENTS/CONTEXTO_AntFish_V2.md` §11 |

3. Subir la versión (+0.1) y registrar el cambio en el "Historial de cambios" de cada documento tocado.
4. Mover cualquier decisión pendiente (DP) resuelta a `decisiones_confirmadas`.
5. Listar en la descripción del cambio cualquier documento que no pudiste actualizar, justificando el motivo.

Esta sección es la excepción explícita a la regla "Nunca reescribir docs/ sin que se pida".

## Definición de terminado

* [ ] Cumple el RF/RNF citado y no contradice CONTEXTO.
* [ ] Documentación sincronizada: ADR actualizado, documentos derivados actualizados, versiones incrementadas y cambios registrados en el historial de cada documento modificado.
* [ ] `ruff`, `mypy`, `lint-imports` y las pruebas pasan.
* [ ] Pruebas nuevas para la lógica nueva (en `engine/`, con la tabla de puntos).
* [ ] Sin datos sensibles en logs, base de datos ni caché.
* [ ] Supuestos y dudas listados en la descripción del cambio.

## Si tienes dudas

Pregunta. Una pregunta cuesta menos que un cambio que viole un requerimiento.

---

## Historial de cambios

| Versión | Fecha | Resumen | ADR relacionados |
|---|---|---|---|
| 2.2 | 2026-10-28 | Inclusión de scripts/init_antfish_db.js en la matriz de sincronización ante cambios de modelo, índices o validaciones (ADR #70). | ADR #70 |
| 2.1 | 2026-10-27 | Sincronización documental v2.1: D1 a D18 (ADR #51 a #68). Actualización de ruta canónica a CONTEXTO_AntFish_V2.md, inclusión de ADR y arquitectura_backend como fuentes de verdad, convenciones de enums completas (error, estados de cuenta, proveedores, motivos de cortocircuito, tipos de código), políticas de seguridad fail-closed y respuestas uniformes, y formalización del protocolo de sincronización documental. | ADR #51 a #68 |
