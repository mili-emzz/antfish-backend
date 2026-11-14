### 1. Casos de uso con ToT (v2.1)

**Raíz:** ¿qué operaciones debe soportar la BD de AntFish?

| Rama | Idea | Evaluación |
| ----- | ----- | ----- |
| A. Por flujo de usuario | Auth local y Google, analizar, historial, métricas, recuperación de contraseña | ✅ Núcleo, todo respaldado en los endpoints de §9.6 |
| B. Por ciclo de vida del dato | Crear, consultar, anonimizar, purgar y expirar por TTL | ✅ Revela cascadas ACID e índices TTL (I8, I11) |
| C. Por camino alterno | Fallos de API, Redis caído (fail-open vs fail-closed), análisis sin URL, concurrencia | ✅ Define validadores `$jsonSchema` e invariantes |
| D. Por operador/admin | Gestionar reglas y marcas | ⚠️ Solo por seed idempotente, sin endpoints de API |
| E. Analítica cruzada | Campañas por `mensaje_hash` o dominios entre usuarios | ❌ Podada: ningún endpoint ni requisito la pide; I3 e I4 diferidos (ADR #57) |

**Casos de uso resultantes (A+B+C+D):**

| CU | Caso de uso | Colecciones / motor | Soporte necesario |
| ----- | ----- | ----- | ----- |
| CU-01 | Registrar usuario local | `usuarios`, Redis | Índice único I1 de email (sin collation, normalizado en app); creación en `pendiente_verificacion`; sobrescritura si ya existía en pendiente (ADR #64); emisión de código a `verif:{user_id}` |
| CU-02 | Login / refresh con verificación de estado | `usuarios` | Lectura por email e `_id`; 403 `ACCOUNT_NOT_VERIFIED` solo tras validar contraseña con Argon2id (ADR #62); rechazo de cuentas `eliminada` con 401; revocación si `iat < password_changed_at` (ADR #68) |
| CU-03 | Analizar SMS (con 0, 1 o 2 URLs) | `analisis`, `metricas_usuario`, `respuestas_apis`, Redis | Transacción ACID (UnitOfWork); `$inc` atómico; `rep:{url_normalizada}`; URL dominante; `motivo_cortocircuito` (ADR #52); persistencia de hasta 2 URLs en `respuestas_apis` (ADR #51) |
| CU-04 | Analizar URL (sin Capa 3) | `analisis`, `metricas_usuario`, `respuestas_apis`, Redis | Igual que CU-03 con `mensaje_hash = null` y omisión de Capa 3 |
| CU-05 | Análisis parcial por degradación | `analisis` | `analisis_parcial: true` si falla cualquier API de cualquiera de las 2 URLs (ADR #53); estados `timeout`, `rate_limit` y `error` |
| CU-06 | Historial paginado por cursor | `analisis` | Índice I2 `(user_id: 1, fecha: -1, _id: -1)`; cursor opaco `(fecha, _id)`, 20 por página (ADR #58) |
| CU-07 | Detalle de un análisis | `analisis` | Búsqueda por `_id` y `user_id` |
| CU-08 | Borrar un análisis | `analisis`, `respuestas_apis` | Borrado en cascada mediante transacción ACID (I9 `user_id: 1, analisis_id: 1`), sin decrementar contadores históricos en `metricas_usuario` |
| CU-09 | Ver métricas de usuario | `metricas_usuario` | Lectura por `_id = user_id` |
| CU-10 | Eliminar cuenta | las 4 colecciones | Reautenticación por método (password si local, id_token si google/vinculada); anonimización completa en `usuarios` (email ofuscado, nulos en nombre, password y google_sub, `estado_cuenta = "eliminada"`, `fecha_eliminacion`) y purga física en cascada de `analisis`, `metricas_usuario` y `respuestas_apis` en transacción ACID (ADR #54) |
| CU-11 | Cargar reglas y marcas al arrancar | `reglas_heuristicas`, `marcas_protegidas` | Seed idempotente en lifespan condicionado a `count_documents == 0` (ADR #61); restablecimiento manual con `scripts/seed_rules.py` |
| CU-12 | Caché de reputación y cuotas | Redis | Claves `rep:{url_normalizada}` (TTL 3,600 s; solo si 3 APIs ok); cuota dual `cuota:{api}:pm` (TTL 60 s) y `cuota:{api}:daily` (TTL 86,400 s) con `INCR` atómico |
| CU-13 | Registro local con código de verificación | `usuarios`, Redis | `POST /auth/register`: crea o actualiza cuenta en `pendiente_verificacion`; emite código de 6 dígitos con HMAC-SHA256 en `verif:{user_id}` (TTL 600 s) despachado vía Resend; rate limit `reenvio:{user_id}` |
| CU-14 | Verificar correo electrónico | `usuarios`, Redis | `POST /auth/verify-email`: recibe `{email, codigo}`; resuelve `user_id` internamente; valida digesto HMAC en Redis bajo política fail-closed; transiciona a `activa`, `email_verificado = true`, `fecha_verificacion = ahora` (ADR #67) |
| CU-15 | Reenvío de código de verificación | Redis | `POST /auth/resend-code`: valida límite de 3 reenvíos/hora por usuario en `reenvio:{user_id}`; genera nuevo código, invalida el anterior y resetea intentos en `verif:{user_id}` |
| CU-16 | Login Google con vinculación | `usuarios` | `POST /auth/google`: valida Google ID Token con `google-auth`. Si es cuenta nueva, nace `activa` con `google_sub`. Si existe en `pendiente_verificacion`, la activa descartando `password_hash` previo (ADR #63). Si existe local activa y correo verificado, vincula `google_sub` preservando password (ADR #47). Emite Access y Refresh Tokens |
| CU-17 | Recuperación y reset de contraseña | `usuarios`, Redis | `POST /auth/password/forgot` responde siempre 200 uniforme (ADR #66); comparte `reenvio:{user_id}`. `POST /auth/password/reset` recibe `{email, codigo, nueva_password}`, actualiza `password_hash`, establece `password_changed_at = ahora` e invalida tokens previos (ADR #67, #68) |
| CU-18 | Depuración física de cuentas pendientes por TTL | `usuarios` | Eliminación desatendida de cuentas en `pendiente_verificacion` tras 48 horas (172,800 s) mediante índice TTL parcial I11 `{ fecha_registro: 1 }` en MongoDB, sin tareas programadas ni schedulers externos (ADR #65) |

---

### 2. Verificación con CoVE (Histórico)

Planteé preguntas de verificación iniciales y las contrasté contra los archivos para detectar inconsistencias:

| \# | Pregunta | Qué encontré |
| ----- | ----- | ----- |
| 1 | ¿El JSON incluye las secciones que el ADR dice haber restaurado? | **No.** El JSON no tenía `patrones_de_acceso`, `motor_de_puntuacion` ni `supuestos_de_capacidad` (ADR \#4). Los índices citaban P1 a P11, pero esos patrones no existían en el archivo. |
| 2 | ¿El ejemplo de `analisis` suma bien? | **No.** `puntos_por_capa.texto = 20`, pero solo aparecía un hallazgo de texto (+10). Faltaba `TXT_SOLICITUD_DATOS`, que el ADR \#5 decía haber restaurado. |
| 3 | ¿Todos los campos del ADR están en el esquema? | **No.** Faltaba `motivo_cortocircuito` (ADR \#12), y `estado` de `fuentes_consultadas` no incluía `error` (ADR \#32). |
| 4 | ¿Las claves de Redis coinciden entre documentos? | **No.** El JSON y el Contexto usaban `rep:{dominio}`, el ADR \#31 decía `rep:{url_normalizada}`. La cuota pasaba de `cuota:{api}` a `cuota:{api}:pm` y `:daily` (ADR \#39). |
| 5 | ¿El documento de reglas de negocio sigue vigente? | **Estaba desactualizado.** Usaba enums en MAYÚSCULAS, `score_total`/`fecha_escaneo` frente a `fecha`, índice único en `user_id`, “todas las URLs” frente a máx. 2, SHA-256 frente a HMAC-SHA256, y omitía el cortocircuito por marca. |
| 6 | ¿`respuestas_apis` permite saber a qué URL pertenece cada respuesta? | **No.** Se consultaban hasta 2 URLs × 3 APIs, pero la colección no tenía campo `dominio` ni `url_normalizada`. |
| 7 | ¿Existen los datos semilla que el arranque necesita? | **No.** El ADR \#33 mencionaba `initial_data.json`, pero solo había 1 regla de ejemplo y 1 marca en borrador. |
| 8 | ¿Los índices I3 e I4 tienen un caso de uso? | **No confirmado.** Ningún endpoint buscaba por `mensaje_hash` ni por `urls_extraidas.dominio`. |

---

### 3. Estado de Verificación (CoVE) tras v2.1

A partir de las decisiones cerradas D1 a D18 y la sincronización documental formal (ADR #51 a #68), se actualiza el estado de las 8 preguntas originales:

| \# | Pregunta de Verificación | Estado tras v2.1 | Resolución y Justificación Técnica |
|---|---|---|---|
| 1 | ¿El JSON incluye las secciones que el ADR dice haber restaurado? | **Resuelta** (ADR #51, #59, #60) | Se reincorporaron formalmente en `antfish_modelo_nosql.json` las secciones `patrones_de_acceso` (P1 a P13), `motor_de_puntuacion`, `supuestos_de_capacidad` y `validaciones_mongo` (con `$jsonSchema` y `$expr`). |
| 2 | ¿El ejemplo de `analisis` suma bien? | **Resuelta** (ADR #56) | Se restauró el hallazgo `TXT_SOLICITUD_DATOS` (+10 pts) junto a `TXT_LENGUAJE_URGENCIA` (+10 pts), cuadrando exactamente los 20 pts de la Capa 3; con URL 30 y APIs 40, la suma resulta exactamente en 90 pts (nivel `critico`). |
| 3 | ¿Todos los campos del ADR están en el esquema? | **Resuelta** (ADR #52, #32) | Se eliminó el booleano redundante `cortocircuito` y se formalizó el enum `motivo_cortocircuito: "lista_negra" | "suplantacion_marca" | null`. Se integró `error` al enum de estado de fuentes consultadas. |
| 4 | ¿Las claves de Redis coinciden entre documentos? | **Resuelta** (ADR #60, #39) | Se unificó universalmente la clave a `rep:{url_normalizada}` (URL con path, sin query, fragmento ni userinfo). Se definió la cuota dual `cuota:{api}:pm` (TTL 60 s) y `cuota:{api}:daily` (TTL 86,400 s). |
| 5 | ¿El documento de reglas de negocio sigue vigente? | **Resuelta** (ADR #51 a #68) | Se reescribió íntegramente `Reglas de negocio AntFIsh.md` en versión 2.1, adoptando enums en minúsculas, RN-01 a RN-26 idénticas al modelo NoSQL, validaciones en Mongo y matriz de responsabilidades. |
| 6 | ¿`respuestas_apis` permite saber a qué URL pertenece cada respuesta? | **Resuelta** (ADR #51) | Se agregaron los campos `url_normalizada` y `dominio` en `respuestas_apis`, persistiendo las hasta 2 URLs analizadas por mensaje (hasta 6 documentos) con TTL de 30 días e índices I8 e I9. |
| 7 | ¿Existen los datos semilla que el arranque necesita? | **Abierta** (en desarrollo) | La lógica de siembra idempotente en `init_db.py` está definida y cerrada (ADR #33, ADR #61), pero la confección exhaustiva del catálogo de reglas y marcas en `initial_data.json` es responsabilidad del equipo humano de seguridad. |
| 8 | ¿Los índices I3 e I4 tienen un caso de uso? | **Resuelta** (ADR #57) | Se retiraron I3 e I4 de los índices activos de v1 y se reclasificaron formalmente como "índices diferidos" (asociados a la rama E de casos de uso), reduciendo la sobrecarga de escritura en MongoDB. |

---

### Historial de cambios

| Versión | Fecha | Resumen | ADR relacionados |
|---|---|---|---|
| 2.1 | 2026-10-27 | Sincronización documental v2.1: Incorporación de casos de uso CU-13 a CU-18 cubriendo registro local con verificación, validación de código, reenvío, federación Google, recuperación de contraseñas y depuración automática por TTL. Actualización de CU-02 (rechazo de pendientes y revocación por iat) y CU-10 (reautenticación y anonimización O12). Reclasificación de I3 e I4 como diferidos. Incorporación formal del estado de verificación CoVE tras v2.1. | ADR #51 a #68 |
