# Reglas de negocio AntFish v2.1

> **Documento Canónico de Reglas de Negocio (v2.1).** Define la totalidad de las reglas operativas, de scoring, privacidad y autenticación de AntFish. La implementación técnica se rige por `docs/CONTEXTO_AntFish_V2.md`, las Decisiones Técnicas y de Arquitectura (ADR #51 a #68) y el modelo de datos NoSQL `docs/MODELADO-AGENTS/antfish_modelo_nosql.json`. Todas las convenciones de identificadores, colecciones y enums se establecen en minúsculas conforme a la arquitectura en capas aprobada.

---

## 1. Evaluación y Cálculo de Puntuación (Scoring Engine)

* **RN-01 (Techo de Puntuación):** La puntuación total asignada a un análisis se encuentra estrictamente dentro del rango de 0 a 100 puntos, calculada mediante la fórmula:
  $$\text{score} = \min(100, \text{puntos\_apis} + \text{puntos\_url} + \text{puntos\_texto})$$
* **RN-02 (Cortocircuito y Clasificación Crítica):** Si un dominio da positivo en Google Web Risk o PhishTank, o si la URL intenta suplantar directamente una entidad de `marcas_protegidas`, se activa la regla de cortocircuito asignando `motivo_cortocircuito` (`"lista_negra"` o `"suplantacion_marca"`; prevaleciendo `"lista_negra"` si ambas aplican) y clasificando el resultado en nivel `critico`:
  * *Listas negras:* $\text{score} = \min(100, 95 + \min(5, (\text{puntos\_url} + \text{puntos\_texto}) // 10))$.
  * *Suplantación directa de marca:* $\text{score} = \max(\text{score}, 80)$.
* **RN-03 (Límite por Capa de Inteligencia Externa):** La Capa 1 aporta un máximo acumulable de 60 puntos (`puntos_apis = min(60, suma_capa1)`), salvo aplicación de cortocircuito por listas negras:
  * Google Web Risk (positivo): +50 pts (`API_GOOGLE_WEB_RISK`).
  * PhishTank (positivo): +50 pts (`API_PHISHTANK`).
  * VirusTotal con $\ge 3$ detecciones: +40 pts (`API_VIRUSTOTAL_3_MAS`).
  * VirusTotal con 1 a 2 detecciones: +20 pts (`API_VIRUSTOTAL_1_2`).
* **RN-04 (Límite por Capa Heurística de URL):** La Capa 2 aporta un máximo acumulable de 30 puntos (`puntos_url = min(30, suma_capa2)`):
  * IP directa en lugar de nombre de dominio: +20 pts (`URL_IP_DIRECTA`).
  * Subdominio engañoso o impersonación: +20 pts (`URL_SUBDOMINIO_ENGANOSO`).
  * TLD de alto riesgo (.xyz, .top, .tk): +15 pts (`URL_TLD_ALTO_RIESGO`).
  * Uso de acortador de enlaces (bit.ly, tinyurl): +10 pts (`URL_ACORTADOR`).
  * Exceso de guiones o palabras clave encadenadas: +10 pts (`URL_EXCESO_GUIONES`).
* **RN-05 (Límite por Capa Heurística de Texto):** La Capa 3 aporta un máximo acumulable de 20 puntos (`puntos_texto = min(20, suma_capa3)`):
  * Lenguaje de urgencia o amenaza: +10 pts (`TXT_LENGUAJE_URGENCIA`).
  * Solicitud de datos sensibles o acciones financieras: +10 pts (`TXT_SOLICITUD_DATOS`).
  * Uso de leetspeak u ofuscación de caracteres: +5 pts (`TXT_LEETSPEAK`).

---

## 2. Clasificación de Riesgo y Visualización (Semáforo)

* **RN-06 (Clasificación Riesgo Bajo - Verde):** Todo análisis con puntuación entre 0 y 19 puntos se clasifica como `bajo` y se representa con semáforo verde 🟢.
* **RN-07 (Clasificación Riesgo Medio - Amarillo):** Todo análisis con puntuación entre 20 y 49 puntos se clasifica como `medio` y se representa con semáforo amarillo 🟡.
* **RN-08 (Clasificación Riesgo Alto - Naranja):** Todo análisis con puntuación entre 50 y 79 puntos se clasifica como `alto` y se representa con semáforo naranja 🟠.
* **RN-09 (Clasificación Riesgo Crítico - Rojo):** Todo análisis con puntuación entre 80 y 100 puntos se clasifica como `critico` y se representa con semáforo rojo 🔴.

---

## 3. Tratamiento y Normalización de Entradas

* **RN-10 (Procesamiento de SMS):** Al analizar un mensaje SMS (`tipo_entrada: "sms"`), el motor procesa el texto completo en memoria RAM (Capa 3), extrae todas las URLs detectadas, aplica heurísticas sintácticas (Capa 2) a cada una y selecciona las 2 URLs de mayor riesgo sintáctico (empate: por orden de aparición en el texto). La URL con mayor riesgo combinado (APIs + Sintaxis) se selecciona como la URL dominante para determinar el diagnóstico global.
* **RN-11 (Procesamiento de URLs / Correos):** Si la entrada es únicamente una URL (`tipo_entrada: "url"`), se omiten las reglas de texto (Capa 3) y la evaluación se realiza exclusivamente sobre las Capas 1 y 2, persistiendo `mensaje_hash: null`.

---

## 4. Caché, Optimización y Resiliencia

* **RN-12 (Prioridad de Caché sobre APIs):** Antes de consumir cuota de Google Web Risk, VirusTotal o PhishTank, el sistema consulta en Redis la clave `rep:{url_normalizada}` (URL con path, sin query string, fragmento ni userinfo). Se almacena en caché con TTL de 3,600 s únicamente si las 3 APIs de reputación respondieron exitosamente (`ok`).
* **RN-13 (Degradación Grácil):** Si una API externa no responde (timeout de 1.5 s), devuelve error o agota su cuota local, el motor marca `analisis_parcial: true`, no persiste el resultado en Redis y calcula el riesgo con las fuentes disponibles y las heurísticas sintácticas/texto.

---

## 5. Privacidad y Métricas

* **RN-14 (Minimización de Datos y Privacidad de SMS):** El texto plano del SMS analizado nunca se almacena en base de datos ni se escribe en logs. Se procesa en memoria RAM y se persiste únicamente un digesto `mensaje_hash` generado mediante HMAC-SHA256 con una clave secreta del servidor (`HMAC_PEPPER`), junto con el arreglo de `urls_extraidas` (máximo 2, normalizadas sin query string).
* **RN-15 (Criterio de Amenaza Bloqueada):** Un escaneo incrementa de forma atómica (`$inc`) el contador de `amenazas_bloqueadas` en `metricas_usuario` si y solo si el diagnóstico final califica en riesgo `alto` (50 a 79 pts) o `critico` (80 a 100 pts), ejecutado dentro de una transacción ACID en MongoDB.

---

## 6. Autenticación, Usuarios y Ciclo de Vida

* **RN-16 (Verificación Obligatoria de Cuenta Local):** Una cuenta creada con método `local` nace en `estado_cuenta = "pendiente_verificacion"` con `email_verificado = false`. El inicio de sesión (`POST /auth/login`) valida la contraseña y retorna HTTP 403 Forbidden con código `ACCOUNT_NOT_VERIFIED` solo tras validar que la contraseña es matemáticamente correcta. No puede acceder a endpoints protegidos hasta validar el código de 6 dígitos vía Resend (vigencia 10 min).
* **RN-17 (Límite de Intentos por Código):** Máximo 5 intentos por código en `verif:{user_id}`; al quinto fallo consecutivo, la clave se destruye en Redis y se debe solicitar un nuevo código.
* **RN-18 (Límite de Reenvíos y Vinculación Google sobre Cuenta Activa):** Máximo 3 solicitudes por hora por usuario compartidas en `reenvio:{user_id}` para reenvío y recuperación. Si un usuario con cuenta local ya activa inicia sesión con Google con el mismo correo y Google certifica `email_verified = true`, se vincula la cuenta añadiendo `google_sub` sin alterar `proveedor_auth = "local"` y preservando `password_hash`. Si el correo en Google no está verificado, se rechaza con HTTP 409 Conflict.
* **RN-19 (Activación Inmediata de Cuentas Google):** Cuentas registradas vía Google Sign-In nacen directamente en `estado_cuenta = "activa"`, `email_verificado = true` y `password_hash = null`, sin requerir envío de correo de verificación.
* **RN-20 (Depuración Física de Cuentas No Verificadas por TTL):** Cuentas en `pendiente_verificacion` que superen 48 horas desde su creación se eliminan físicamente de MongoDB mediante el índice TTL parcial I11 (`{ fecha_registro: 1 }`, `expireAfterSeconds: 172800`, `partialFilterExpression: { estado_cuenta: "pendiente_verificacion" }`), sin necesidad de tareas programadas ni schedulers externos. Cuentas no verificadas nunca generan métricas ni análisis.
* **RN-21 (Reautenticación para Borrado de Cuenta):** El borrado de cuenta (`DELETE /auth/me`) exige reautenticación en el body: `{ "password": "..." }` para cuentas locales, o `{ "id_token": "..." }` reciente de Google validado contra `google_sub` para cuentas Google o vinculadas.
* **RN-22 (Recuperación de Contraseña y Revocación de Sesiones):** El restablecimiento de contraseña en `POST /auth/password/reset` actualiza `password_hash` y registra la marca temporal `password_changed_at`. Tanto el acceso JWT en `deps.py` como la renovación en `POST /auth/refresh` comparan el claim `iat` contra `password_changed_at`; si `iat` es anterior, el token se rechaza de inmediato con HTTP 401 Unauthorized.
* **RN-23 (Registro sobre Cuenta en Pendiente de Verificación):** Si en `POST /auth/register` el email ya existe en `estado_cuenta == "pendiente_verificacion"`, se sobrescriben `nombre` y `password_hash`, se emite un nuevo código numérico (contabilizado contra `reenvio:{user_id}`) y se reinicia `fecha_registro` a la fecha actual [SUPUESTO por confirmar]. Si la cuenta ya se encuentra activa o suspendida, responde HTTP 409 Conflict (riesgo aceptado de enumeración).
* **RN-24 (Vinculación Google sobre Cuenta en Pendiente de Verificación):** Si un usuario inicia sesión con Google sobre una cuenta preexistente en `pendiente_verificacion` y Google certifica `email_verified = true`, se descarta cualquier `password_hash` previo (`null`), la cuenta transiciona a `activa`, `email_verificado = true`, `fecha_verificacion = ahora`, `password_changed_at = ahora` y `proveedor_auth = "google"` [SUPUESTO por confirmar], evitando el secuestro previo de cuentas.
* **RN-25 (Respuestas Uniformes contra Enumeración):** Los endpoints `POST /auth/password/forgot`, `POST /auth/verify-email` y `POST /auth/password/reset` responden de manera uniforme e indistinguible exista o no el correo registrado, evitando que actores externos infieran la existencia de cuentas.
* **RN-26 (Anonimización Completa en Baja de Cuenta):** Al ejecutarse `DELETE /auth/me`, se purgan en cascada bajo transacción ACID los registros de `analisis`, `metricas_usuario` y `respuestas_apis`. El documento en `usuarios` se preserva anonimizado: `email = "deleted_<id>@deleted.local"`, `password_hash = null`, `google_sub = null`, `nombre = null`, `email_verificado = false`, `estado_cuenta = "eliminada"` y `fecha_eliminacion = ahora`.

---

## 7. Integridad de Reglas: MongoDB vs. Aplicación (FastAPI)

En la arquitectura de AntFish, la responsabilidad se divide según el principio de defensa en profundidad: **MongoDB** garantiza la **consistencia estructural, rangos e invariantes de datos persistidos** mediante validadores de esquema e índices, mientras que la **aplicación (FastAPI + engine)** orquesta la **lógica algorítmica, heurísticas, llamadas a terceros y políticas de privacidad**.

### Integridades garantizadas por MongoDB (`$jsonSchema` + `$expr`)

MongoDB actúa como la última línea de defensa. No evalúa la fórmula compleja de scoring de `engine/`, pero valida mediante `$jsonSchema` y `$expr` las siguientes coherencias relacionales (D9, ADR #59) bajo nivel de validación estricto (`validationLevel: "strict"`, `validationAction: "error"`):

1. **Rango de Puntuación (RN-01):** `0 <= score_total <= 100`.
2. **Coherencia Score y Nivel de Riesgo (RN-06 a RN-09):**
   * `bajo` $\iff 0 \le \text{score\_total} \le 19$.
   * `medio` $\iff 20 \le \text{score\_total} \le 49$.
   * `alto` $\iff 50 \le \text{score\_total} \le 79$.
   * `critico` $\iff 80 \le \text{score\_total} \le 100$.
3. **Coherencia de Cortocircuito (RN-02):**
   * `motivo_cortocircuito == "lista_negra"` $\implies \text{score\_total} \ge 95$.
   * `motivo_cortocircuito == "suplantacion_marca"` $\implies \text{score\_total} \ge 80$.
4. **Tipado e Integridad de Entrada (RN-10, RN-11, RN-14):**
   * `tipo_entrada == "sms"` $\implies \text{mensaje\_hash}$ obligatorio de 64 caracteres hexadecimales.
   * `tipo_entrada == "url"` $\implies \text{mensaje\_hash} == \text{null}$.
5. **Topes por Capa en Snapshot (RN-03 a RN-05):**
   * `0 <= puntos_por_capa.apis <= 60`.
   * `0 <= puntos_por_capa.url <= 30`.
   * `0 <= puntos_por_capa.texto <= 20`.
6. **Invariantes de Métricas (RN-15):**
   * `total_escaneos == total_url + total_sms`.
   * `amenazas_bloqueadas <= total_escaneos`.
   * Todos los contadores $\ge 0$.
7. **Invariantes de Estado de Cuenta (RN-16, RN-19, RN-26):**
   * `proveedor_auth == "local"` $\implies \text{password\_hash}$ obligatorio, salvo si `estado_cuenta == "eliminada"`.
   * `proveedor_auth == "google"` $\implies \text{google\_sub}$ obligatorio, salvo si `estado_cuenta == "eliminada"`.
   * `estado_cuenta == "activa"` $\implies \text{email\_verificado} == \text{true}$.
   * `estado_cuenta == "pendiente_verificacion"` $\implies \text{email\_verificado} == \text{false}$.
   * `estado_cuenta == "eliminada"` $\implies \text{nombre} == \text{null}$, $\text{password\_hash} == \text{null}$, $\text{google\_sub} == \text{null}$ y $\text{fecha\_eliminacion}$ presente.
8. **Ciclo de Vida Automático (RN-20):** Purga física desatendida de cuentas no verificadas a las 48 h mediante índice TTL parcial I11.

### Integridades garantizadas por la Aplicación (FastAPI / Engine)

La aplicación asume el procesamiento en memoria, evaluación heurística y comunicaciones de red:

1. **Scoring y Algoritmos Heurísticos (RN-01 a RN-05, RN-10):** Normalización de URLs, evaluación sintáctica de dominios, detección de leetspeak, cálculo de la URL dominante y cómputo matemático de la fórmula de puntuación.
2. **Privacidad de SMS y Claves (RN-14, RN-17, RN-25):** Sanitización de URLs (remoción de query parameters), destrucción de texto plano en memoria RAM, generación de digestos HMAC-SHA256 con `HMAC_PEPPER` y respuestas uniformes anti-enumeración.
3. **Orquestación de Caché y Terceros (RN-12, RN-13):** Consulta preliminar de Redis (`rep:{url_normalizada}`), consultas paralelas con timeout (`asyncio.gather`), control dual de cuotas y activación de degradación grácil (`analisis_parcial: true`).
4. **Flujos Criptográficos y de Sesión (RN-16, RN-18, RN-21 a RN-24):** Verificación de Argon2id, validación de Google ID Token con `google-auth`, emisión y revocación de tokens JWT mediante `iat` contra `password_changed_at`.

### Matriz de Responsabilidad

| Regla | Responsable | Mecanismo |
|---|---|---|
| **RN-01** (Puntaje 0-100) | Ambos | App calcula; Mongo `$jsonSchema` (0-100). |
| **RN-02** (Cortocircuito) | Ambos | App evalúa override y causa; Mongo `$expr` valida piso de score según motivo. |
| **RN-03 a RN-05** (Límites por capa) | Ambos | App aplica `min()` en memoria; Mongo valida topes numéricos en `puntos_por_capa`. |
| **RN-06 a RN-09** (Nivel de riesgo) | Ambos | App mapea score $\to$ nivel; Mongo valida coherencia de rangos con `$expr`. |
| **RN-10** (URLs en SMS) | Aplicación | `engine/url_extractor.py` y `url_heuristics.py` seleccionan las 2 URLs más riesgosas. |
| **RN-11** (URL pura) | Ambos | App omite Capa 3; Mongo exige `mensaje_hash == null`. |
| **RN-12, RN-13** (Caché y resiliencia) | Aplicación | `AnalysisService` maneja Redis `rep:{url_normalizada}`, timeouts y degradación grácil. |
| **RN-14** (Privacidad SMS) | Ambos | App destruye SMS y calcula HMAC; Mongo `$jsonSchema` valida regex de 64 hex. |
| **RN-15** (Métricas de amenaza) | Ambos | App detecta $\ge 50$ pts; Mongo ejecuta `$inc` atómico y valida invariantes de suma. |
| **RN-16** (Verificación obligatoria) | Ambos | App valida contraseña antes de emitir 403; Mongo valida enum `estado_cuenta`. |
| **RN-17** (Límite 5 intentos) | Aplicación | `VerificationService` incrementa y destruye la clave `verif:{user_id}` en Redis. |
| **RN-18** (Límite de reenvíos) | Ambos | App aplica rate limit en Redis (`reenvio:{user_id}`); Mongo garantiza unicidad I1 e I10. |
| **RN-19** (Activación Google) | Ambos | App valida token con `google-auth`; Mongo valida obligatoriedad de campos. |
| **RN-20** (Purga cuentas pendientes) | MongoDB | Índice TTL parcial I11 elimina cuentas pendientes con `fecha_registro > 48h`. |
| **RN-21** (Reautenticación borrado) | Aplicación | `AuthService` valida Argon2id o token Google antes de ejecutar la transacción ACID. |
| **RN-22** (Revocación sesiones) | Ambos | App contrasta `iat` contra `password_changed_at`; Mongo persiste la marca temporal. |
| **RN-23** (Registro sobre pendiente) | Ambos | App sobrescribe datos y reinicia fecha; Mongo valida unicidad I1 y esquema. |
| **RN-24** (Vinculación Google) | Ambos | App valida identidad federada; Mongo actualiza campos y desmarca password_hash. |
| **RN-25** (Respuestas uniformes) | Aplicación | Controladores HTTP devuelven respuestas y códigos indistinguibles. |
| **RN-26** (Anonimización O12) | Ambos | App ejecuta transacción de cascada; Mongo valida nulos condicionales con `$expr`. |

---

## Historial de cambios

| Versión | Fecha | Resumen | ADR relacionados |
|---|---|---|---|
| 2.1 | 2026-10-27 | Sincronización documental v2.1: Reescritura integral del documento eliminando borradores históricos desactualizados. Incorporación canónica de RN-01 a RN-26 en minúsculas, alineadas con antfish_modelo_nosql.json. Incorporación de validaciones estructurales de MongoDB ($jsonSchema + $expr), depuración desatendida vía índice TTL I11, anonimización completa (O12), revocación de sesiones por iat/password_changed_at y respuestas uniformes anti-enumeración. | ADR #51 a #68 |
