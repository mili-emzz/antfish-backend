# AntFish: Contexto, Requerimientos y Arquitectura

> **Fuente de verdad del proyecto (Versión 2.1).** Las secciones 1 a 8 corresponden al levantamiento de requerimientos original (con aclaraciones de implementación e integración de decisiones confirmadas). Las secciones 9 a 11 detallan la arquitectura backend y las decisiones de diseño resueltas.
> Modelo de datos detallado: `antfish_modelo_nosql.json`.

---

## 1. Nombre del Proyecto

**AntFish**

## 2. Planteamiento del Problema

### Contexto Actual

El phishing y el smishing son problemáticas críticas de la seguridad informática: técnicas con las que los ciberdelincuentes engañan a las personas mediante enlaces y mensajes fraudulentos. El phishing llega comúnmente por correo electrónico con enlaces a páginas falsas; el smishing usa mensajes SMS para suplantar bancos, empresas de paquetería, servicios digitales y otras organizaciones.

Estas técnicas buscan que las víctimas accedan a sitios maliciosos, entreguen información personal o credenciales, o realicen acciones que comprometan su seguridad. Existen herramientas que verifican la reputación de enlaces, pero los usuarios no siempre cuentan con una forma sencilla e inmediata de analizar lo que reciben. Esto abre la oportunidad de una aplicación móvil que combine un motor propio de detección sintáctica/heurística con servicios externos de inteligencia de amenazas.

### Justificación

El phishing y el smishing aprovechan la confianza, la urgencia y la falta de herramientas de verificación rápida para facilitar el robo de información y los fraudes financieros. Una persona puede recibir un mensaje que parece venir de una organización legítima y acceder a un enlace fraudulento sin identificar el riesgo.

### Impacto Esperado

* **Reducción del riesgo del usuario final:** herramienta accesible e intuitiva que evalúa enlaces y mensajes en segundos, antes de que el usuario interactúe con ellos.
* **Mitigación de fraudes financieros y robo de identidad:** disminuir la tasa de éxito de campañas de phishing y smishing.
* **Educación y concientización:** explicar los motivos concretos por los que un mensaje o URL es peligroso (lenguaje de urgencia, reputación negativa del dominio, solicitud de información confidencial).

## 3. Objetivos

### Objetivo General

Desarrollar una aplicación móvil multiplataforma respaldada por una API REST en Python (FastAPI) que permita analizar el contenido de mensajes SMS y URLs sospechosas mediante un motor heurístico propio y servicios externos de inteligencia de amenazas (Google Web Risk, VirusTotal y PhishTank), determinando y visualizando el nivel de riesgo en tiempo real.

### Objetivos Específicos

1. **Arquitectura del backend y motor de análisis:** backend asíncrono en Python (FastAPI) que procese SMS y URLs con reglas heurísticas (patrones de urgencia, extracción sintáctica de enlaces) y ejecute consultas en paralelo a APIs externas.
2. **Rendimiento y caché:** almacenar en caché las reputaciones de dominios ya analizados (únicamente tras una consulta exitosa de todas las fuentes externas), reduciendo el tiempo de respuesta y optimizando la cuota de peticiones a servicios externos.
3. **Métricas y estadísticas de escaneo:** contabilizar de forma atómica el volumen de análisis por usuario, distinguiendo URLs y SMS, e identificando las amenazas bloqueadas.
4. **Aplicación móvil multiplataforma:** interfaz que permita entrada manual o directa mediante la función nativa "Compartir", presentando el diagnóstico con semáforo de riesgo, hallazgos clave y recomendaciones.
5. **Autenticación, seguridad y pruebas de rendimiento:** arquitectura de acceso dual que soporte autenticación con Google (Google Sign-In) y registro/acceso local con verificación de correo mediante código de 6 dígitos vía Resend; auditoría de seguridad de la API mediante JWT (Access y Refresh Tokens), comunicaciones cifradas sobre HTTPS y pruebas de esfuerzo para validar tiempos de respuesta bajos.

## 4. Stack Tecnológico Seleccionado

* **Frontend móvil:** Flutter (Dart). Una sola base de código para Android e iOS, con SDK de Google Sign-In.
* **Backend y API REST:** Python con FastAPI. Procesamiento asíncrono (`asyncio`) para consultar varias APIs de inteligencia en paralelo y librería `google-auth` para validación criptográfica de Google ID Tokens.
* **Servicio de correo transaccional:** Resend (API HTTP consumida de forma asíncrona mediante `httpx.AsyncClient`) para entrega de códigos de verificación y recuperación.
* **Base de datos y caché:** MongoDB (NoSQL) para respuestas complejas en JSON y Redis para caché de reputación por URL normalizada, control de cuota dual y almacenamiento efímero de códigos de verificación/control de reenvíos.
* **Infraestructura y seguridad:** Docker, autenticación JWT (Access + Refresh Tokens), contraseñas con Argon2id, HMAC-SHA256 para protección de SMS y códigos de verificación, y cifrado obligatorio HTTPS/TLS en todas las comunicaciones.

## 5. Heurísticas y Sistema de Puntuación

### Arquitectura de Evaluación (score de 0 a 100)

El riesgo se calcula combinando tres capas de análisis en el motor Python:

$$\text{PuntuaciónTotal} = \min(100, \text{Puntos\_APIs} + \text{Puntos\_URL} + \text{Puntos\_Texto})$$

#### Capa 1: Inteligencia Externa / Listas Negras (máx. 60 pts)

* **Google Web Risk (positivo):** +50 pts.
* **PhishTank (positivo):** +50 pts.
* **VirusTotal ($\ge 3$ detecciones):** +40 pts.
* **VirusTotal (1 a 2 detecciones):** +20 pts.
* **Regla de cortocircuito por listas negras:** si Google Web Risk o PhishTank confirman amenaza, la puntuación escala automáticamente a un rango de **95-100 pts (Crítico)**.

#### Capa 2: Heurística Sintáctica de URL (máx. 30 pts)

* **IP directa en la URL:** +20 pts.
* **Subdominio engañoso o impersonación de marca:** +20 pts.
* **TLD de alto riesgo (.xyz, .top, .tk):** +15 pts.
* **Acortadores de enlaces (bit.ly, tinyurl):** +10 pts.
* **Exceso de guiones o palabras clave encadenadas:** +10 pts.
* **Regla de cortocircuito por suplantación directa de marca:** si la URL intenta suplantar directamente una marca registrada en `marcas_protegidas`, se activa un cortocircuito sintáctico que fija el piso mínimo del análisis en **80 a 100 pts (Riesgo Crítico)**.

#### Capa 3: Heurística de Texto y SMS (máx. 20 pts)

* **Lenguaje de urgencia o amenaza ("bloqueada", "inmediato", "suspensión"):** +10 pts.
* **Solicitud de datos personales o acciones financieras ("verifica tu PIN", "cancela cargo"):** +10 pts.
* **Ofuscación de caracteres o leetspeak ("b4nco", "p4yp4l"):** +5 pts.

#### Reglas de consolidación e implementación

```text
puntos_apis  = min(60, suma_reglas_capa1)
puntos_url   = min(30, suma_reglas_capa2)
puntos_texto = min(20, suma_reglas_capa3)

score = min(100, puntos_apis + puntos_url + puntos_texto)

# Cortocircuito por listas negras (Web Risk o PhishTank positivo):
score = min(100, 95 + min(5, (puntos_url + puntos_texto) // 10))

# Cortocircuito por suplantación directa de marca:
score = max(score, 80)
```

* Sin cortocircuito el máximo teórico es $60 + 30 + 20 = 110$, por lo que el $\min(100, \dots)$ externo garantiza el rango válido.
* Si un mensaje contiene múltiples URLs (hasta un límite estricto de **2 URLs**), se analiza cada enlace de forma independiente y se selecciona la **URL con el mayor riesgo dominante** para alimentar las Capas 1 y 2.
* Los `hallazgos` guardan los puntos originales de cada regla; `puntos_por_capa` guarda los puntos ya recortados.
* Cuando la entrada es `url` (o correo), la Capa 3 se omite.

### Escala de Riesgo y Semáforo Visual

* 🟢 **0 a 19 pts, RIESGO BAJO:** sin patrones sospechosos ni reportes en listas negras.
* 🟡 **20 a 49 pts, RIESGO MEDIO:** patrones leves (acortadores, lenguaje de urgencia), sin reputación negativa.
* 🟠 **50 a 79 pts, RIESGO ALTO:** múltiples reglas de suplantación sintáctica o reporte menor en motores antivirus.
* 🔴 **80 a 100 pts, RIESGO CRÍTICO:** confirmación en listas negras o imitación directa de marca legítima.

## 6. Flujos del Sistema y Procesamiento de Información

### Flujo General de la Aplicación

```text
[ USUARIO ]
     │
     ├───► [ Ingrese URL ] ──────────┐
     │                               │
     └───► [ Ingrese Texto / SMS ] ──┴──► [ API REST (FastAPI) ]
                                                │
                                                ▼
                                      [ Motor de Análisis ]
                                                │
                                ┌───────────────┼───────────────┐
                                ▼               ▼               ▼
                            [ Dominio ]    [ Contenido ]   [ Reputación ]
                                └───────────────┬───────────────┘
                                                │
                                                ▼
                                      [ Nivel de Riesgo ]
                                                │
                                                ▼
                                [ Semáforo Visual (🟢🟡🟠🔴) ]
```

### Flujo Detallado de Análisis de SMS / Phishing

```text
[ SMS Recibido / URL de Correo ]
               │
               ▼
       [ App Móvil Android / iOS ]
               │
               ▼
       [ API REST Propia (FastAPI) ]
               │
               ▼
  ┌───────────────────────────────────────────────┐
  │ Motor de Análisis (Python)                    │
  │  • Análisis del texto                         │
  │  • Extracción de URLs (máximo 2)              │
  │  • Análisis sintáctico y reglas de smishing   │
  │  • Reputación de URL de mayor riesgo          │
  └──────────────────────┬────────────────────────┘
                         │
                         ▼
  ┌───────────────────────────────────────────────┐
  │ Consultas a APIs Externas                     │
  │  ├─ Google Web Risk                           │
  │  ├─ VirusTotal                                │
  │  └─ PhishTank                                 │
  └──────────────────────┬────────────────────────┘
                         │
                         ▼
              [ Motor de Puntuación ]
                         │
                         ▼
        [ Retorno de Diagnóstico a la App ]
```

### Ejemplo de Estructura del Resultado Retornado al Usuario

```text
RIESGO: CRÍTICO
Puntuación: 90/100

🔗 URL sospechosa
   El dominio imita la marca legítima 'BBVA' y tiene reputación negativa.

⚠️ Lenguaje de urgencia
   El mensaje intenta provocar una acción inmediata de suspensión.

⚠️ Solicitud de información
   Solicita datos personales mediante un enlace.

🛡️ Recomendación
   No accedas al enlace, no compartas datos personales ni credenciales de acceso.
```

### Diferenciación por Tipo de Entrada

* **Correos electrónicos:** el análisis se enfoca en la extracción sintáctica y verificación de reputación de la **URL contenida** en el mensaje.
* **Mensajes SMS:** se analiza el **contenido del texto completo** (urgencia, ofuscación, solicitudes de información sensible) combinado con la verificación de las URLs extraídas (máx. 2).

## 7. Requerimientos Funcionales (RF)

* **RF-01: Recepción de entradas (nativa y manual)**
  * **RF-01.1:** la aplicación debe permitir pegar manualmente texto SMS o URLs en la interfaz.
  * **RF-01.2:** la aplicación debe integrarse con el menú nativo "Compartir" de Android e iOS para recibir enlaces o textos desde otras apps.
* **RF-02: Motor de análisis combinado**
  * **RF-02.1:** el backend debe extraer sintácticamente todas las URLs contenidas en el mensaje en memoria RAM, evaluar la heurística sintáctica (Capa 2) a cada una y seleccionar las **2 URLs de mayor riesgo sintáctico** (en caso de empate, por orden de aparición en el texto).
  * **RF-02.2:** el backend debe ejecutar en paralelo las consultas a Google Web Risk, VirusTotal y PhishTank mediante el cliente asíncrono (`asyncio`).
  * **RF-02.3:** el backend debe evaluar las reglas heurísticas sintácticas de la URL (IP directa, TLDs de alto riesgo, subdominios engañosos, acortadores).
  * **RF-02.4:** el backend debe analizar el texto buscando lenguaje de urgencia, patrones de suplantación de identidad (leetspeak) y solicitudes de información sensible.
* **RF-03: Asignación de riesgo y diagnóstico**
  * **RF-03.1:** el sistema debe calcular la puntuación total e invocar los cortocircuitos correspondientes (escalar a 95-100 pts si el dominio está en listas negras o $\ge 80$ pts si hay suplantación directa de marca).
  * **RF-03.2:** la app debe renderizar el resultado con el semáforo visual (Verde, Amarillo, Naranja, Rojo) según la puntuación.
  * **RF-03.3:** el diagnóstico debe incluir la lista desglosada de hallazgos, `puntos_por_capa` y `fuentes_consultadas` correspondientes a la URL dominante (la URL secundaria conserva sus alertas sintácticas en `urls_extraidas[].flags_sintacticos`), junto con recomendaciones de acción concretas.
* **RF-04: Caché y rendimiento de consultas**
  * **RF-04.1:** el backend debe consultar Redis (`rep:{url_normalizada}`, URL con path y sin query string, fragmento ni userinfo) antes de consumir las APIs externas, para verificar si la URL fue analizada recientemente dentro del TTL definido (3600 segundos).
  * **RF-04.2:** ante un *cache hit* se devuelven los resultados de reputación sin consumir cuota de las APIs.
  * **RF-04.3:** se almacenará el resultado en caché Redis únicamente si las 3 APIs externas respondieron con éxito total (`ok`), evitando almacenar respuestas parciales.
* **RF-05: Métricas y panel del usuario**
  * **RF-05.1:** el sistema debe almacenar el historial de análisis de cada usuario autenticado.
  * **RF-05.2:** la interfaz debe mostrar un panel con escaneos totales, desglose entre SMS y URLs, y cantidad de amenazas bloqueadas.
* **RF-06: Autenticación y cuenta**
  * **RF-06.1: Registro con correo y contraseña.** El sistema debe permitir el registro de usuarios locales mediante correo electrónico (normalizado a minúsculas y sin espacios, D5), contraseña y nombre (`proveedor_auth = "local"`). La contraseña se hashea con Argon2id (`password_hash`). La cuenta se crea inicialmente en `estado_cuenta = "pendiente_verificacion"` con `email_verificado = false` y `fecha_verificacion = null`. Si el correo ya existe en estado `pendiente_verificacion`, se sobrescriben nombre y contraseña, se genera nuevo código y se reinicia `fecha_registro` [SUPUESTO por confirmar, D14]; si la cuenta ya está activa o suspendida, se responde HTTP 409 Conflict (riesgo aceptado de enumeración).
  * **RF-06.2: Verificación de correo mediante código de 6 dígitos (Resend).** El sistema debe verificar el código ingresado en `POST /api/v1/auth/verify-email` recibiendo `{email, codigo}` y resolviendo el `user_id` internamente (D17). El código tiene una vigencia estricta de 10 minutos y un límite de hasta 5 intentos. El código se almacena hasheado (HMAC-SHA256 con `HMAC_PEPPER`) en Redis (`verif:{user_id}`, TTL 600 s) con política *fail-closed*. Al validarse correctamente, la cuenta pasa a `estado_cuenta = "activa"`, `email_verificado = true` y `fecha_verificacion = ISODate`. Ante un correo inexistente o código inválido, responde de forma uniforme (RN-25).
  * **RF-06.3: Reenvío de código con límite.** El sistema debe permitir solicitar un nuevo código de verificación en `POST /api/v1/auth/resend-code`, aplicando un límite estricto de máximo 3 solicitudes por hora por usuario compartido en Redis (`reenvio:{user_id}`, TTL 3600 s; D17). Cada reenvío invalida el código anterior y restablece el contador de intentos.
  * **RF-06.4: Login con Google.** La app móvil obtiene un ID token a través del SDK de Google Sign-In para Flutter y lo envía al backend en `POST /api/v1/auth/google`. El backend valida el token mediante la librería `google-auth` (verificando firma, expiración, `aud = GOOGLE_CLIENT_ID` y `email_verified = true`). Si el usuario no existe, se crea con `proveedor_auth = "google"`, `google_sub`, `password_hash = null`, `estado_cuenta = "activa"` y `email_verificado = true`. Luego emite tokens propios (Access y Refresh). El backend nunca almacena el ID token de Google.
  * **RF-06.5: Vinculación de cuenta por correo verificado.** Si un usuario inicia sesión con Google con un correo que ya existe en `pendiente_verificacion` y Google certifica `email_verified = true`, se descarta cualquier `password_hash` previo (`null`), transicionando a `activa`, `email_verificado = true`, `fecha_verificacion = ahora`, `password_changed_at = ahora` y `proveedor_auth = "google"` [SUPUESTO por confirmar, D13]. Si la cuenta local ya estaba activa, se vincula añadiendo `google_sub`, conservando `proveedor_auth = "local"` y preservando `password_hash`. Si el correo en Google no está verificado, se rechaza con HTTP 409 Conflict.
  * **RF-06.6: Recuperación de contraseña por código.** `POST /api/v1/auth/password/forgot` responde siempre HTTP 200 con mensaje uniforme exista o no el correo (D16); solo emite código vía Resend si la cuenta existe, está activa y tiene `password_hash` (comparte el límite de `reenvio:{user_id}`). El cambio se completa en `POST /api/v1/auth/password/reset` recibiendo `{email, codigo, nueva_password}` con Argon2id (D17). Tras un reset exitoso, se actualiza `password_changed_at` en `usuarios`, invalidando de inmediato todos los Access y Refresh Tokens previos (D18).
  * **RF-06.7: Borrado de cuenta con reautenticación según método.** El endpoint `DELETE /api/v1/auth/me` exige reautenticación en el body: `{ "password": "..." }` si es `local`, o `{ "id_token": "..." }` validado contra `google_sub` si es `google` o vinculada. Tras validar, anonimiza el documento en `usuarios` (`email = "deleted_<id>@deleted.local"`, nulos en `password_hash`, `google_sub`, `nombre`, `email_verificado = false`, `estado_cuenta = "eliminada"`, `fecha_eliminacion = ahora`) y purga en cascada bajo transacción ACID las colecciones `analisis`, `metricas_usuario` y `respuestas_apis` (D4).
  * **RF-06.8: Bloqueo de acceso a cuentas no verificadas.** En `POST /api/v1/auth/login`, la validación de contraseña con Argon2id se ejecuta antes de comprobar el estado; responde HTTP 403 Forbidden con `ACCOUNT_NOT_VERIFIED` solo tras validar contraseña válida en cuenta pendiente; credenciales inválidas devuelven HTTP 401 genérico (D12). Las cuentas en `pendiente_verificacion` con más de 48 horas desde su creación se eliminan físicamente de forma automática en MongoDB mediante el índice TTL parcial I11 sobre `fecha_registro`, sin tareas programadas ni schedulers externos (D15).

## 8. Requerimientos No Funcionales (RNF)

* **RNF-01: Latencia.** El tiempo total desde que el usuario envía la solicitud hasta que recibe la respuesta visual no debe superar **2.5 segundos** en el 95% de los casos (ejecución asíncrona y caché).
* **RNF-02: Disponibilidad y tolerancia a fallos (degradación grácil).** Si una API externa no responde o alcanza su *rate-limit*, el motor continúa el cálculo con las APIs disponibles y las heurísticas internas, marcando `analisis_parcial: true` sin interrumpir el servicio.
* **RNF-03: Seguridad y privacidad (Privacy by Design).**
  * Todas las comunicaciones cifradas con HTTPS/TLS.
  * Autenticación y autorización entre la app y el API REST vía JWT (Access Token corto + Refresh Token largo).
  * Los textos de los SMS analizados nunca se persisten en texto plano en la base de datos; se procesan en memoria RAM y se guarda un hash irreversible de identificación `mensaje_hash` generado con **HMAC-SHA256** utilizando una clave secreta del servidor (`HMAC_PEPPER`).
* **RNF-04: Multiplataforma.** App móvil sobre un único código base Flutter, compilable e interoperable de forma nativa en Android y iOS.
* **RNF-05: Seguridad de credenciales y tokens.**
  * Los códigos de verificación y recuperación jamás se guardan en texto plano; se persisten únicamente hasheados con HMAC-SHA256 (`HMAC_PEPPER`) en Redis (`verif:{user_id}`).
  * Las contraseñas locales se procesan y almacenan con Argon2id (`argon2-cffi`).
  * La validación de Google ID Tokens en el backend se realiza de forma estricta mediante `google-auth` comprobando firma criptográfica, vigencia, audiencia autorizada (`aud`) y certificación de correo (`email_verified`).
  * El backend nunca almacena ni registra en logs los ID tokens de Google, códigos de verificación en texto plano, contraseñas ni tokens sensibles.
* **RNF-06: Tolerancia a fallos del servicio de correo.**
  * Si el proveedor de correo transaccional (Resend) no responde, devuelve error o agota su cuota, el backend responde HTTP 503 Service Unavailable con mensaje claro (`EmailDeliveryError`), sin bloquear ni degradar el resto de la API. El reintento es manual por el usuario mediante el endpoint de reenvío de código.

---

## 9. Arquitectura (decisión del equipo)

### 9.1 Decisión: arquitectura por capas

Se elige **arquitectura por capas** sobre arquitectura por módulos porque:

* Son pocas funcionalidades (auth, análisis, historial/métricas, reglas) y todas giran alrededor del análisis; módulos darían carpetas casi vacías con dependencias cruzadas.
* La carga esperada es baja (~5 usuarios/día, ~18 mil análisis/año), sin presión de escalado por equipos.
* Los flujos de la sección 6 ya están pensados en capas.

Para no perder lo bueno de la otra opción, el **motor de análisis (`engine/`) es un núcleo puro**: sin I/O, sin red, sin base de datos.

### 9.2 Backend: capas y responsabilidades

```text
        Flutter (HTTPS + JWT)
               │
               ▼
┌──────────────────────────────┐
│  api/          Presentación  │  Routers, schemas (DTO), JWT, errores HTTP
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│  services/     Aplicación    │  Orquesta casos de uso (analizar, login, métricas)
└───────┬──────────┬───────────┘
        ▼          ▼
┌────────────┐ ┌────────────────────────────────────┐
│ engine/    │ │ Infraestructura                    │
│ Dominio    │ │  clients/       APIs externas      │
│ PURO       │ │  repositories/  Mongo y Redis      │
└────────────┘ └────────────────────────────────────┘
        core/  (config, seguridad, logging, excepciones): transversal
```

| Capa | Responsabilidad | Qué NO hace |
|---|---|---|
| `api/` | Recibe HTTP, valida con Pydantic, autentica (JWT y estado activo), traduce excepciones a respuestas HTTP | Lógica de negocio, acceso a datos |
| `services/` | Casos de uso: coordina engine, clients y repositories; maneja degradación grácil, transacciones y caché | Conocer HTTP, escribir queries Mongo |
| `engine/` | Extracción de URLs (máx. 2), heurísticas de URL y texto, scoring, nivel de riesgo, recomendaciones | I/O de cualquier tipo, imports de otras capas |
| `clients/` | Habla con Google Web Risk, VirusTotal y PhishTank (async, timeout, mapeo a modelos del engine) | Decidir puntos o riesgo |
| `repositories/` | Persistencia: Mongo (usuarios, análisis, métricas, reglas, marcas, respuestas) y Redis (reputación, cuota) | Lógica de negocio |
| `core/` | Configuración, JWT (Access/Refresh)/Argon2id/HMAC, logging, excepciones de dominio | Depender de otras capas |

### 9.3 Regla de dependencias (obligatoria)

| Capa | Puede importar | No puede importar |
|---|---|---|
| `api` | `services`, `core`, `api.schemas` | `repositories`, `clients`, `engine` |
| `services` | `engine`, `clients`, `repositories`, `core` | `api` |
| `engine` | solo librería estándar | todo lo demás de `app` |
| `clients` | `engine.models`, `core` | `api`, `services`, `repositories` |
| `repositories` | `engine.models`, `core` | `api`, `services`, `clients` |
| `core` | nada de `app` | todo lo demás |
| `container` | `services`, `clients`, `repositories`, `core` | `api` (declarado en `.importlinter` como excepción explícita) |

Se hace cumplir de forma automática con **import-linter** (`lint-imports`) en CI.

### 9.4 Estructura de carpetas (backend)

```text
antfish-backend/
├── app/
│   ├── main.py                  # crea FastAPI, middlewares, registra routers, lifespan y healthcheck global
│   ├── container.py             # Composition Root: cableado e inyección de dependencias (UnitOfWork, repos, servicios)
│   ├── api/
│   │   ├── deps.py              # inyección de servicios, get_current_user (JWT, estado activo e iat >= password_changed_at)
│   │   ├── errors.py            # excepciones de dominio -> respuestas JSON uniformes (HTTP 401, 403, 404, 409, 429, 503)
│   │   ├── schemas/             # DTOs Pydantic (auth, analysis, metrics)
│   │   └── v1/
│   │       ├── auth.py          # register, verify-email, resend-code, login, google, refresh, password/forgot, password/reset, delete me
│   │       ├── analysis.py      # post analysis, get history con cursor, get detail, delete analysis
│   │       ├── metrics.py       # get user metrics
│   │       └── health.py        # controlador de salud (registrado en raíz GET /health)
│   ├── services/
│   │   ├── analysis_service.py  # caso de uso principal con transacciones Mongo (UnitOfWork) y degradación grácil
│   │   ├── auth_service.py      # registro local/google, login, refresh, vinculación, forgot/reset, borrado con anonimización
│   │   ├── verification_service.py # generación, hash HMAC y validación de códigos de 6 dígitos vía Redis y Resend
│   │   ├── metrics_service.py   # lectura del panel de estadísticas
│   │   ├── rate_limiter.py      # control de tasa en Redis (falla abierto para APIs de reputación)
│   │   └── rules_provider.py    # carga reglas y marcas con caché en memoria RAM (TTL 3,600 s)
│   ├── engine/                  # PURO (sin I/O, sin red ni dependencias de terceros)
│   │   ├── models.py            # dataclasses y enums: UrlFeatures, Finding, Reputation, ScoreResult, CircuitBreakerReason
│   │   ├── public_suffixes.py   # sufijos públicos embebidos como constante estática
│   │   ├── url_extractor.py     # RF-02.1 (extrae todas las URLs en memoria)
│   │   ├── url_heuristics.py    # RF-02.3 (Capa 2 y selección de las 2 de mayor riesgo sintáctico)
│   │   ├── text_heuristics.py   # RF-02.4 (Capa 3: urgencia, solicitud de datos, leetspeak)
│   │   ├── scoring.py           # Capas 1+2+3, topes, cortocircuitos y motivo_cortocircuito
│   │   ├── risk_levels.py       # score -> bajo|medio|alto|critico
│   │   └── recommendations.py   # nivel/hallazgos -> 1 a 3 recomendaciones
│   ├── clients/
│   │   ├── base.py              # BaseReputationClient (HTTPX asíncrono, timeout 1.5 s, mapeo a ok|timeout|rate_limit|error)
│   │   ├── google_web_risk.py   # Lookup API (uris:search)
│   │   ├── virustotal.py        # API v3 (HTTP 404 procesado como ok sin detecciones)
│   │   ├── phishtank.py         # checkurl API con User-Agent obligatorio AntFish/1.0
│   │   ├── google_identity.py   # validación de Google ID Token en backend con google-auth
│   │   └── resend_email.py      # entrega transaccional de correos vía Resend (HTTPX async)
│   ├── repositories/
│   │   ├── mongo/
│   │   │   ├── unit_of_work.py  # Unit of Work que maneja sesiones y transacciones ACID en PyMongo Async
│   │   │   ├── user_repository.py # persistencia de usuarios, anonimización O12 y consulta
│   │   │   ├── analysis_repository.py # persistencia de análisis y respuestas_apis con cursor opaco (fecha, _id)
│   │   │   ├── metrics_repository.py # actualización atómica con $inc de contadores acumulados
│   │   │   ├── rules_repository.py # lectura de reglas_heuristicas y marcas_protegidas
│   │   │   ├── init_db.py       # inicialización idempotente de índices I1-I11, TTL y $jsonSchema
│   │   │   └── initial_data.json # catálogo semilla de reglas y marcas
│   │   └── redis/
│   │       ├── reputation_cache.py # get/set rep:{url_normalizada} (TTL 3,600 s)
│   │       ├── quota_repository.py # control de cuota dual cuota:{api}:pm y cuota:{api}:daily
│   │       ├── rate_limit_repository.py # contadores de tasa para auth y análisis
│   │       └── verification_repository.py # códigos verif:{user_id} (TTL 600 s, fail-closed) y reenvio:{user_id}
│   └── core/
│       ├── config.py            # settings validados con pydantic-settings
│       ├── security.py          # JWT, Argon2id, HMAC-SHA256 con HMAC_PEPPER
│       ├── logging.py           # logs estructurados JSON sin datos sensibles
│       └── exceptions.py        # jerarquía de excepciones con base AntFishError
├── tests/
│   ├── unit/                    # engine puro y fakes de servicios
│   ├── integration/             # API + MongoDB (Replica Set rs0) + Redis reales
│   └── performance/             # Locust (RNF-01, p95 <= 2.5 s)
├── scripts/seed_rules.py        # restablecimiento manual de reglas y marcas
├── .importlinter
├── pyproject.toml
├── Dockerfile
└── docker-compose.yml
```

### 9.5 Flujo del caso de uso `analizar` (RF-02, RF-03, RF-04)

```text
POST /api/v1/analysis  {tipo_entrada, contenido}
 1. api: valida schema Pydantic, rate limit por usuario (20/min) y autenticación JWT con estado activo en deps.py -> AnalysisService.analyze(user_id, tipo, contenido)
 2. service: rules_provider.get()  (reglas + marcas, caché en memoria RAM con TTL 3600 s)
 3. engine:
      sms -> url_extractor extrae TODAS las URLs en memoria; url_heuristics evalúa Capa 2 a cada una y selecciona las 2 de mayor riesgo sintáctico (empate: orden de aparición)
             text_heuristics evalúa Capa 3 (urgencia, datos sensibles, leetspeak)
      url -> normaliza la URL (https://, remueve query string, fragmento y userinfo); omite Capa 3 (RN-11)
 4. service: por cada una de las hasta 2 URLs normalizadas
      a. Redis rep:{url_normalizada} -> HIT: reutiliza reputación cacheadas (desde_cache = true)
      b. MISS: verifica y consume cuota dual en Redis (cuota:{api}:pm y cuota:{api}:daily); si excede -> estado "rate_limit"
      c. asyncio.gather(*clientes, return_exceptions=True), timeout independiente (1.5 s) por API (Web Risk, VirusTotal, PhishTank)
         -> estado: ok | timeout | rate_limit | error
      d. si las 3 APIs respondieron ok para esa URL -> guarda en Redis SET rep:{url_normalizada}, TTL 3600 s
 5. engine.scoring:
      - Aplica topes por capa (APIs <= 60, URL <= 30, texto <= 20)
      - Cortocircuito por lista negra (piso 95-100) y override por suplantación directa de marca (piso 80)
      - Evalúa riesgo total combinado y selecciona la URL dominante; determina motivo_cortocircuito (prevalece lista_negra)
      - Marca analisis_parcial = true si cualquier API falló en cualquiera de las 2 URLs (D3)
 6. engine.recommendations: emite 1 a 3 recomendaciones concretas basadas en nivel y hallazgos
 7. service: persiste bajo una Transacción de Sesión ACID en MongoDB (UnitOfWork):
      a. analisis: dominio_principal, score_total, nivel_riesgo, motivo_cortocircuito, analisis_parcial, hallazgos, recomendaciones y fuentes_consultadas de la URL dominante; urls_extraidas (máx. 2 normalizadas); mensaje_hash (HMAC-SHA256, sin texto SMS)
      b. metricas_usuario: incremento atómico con $inc sobre total_escaneos, total_sms/url y amenazas_bloqueadas (si score >= 50)
      c. respuestas_apis: respuestas crudas de las hasta 2 URLs analizadas (máx. 6 documentos con url_normalizada, dominio y TTL 30 días, D1)
 8. api: retorna AnalysisResponse DTO -> Flutter renderiza semáforo visual y desglosa hallazgos
```

### 9.6 Endpoints Confirmados

| Método y ruta | Operación del modelo | Descripción |
|---|---|---|
| `POST /api/v1/auth/register` | O1 | Registro local (cuenta `pendiente_verificacion`, código Resend; sobrescritura si ya estaba pendiente, D14; 409 si activa) |
| `POST /api/v1/auth/verify-email` | O1.1 | Valida `{email, codigo}`, resuelve `user_id` internamente, transiciona cuenta a `activa` (respuestas uniformes, D17) |
| `POST /api/v1/auth/resend-code` | O1.2 | Reenvía código de 6 dígitos (máximo 3/hora por usuario compartido en `reenvio:{user_id}`, D17) |
| `POST /api/v1/auth/login` | O2 | Valida contraseña antes de estado; devuelve Access y Refresh Tokens (403 `ACCOUNT_NOT_VERIFIED` solo tras validar pass; D12) |
| `POST /api/v1/auth/google` | O2.2 | Valida ID token con `google-auth`; alta inmediata o vinculación automática sobre activa o pendiente (D13) |
| `POST /api/v1/auth/refresh` | O2.1 | Emite nuevo Access Token si refresh es válido, cuenta activa y `iat >= password_changed_at` (D18) |
| `POST /api/v1/auth/password/forgot` | O13 | Solicita código para reset vía Resend; responde siempre HTTP 200 uniforme (comparte `reenvio:{user_id}`, D16, D17) |
| `POST /api/v1/auth/password/reset` | O14 | Recibe `{email, codigo, nueva_password}`, aplica nuevo hash, fija `password_changed_at` y revoca tokens previos (D17, D18) |
| `DELETE /api/v1/auth/me` | O12 | Borrado de cuenta (exige `{password}` si local, o `{id_token}` si google); anonimiza usuario y purga datos en cascada ACID (D4) |
| `POST /api/v1/analysis` | O7 | Analiza SMS o URL (máx. 2 URLs, rate limit de 20 peticiones/min por usuario; responde 429 si excede) |
| `GET /api/v1/analysis?cursor=` | O9 | Historial paginado por cursor opaco `(fecha, _id)` respaldado por I2 (20 por página; D8) |
| `GET /api/v1/analysis/{id}` | O10 | Consulta detalle de un análisis específico comprobando pertenencia por `user_id` |
| `DELETE /api/v1/analysis/{id}` | O11 | Elimina un análisis y sus respuestas crudas de APIs en transacción ACID sin alterar métricas acumuladas |
| `GET /api/v1/metrics/me` | O8 | Panel de estadísticas del usuario autenticado |
| `GET /health` | n/a | Healthcheck global registrado en la raíz (verifica conectividad activa de MongoDB y Redis) |

### 9.7 Errores, seguridad y autenticación

* **Autenticación y Ciclo de Vida:**
  * **Access Token JWT:** Vida corta (30 minutos). Transmitido en la cabecera `Authorization: Bearer <token>`.
  * **Refresh Token JWT:** Vida larga (30 días), *stateless* firmado con `JWT_REFRESH_SECRET`.
  * **Validación Activa e Invalidación Instantánea por `password_changed_at`:** En cada llamada protegida, `deps.py` valida la firma del token y comprueba que el claim `iat` (*issued at*) no sea anterior a `password_changed_at` en MongoDB; si `iat < password_changed_at`, rechaza con HTTP 401 Unauthorized (D18). Asimismo comprueba que `estado_cuenta == "activa"`. Si la cuenta está en `pendiente_verificacion`, deniega con HTTP 403 Forbidden y código `ACCOUNT_NOT_VERIFIED`.
* **Políticas de Rate Limiting y Control de Tasa:**
  * **Reenvío y recuperación:** Máximo 3 solicitudes por hora por usuario compartidas en Redis (`reenvio:{user_id}`, TTL 3600 s) entre `/auth/resend-code` y `/auth/password/forgot` (D17). Al excederse, responde HTTP 429 Too Many Requests.
  * **Endpoints de autenticación (`/auth/login`, `/auth/google`):** Máximo 5 intentos por minuto por dirección IP del cliente (HTTP 429).
  * **Análisis (`/analysis`):** Máximo 20 análisis por minuto por usuario (`user_id`).
  * **Resiliencia de verificación (Fail-Closed):** A diferencia de la caché de reputación que opera como *fail-open*, la emisión y validación de códigos numéricos en Redis opera estrictamente como *fail-closed*: si Redis no responde, se deniega la operación retornando HTTP 503 Service Unavailable.
* **HMAC para Privacidad de SMS y Códigos:** Se calcula `mensaje_hash = HMAC_SHA256(texto_sms, HMAC_PEPPER)`. El texto plano del SMS se destruye de la memoria RAM inmediatamente tras el análisis. Los códigos temporales se almacenan en Redis (`verif:{user_id}`) exclusivamente como digestos HMAC-SHA256 con el mismo pepper de servidor.
* **Escritura Atómica de Métricas:** La persistencia de `analisis`, `respuestas_apis` y el incremento atómico (`$inc`) en `metricas_usuario` se ejecutan dentro de una Transacción ACID de MongoDB (`async with await client.start_session()`).

### 9.8 Pruebas y rendimiento (fuente: ADR #27)

* **Herramienta Oficial de Carga:** Se aprueba **Locust** (`tests/performance/locustfile.py`) como la herramienta única de pruebas de carga y rendimiento asíncronas para validar el cumplimiento del RNF-01 ($p95 \le 2.5\text{ s}$).
* **Pruebas Unitarias:** Confinadas en `tests/unit/engine/` para validar el motor puro sin I/O ni dependencias externas, cubriendo la matriz completa de ponderaciones por capa y cortocircuitos.
* **Pruebas de Integración:** Confinadas en `tests/integration/` con MongoDB (Replica Set rs0) y Redis reales levantados vía Docker Compose.

### 9.9 Prevención de SSRF y Seguridad TLS (fuente: ADR #30, #31, #35, #60)

* **Política Estricta contra SSRF:** El backend **nunca realiza peticiones de red directas a las URLs analizadas** (ni peticiones HEAD, ni redirecciones HTTP, ni resolución DNS directa, ni capturas de pantalla). Toda la inteligencia se obtiene de las APIs de reputación.
* **Sanitización de URLs:** Se eliminan obligatoriamente query strings, fragmentos e información de usuario en `urls_extraidas[]`, `respuestas_apis.url_normalizada` y la clave de caché `rep:{url_normalizada}`.
* **Cifrado en Tránsito:** HTTPS/TLS obligatorio en todas las comunicaciones externas y móviles (RNF-03).

### 9.10 Convenciones de Desarrollo y Código (fuente: ADR #1, #22, #32, #56)

* **Idioma:** Código Python en inglés; nombres de colecciones, campos persistidos, códigos de regla y textos al usuario en español.
* **Enums en Minúsculas:** `nivel_riesgo` (`bajo|medio|alto|critico`), `tipo_entrada` (`sms|url`), `estado_fuente` (`ok|timeout|rate_limit|error`), `estado_cuenta` (`pendiente_verificacion|activa|suspendida|eliminada`), `proveedor_auth` (`local|google`), `motivo_cortocircuito` (`lista_negra|suplantacion_marca|null`), `tipo_codigo` (`verificacion|recuperacion`).
* **Excepciones:** Jerarquía unificada con sufijo `Error` derivada de `AntFishError`.

### 9.11 Infraestructura y Despliegue (fuente: ADR #18, #20, #33, #61, #65)

* **Orquestación:** Docker Compose para servicios `api`, `mongo` y `redis`.
* **MongoDB Replica Set:** Nodo único con `--replSet rs0` inicializado automáticamente para transacciones ACID con PyMongo Async.
* **Inicialización Idempotente (`init_db.py`):** Creación de índices I1-I11, `$jsonSchema + $expr` y monitores TTL (I8 a 30 días, I11 a 48 horas) en el evento `lifespan`.
* **Siembra Idempotente:** Carga de reglas y marcas desde `initial_data.json` solo si las colecciones están vacías (`count_documents == 0`). Restablecimiento manual vía `scripts/seed_rules.py`.

---

## 10. Modelo de Datos (resumen)

Detalle completo en `antfish_modelo_nosql.json`.

* **MongoDB:**
  * `usuarios`: Datos del usuario, correo en minúsculas (índice I1 único), `proveedor_auth` (`local | google`), `google_sub` (índice I10 único parcial), `password_hash` (Argon2id, opcional), `nombre`, `estado_cuenta` (`pendiente_verificacion | activa | suspendida | eliminada`), `email_verificado`, `fecha_verificacion`, `password_changed_at` (D18) y `fecha_eliminacion` (para anonimización O12, D4). Purga física automática de cuentas no verificadas tras 48 h mediante índice TTL parcial I11 (D15).
  * `analisis`: Registro del análisis, `user_id` (referencia), `tipo_entrada` (`sms | url`), `mensaje_hash` (HMAC-SHA256 con `HMAC_PEPPER`), `urls_extraidas` (máx. 2, URL normalizada con path), `dominio_principal`, `score_total` (0-100), `nivel_riesgo`, `puntos_por_capa` (apis, url, texto), `motivo_cortocircuito` (`lista_negra | suplantacion_marca | null`, D2), `analisis_parcial` (true si falla cualquier API de las 2 URLs, D3), `hallazgos` y `fuentes_consultadas` de la URL dominante, y recomendaciones. Índice I2 compuesto `{ user_id: 1, fecha: -1, _id: -1 }` para paginación determinista por cursor opaco `(fecha, _id)` (D8).
  * `metricas_usuario`: Contadores acumulados (`total_escaneos`, `total_url`, `total_sms`, `amenazas_bloqueadas`) actualizados atómicamente mediante `$inc` en transacciones ACID.
  * `reglas_heuristicas`: Catálogo de reglas heurísticas activas con prefijos `URL_`, `TXT_` y `API_` (D6).
  * `marcas_protegidas`: Catálogo de marcas oficiales con dominios autorizados y variantes ofuscadas para detección de suplantación.
  * `respuestas_apis`: Log de auditoría crudo por URL (`analisis_id`, `user_id`, `url_normalizada`, `dominio`, `api`, `respuesta_cruda`, `fecha`, `expira_en`) para las hasta 2 URLs analizadas (máx. 6 docs), con TTL automático de 30 días respaldado por índice TTL I8 e índice compuesto I9 (D1).
* **Redis:**
  * `rep:{url_normalizada}`: Caché de reputación de URLs normalizadas con TTL de 3600 s (solo si las 3 APIs respondieron `ok`, D10).
  * `cuota:{api}:pm` y `cuota:{api}:daily`: Control de cuota dual por minuto (TTL 60 s) y diario (TTL 86400 s).
  * `verif:{user_id}`: Código temporal de 6 dígitos hasheado con HMAC-SHA256 para verificación o recuperación, TTL 600 s (*fail-closed*).
  * `reenvio:{user_id}`: Contador compartido de reenvíos y recuperación (máx. 3 por hora por usuario), TTL 3600 s (D17).

---

## 11. Decisiones Confirmadas y Resueltas

Todas las decisiones de diseño del backend han sido formalmente analizadas, resueltas y sincronizadas por el equipo:

1. **Límite y procesamiento de URLs en SMS:** Se extraen todas las URLs en memoria y se analizan las **2 URLs de mayor riesgo sintáctico** (empate: orden de aparición). La URL con mayor riesgo combinado se selecciona como **URL dominante** para el diagnóstico global (ADR #7, #8, #9).
2. **Caché Redis ante fallos parciales:** Solo se almacena en `rep:{url_normalizada}` si las 3 APIs de reputación respondieron con éxito total (`ok`). Ante fallos o cuota superada se activa la degradación grácil (`analisis_parcial: true`) sin cachear respuestas parciales (ADR #21, #31, #53, #60).
3. **Cortocircuito por Marca y Listas Negras:** Suplantación directa de marcas activa cortocircuito fijando el piso mínimo en **80 pts (Crítico)**. Listas negras escalan a **95-100 pts**. Se formaliza `motivo_cortocircuito: "lista_negra" | "suplantacion_marca" | null`, prevaleciendo `lista_negra` (ADR #10, #12, #52).
4. **Estrategia JWT y Revocación Inmediata:** Access Token de 30 min y Refresh Token de 30 días. En cada petición, `deps.py` y el endpoint de refresco contrastan `iat >= password_changed_at`, logrando revocación instantánea de sesiones tras cambio de contraseña (ADR #13, #14, #49, #68).
5. **Doble Escritura de Análisis y Métricas:** Transacciones de Sesión ACID en MongoDB (`UnitOfWork`), garantizando atomicidad con `$inc` y consistencia absoluta entre análisis y métricas (ADR #6, #18).
6. **Privacidad del SMS:** Texto plano destruido de la memoria RAM inmediatamente tras el análisis; persistencia de `mensaje_hash` con HMAC-SHA256 (`HMAC_PEPPER`) y URLs normalizadas sin query string (ADR #31, #35, #60).
7. **Autenticación Dual y Vinculación de Cuentas:** Soporte dual `local` y `google`. Login con Google sobre cuenta en `pendiente_verificacion` descarta contraseñas previas y activa la cuenta previniendo pre-account takeover (ADR #63). Cuentas locales ya activas vinculan `google_sub` preservando su contraseña local (ADR #47).
8. **Verificación por Código de 6 Dígitos vía Resend:** Códigos efímeros numéricos de 6 dígitos con vigencia de 10 min, máx. 5 intentos y máx. 3 reenvíos/hora. Almacenamiento exclusivo en Redis hasheado con HMAC-SHA256 bajo política *fail-closed* (ADR #41, #42, #43).
9. **Validación de Google Sign-In en Backend:** Criptográfica con `google-auth` en backend (firma, expiración, `aud` y `email_verified`). Sin almacenamiento de tokens de terceros (ADR #44, #45).
10. **Reautenticación en Baja de Cuenta y Anonimización:** `DELETE /auth/me` exige password (si local) o id_token de Google (si google/vinculada). Anonimiza el usuario (`deleted_<id>@deleted.local`) y purga en cascada bajo transacción ACID (ADR #48, #54).
11. **Respuestas Uniformes contra Enumeración:** Login valida credenciales antes de retornar 403 `ACCOUNT_NOT_VERIFIED` (ADR #62). `POST /auth/password/forgot` responde siempre HTTP 200 uniforme (ADR #66). Verificación y reset resuelven `user_id` internamente (ADR #67).
12. **Purga Automática por TTL en Base de Datos:** Se elimina la figura de schedulers o tareas programadas externas. La purga de cuentas no verificadas tras 48 h la gestiona directamente MongoDB mediante el índice TTL parcial I11 sobre `fecha_registro` (ADR #50, #65).
13. **Auditoría Completa en `respuestas_apis`:** Almacenamiento de respuestas por URL con `url_normalizada` y `dominio` para las hasta 2 URLs evaluadas (máx. 6 docs) con TTL de 30 días respaldado por índices I8 e I9 (ADR #51).
14. **Semántica de Análisis Parcial:** `analisis_parcial = true` si falla cualquier API de cualquiera de las 2 URLs; fuentes y hallazgos continúan describiendo la URL dominante (ADR #53).
15. **Normalización Universal de Correos:** En minúsculas y sin espacios desde la aplicación; índice I1 sin collation (ADR #55).
16. **Nomenclatura Unificada de Reglas:** Prefijos fijos `URL_`, `TXT_` y `API_`, con `TXT_LENGUAJE_URGENCIA` y `TXT_SOLICITUD_DATOS` unificados (ADR #56).
17. **Índices Diferidos:** Retiro de I3 e I4 de la especificación activa v1 para optimizar rendimiento de transacciones (ADR #57).
18. **Paginación Estable por Cursor:** Índice I2 `{ user_id: 1, fecha: -1, _id: -1 }` con cursor opaco determinista `(fecha, _id)` (ADR #58).

---

## Historial de cambios

| Versión | Fecha | Resumen | ADR relacionados |
|---|---|---|---|
| 2.1 | 2026-10-27 | Sincronización documental v2.1: Actualización de requerimientos RF-02.1 (extracción de todas las URLs y análisis de las 2 de mayor riesgo sintáctico), RF-03.3 (URL dominante), RF-04.1 (rep:{url_normalizada} y cuota dual), RF-06.1 a RF-06.8 (respuestas uniformes, vinculación sobre pendiente, anonimización O12, revocación inmediata por iat y purga desatendida vía índice TTL I11 sin scheduler). Actualización de §9.3 (container.py), §9.4 (árbol con uow, init_db, rate limit), §9.5 (flujo v2.1 con respuestas_apis de 2 URLs), §9.6 (endpoints confirmados y errores), §9.7 (iat contra password_changed_at). Restauración técnica de secciones §9.8 a §9.11 (pruebas Locust, SSRF/TLS, convenciones e infraestructura). Actualización de modelo §10 y formalización de decisiones confirmadas D1 a D18 en §11. | ADR #51 a #68 |