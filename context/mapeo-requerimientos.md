Ran list directory structure
Checked task List directory structure
Analyzed AGENTS.md:L1-150
Ran list docs folder
Analyzed requerimientos.md:L1-215
Analyzed arquitectura_backend_v2.json:L1-150
Analyzed arquitectura_backend_v2.json:L151-300
Analyzed arquitectura_backend_v2.json:L301-450
Analyzed arquitectura_backend_v2.json:L451-600
Analyzed arquitectura_backend_v2.json:L601-745
Analyzed casos-de-uso.md:L1-76
Ran check sections in contexto-AntFish.md
Analyzed contexto-AntFish.md:L195-430
Ran check app directory contents
Analyzed main.py
Analyzed requeriments.txt
Analyzed logging.py:L1-20
Analyzed init_db.py:L1-100

He analizado la documentación de contexto en `docs/` (`contexto-AntFish.md`, `requerimientos.md`, `arquitectura_backend_v2.json`, `casos-de-uso.md`, `reglas-negocio.md`, `antfish_modelo_nosql.json`) y la estructura de carpetas actual del proyecto.

Con base en la arquitectura por capas, las reglas de precedencia de `AGENTS.md` y los requerimientos funcionales (RF) y no funcionales (RNF), presento el mapeo exacto de en qué archivo se programará cada requerimiento sin tocar código aún:

---

### **RF-01: Recepción de Entradas**
* **RF-01.1 & RF-01.2 (Validación de payload manual y compartido de SMS / URL, límites de longitud: SMS $\le$ 1,600 caracteres, URL $\le$ 2,048 caracteres):**
  * Esquemas Pydantic y validadores: [`app/api/schemas/analysis.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/schemas/analysis.py)
  * Controlador del endpoint HTTP (`POST /api/v1/analysis`): [`app/api/v1/analysis.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/v1/analysis.py)

---

### **RF-02: Motor de Análisis Combinado**
* **RF-02.1 (Extracción en RAM de todas las URLs explícitas y dominios sin esquema, y normalización con `https://` sin query string):**
  * [`app/engine/url_extractor.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/engine/url_extractor.py)
* **RF-02.2 (Consultas paralelas con `asyncio.gather` y timeout individual de 1.5 s a Google Web Risk, VirusTotal y PhishTank):**
  * Cliente base y traducción de estados (`ok|timeout|rate_limit|error`): [`app/clients/base.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/clients/base.py)
  * Cliente Google Web Risk: [`app/clients/google_web_risk.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/clients/google_web_risk.py)
  * Cliente VirusTotal (manejo de 404 como sin detecciones): [`app/clients/virustotal.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/clients/virustotal.py)
  * Cliente PhishTank (User-Agent obligatorio `AntFish/1.0`): [`app/clients/phishtank.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/clients/phishtank.py)
  * Orquestación concurrente en el servicio: [`app/services/analysis_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/analysis_service.py)
* **RF-02.3 (Capa 2: Heurística sintáctica de URL — IP directa, TLDs de alto riesgo, subdominios engañosos, acortadores, exceso de guiones — y selección de las 2 URLs de mayor riesgo sintáctico):**
  * Lógica algorítmica de heurística de URL: [`app/engine/url_heuristics.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/engine/url_heuristics.py)
  * Constante estática de sufijos de dominio (Public Suffixes): [`app/engine/public_suffixes.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/engine/public_suffixes.py)
* **RF-02.4 (Capa 3: Heurística de texto de SMS — lenguaje de urgencia `TXT_LENGUAJE_URGENCIA`, solicitud de datos `TXT_SOLICITUD_DATOS`, ofuscación y leetspeak; omitida en análisis de URL):**
  * [`app/engine/text_heuristics.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/engine/text_heuristics.py)

---

### **RF-03: Asignación de Riesgo y Diagnóstico**
* **RF-03.1 (Cálculo de score con topes por capa, cortocircuito por lista negra 95-100 pts, override por suplantación de marca piso 80 pts, y selección de URL dominante):**
  * Motor de puntuación puro: [`app/engine/scoring.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/engine/scoring.py)
  * Dataclasses y enums (`ScoreResult`, `CircuitBreakerReason`, `Finding`): [`app/engine/models.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/engine/models.py)
* **RF-03.2 (Clasificación de riesgo en escala `bajo | medio | alto | critico` para el semáforo visual):**
  * [`app/engine/risk_levels.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/engine/risk_levels.py)
* **RF-03.3 (Generación de 1 a 3 recomendaciones de acción concretas y desglose de hallazgos de la URL dominante):**
  * Lógica de recomendaciones: [`app/engine/recommendations.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/engine/recommendations.py)
  * Mapeo al DTO de respuesta: [`app/api/schemas/analysis.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/schemas/analysis.py)

---

### **RF-04: Caché y Rendimiento de Consultas**
* **RF-04.1 & RF-04.2 (Consulta y obtención de caché Redis `rep:{url_normalizada}` con TTL de 3,600 s previa a APIs):**
  * Repositorio de caché Redis: [`app/repositories/redis/reputation_cache.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/redis/reputation_cache.py)
  * Flujo condicional de caché en el caso de uso: [`app/services/analysis_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/analysis_service.py)
* **RF-04.3 (Escritura en caché Redis condicionada estrictamente a que las 3 APIs hayan respondido `ok`):**
  * [`app/services/analysis_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/analysis_service.py)
* **Control atómico de cuotas externas dual (por minuto y diaria: `cuota:{api}:pm` y `cuota:{api}:daily`):**
  * Repositorio de cuotas en Redis: [`app/repositories/redis/quota_repository.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/redis/quota_repository.py)

---

### **RF-05: Métricas y Panel del Usuario**
* **RF-05.1 (Almacenamiento de análisis, persistencia de `respuestas_apis` de hasta 2 URLs e historial paginado por cursor opaco `(fecha, _id)` respaldado por índice I2):**
  * Transacciones ACID y sesión MongoDB: [`app/repositories/mongo/unit_of_work.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/mongo/unit_of_work.py)
  * Repositorio MongoDB de análisis: [`app/repositories/mongo/analysis_repository.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/mongo/analysis_repository.py)
  * Endpoints de historial, detalle y borrado (`GET /api/v1/analysis`, `GET /api/v1/analysis/{id}`, `DELETE /api/v1/analysis/{id}`): [`app/api/v1/analysis.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/v1/analysis.py)
* **RF-05.2 (Contadores acumulados con `$inc` y lectura de estadísticas del usuario — total escaneos, SMS vs URLs, amenazas bloqueadas):**
  * Repositorio MongoDB de métricas: [`app/repositories/mongo/metrics_repository.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/mongo/metrics_repository.py)
  * Servicio de lectura de métricas: [`app/services/metrics_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/metrics_service.py)
  * Endpoint `GET /api/v1/metrics/me` y esquema: [`app/api/v1/metrics.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/v1/metrics.py) y [`app/api/schemas/metrics.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/schemas/metrics.py)

---

### **RF-06: Autenticación, Verificación y Gestión de Cuenta**
* **RF-06.1 (Registro local con normalización de email, hash Argon2id, cuenta en `pendiente_verificacion`, sobrescritura controlada D14 y 409 si activa):**
  * Funciones criptográficas (Argon2id): [`app/core/security.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/core/security.py)
  * Repositorio MongoDB de usuarios: [`app/repositories/mongo/user_repository.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/mongo/user_repository.py)
  * Servicio de autenticación: [`app/services/auth_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/auth_service.py)
  * Endpoint `POST /api/v1/auth/register` y DTOs: [`app/api/v1/auth.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/v1/auth.py) y [`app/api/schemas/auth.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/schemas/auth.py)
* **RF-06.2 (Verificación de correo mediante código de 6 dígitos con hash HMAC en Redis `verif:{user_id}`, vigencia 10 min, máx. 5 intentos, fail-closed, transición a `activa` y respuestas uniformes):**
  * Repositorio Redis de códigos: [`app/repositories/redis/verification_repository.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/redis/verification_repository.py)
  * Cliente de correo Resend: [`app/clients/resend_email.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/clients/resend_email.py)
  * Servicio de verificación de códigos: [`app/services/verification_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/verification_service.py)
  * Endpoint `POST /api/v1/auth/verify-email`: [`app/api/v1/auth.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/v1/auth.py)
* **RF-06.3 (Reenvío de código con rate limit en Redis `reenvio:{user_id}`, máx. 3 solicitudes/hora por usuario):**
  * Control de reenvíos: [`app/repositories/redis/verification_repository.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/redis/verification_repository.py) y [`app/services/verification_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/verification_service.py)
  * Endpoint `POST /api/v1/auth/resend-code`: [`app/api/v1/auth.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/v1/auth.py)
* **RF-06.4 (Login con Google mediante validación estricta de ID Token con `google-auth`):**
  * Cliente de validación de Google Identity: [`app/clients/google_identity.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/clients/google_identity.py)
  * Lógica de login/alta en servicio: [`app/services/auth_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/auth_service.py)
  * Endpoint `POST /api/v1/auth/google`: [`app/api/v1/auth.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/v1/auth.py)
* **RF-06.5 (Vinculación de cuentas locales y Google preservando estados y descartando password en pendientes D13):**
  * [`app/services/auth_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/auth_service.py) y [`app/repositories/mongo/user_repository.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/mongo/user_repository.py)
* **RF-06.6 (Recuperación y reset de contraseña: respuesta uniforme 200 en `forgot`, código en `reset`, actualización de `password_changed_at` e invalidación inmediata de tokens D18):**
  * Lógica en servicios: [`app/services/auth_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/auth_service.py) y [`app/services/verification_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/verification_service.py)
  * Endpoints `POST /api/v1/auth/password/forgot` y `/password/reset`: [`app/api/v1/auth.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/v1/auth.py)
* **RF-06.7 (Borrado de cuenta `DELETE /api/v1/auth/me` con reautenticación por método, anonimización O12 y purga en cascada bajo transacción ACID D4):**
  * Orquestación de borrado: [`app/services/auth_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/auth_service.py)
  * Operaciones en transacción: [`app/repositories/mongo/unit_of_work.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/mongo/unit_of_work.py) y [`app/repositories/mongo/user_repository.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/mongo/user_repository.py)
  * Endpoint `DELETE /api/v1/auth/me`: [`app/api/v1/auth.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/v1/auth.py)
* **RF-06.8 (Bloqueo de acceso a no verificados: validación de contraseña antes de 403 `ACCOUNT_NOT_VERIFIED` D12; depuración física de pendientes a las 48 h vía índice TTL I11 D15):**
  * Autenticación y chequeo de estado: [`app/services/auth_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/auth_service.py) y [`app/api/deps.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/deps.py)
  * Configuración del índice TTL I11: [`app/repositories/mongo/init_db.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/mongo/init_db.py)

---

### **Requerimientos No Funcionales y Componentes Transversales**
* **RNF-01 (Latencia p95 $\le$ 2.5 s):**
  * Orquestación asíncrona: [`app/services/analysis_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/analysis_service.py)
  * Pruebas de rendimiento con Locust: [`tests/performance/locustfile.py`](file:///d:/dev/AntFish-Backend/antfish-backend/tests/performance/locustfile.py)
* **RNF-02 (Degradación grácil y `analisis_parcial: true` ante fallos o cuota de APIs externas):**
  * [`app/services/analysis_service.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/analysis_service.py)
* **RNF-03 (Seguridad y Privacidad: hash HMAC-SHA256 con `HMAC_PEPPER` para `mensaje_hash` sin persistir texto de SMS; Access Tokens de 30 min y Refresh Tokens de 30 días):**
  * Lógica criptográfica y tokens JWT: [`app/core/security.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/core/security.py)
  * Inyección y validación de tokens en endpoints con verificación de `iat \ge password_changed_at`: [`app/api/deps.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/deps.py)
  * Enmascaramiento y logs estructurados sin datos sensibles ni query strings: [`app/core/logging.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/core/logging.py)
* **RNF-05 (Seguridad de credenciales):**
  * Argon2id directo y HMAC en: [`app/core/security.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/core/security.py)
* **RNF-06 (Tolerancia a fallos de Resend con `EmailDeliveryError` mapeado a HTTP 503):**
  * Definición de excepción: [`app/core/exceptions.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/core/exceptions.py)
  * Manejador de errores HTTP: [`app/api/errors.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/errors.py)
  * Cliente Resend: [`app/clients/resend_email.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/clients/resend_email.py)
* **Rate Limiting de la API (5 req/min por IP en auth; 20 req/min por usuario en análisis):**
  * Repositorio de rate limit en Redis: [`app/repositories/redis/rate_limit_repository.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/redis/rate_limit_repository.py)
  * Servicio de control de tasa (fail-open para análisis): [`app/services/rate_limiter.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/rate_limiter.py)
  * Dependencias FastApi: [`app/api/deps.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/deps.py)
* **Carga de Reglas Heurísticas y Marcas con caché en memoria RAM (TTL 3,600 s):**
  * Repositorio MongoDB: [`app/repositories/mongo/rules_repository.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/mongo/rules_repository.py)
  * Proveedor con caché: [`app/services/rules_provider.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/services/rules_provider.py)
  * Catálogo semilla: [`app/repositories/mongo/initial_data.json`](file:///d:/dev/AntFish-Backend/antfish-backend/app/repositories/mongo/initial_data.json)
* **Healthcheck Global (`GET /health` comprobando MongoDB y Redis):**
  * [`app/api/v1/health.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/v1/health.py) registrado en [`app/main.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/main.py)
* **Composition Root e Inyección de Dependencias:**
  * Contenedor de dependencias: [`app/container.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/container.py)
  * Dependencias FastAPI (`deps.py`): [`app/api/deps.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/api/deps.py)
  * Ciclo de vida y arranque de la aplicación: [`app/main.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/main.py)
  * Configuración centralizada (`pydantic-settings`): [`app/core/config.py`](file:///d:/dev/AntFish-Backend/antfish-backend/app/core/config.py)