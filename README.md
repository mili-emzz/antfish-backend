# AntFish Backend

API que analiza **SMS y enlaces sospechosos** (phishing y smishing) y devuelve un **puntaje de riesgo de 0 a 100** con un semáforo (`bajo`, `medio`, `alto`, `critico`) y recomendaciones de acción. Es el backend de la app móvil AntFish (Flutter), que no recalcula el puntaje en el cliente.

## Qué hace

- **Analiza un SMS o una URL** combinando tres capas de evidencia:
  1. **Inteligencia externa** (hasta 60 puntos): Google Web Risk y VirusTotal.
  2. **Heurísticas de URL** (hasta 30 puntos): dominios engañosos, suplantación de marcas, TLD de alto riesgo, acortadores, IP directa, exceso de guiones.
  3. **Heurísticas de texto** (hasta 20 puntos): señales típicas de ingeniería social en el mensaje.
- **Cortocircuito** cuando hay evidencia contundente: lista negra o suplantación de una marca protegida.
- **Degradación controlada:** si una fuente externa falla o agota su cuota, el análisis se devuelve igual, marcado como parcial.
- **Cuentas de usuario:** registro con verificación por correo, login local y con Google, renovación de sesión, recuperación de contraseña y borrado de cuenta con purga de datos.
- **Historial y métricas** por usuario.

## Principios de diseño

- **Privacidad por diseño:** el texto de un SMS nunca se guarda (solo una huella HMAC) y nunca se hace una petición a las URLs analizadas.
- **Sin secretos en el repositorio:** la aplicación no arranca sin secretos fuertes definidos por entorno.
- **Fallos explícitos:** Redis o Mongo caídos tienen una política definida (fail-open o fail-closed) según la funcionalidad.

## Arquitectura

Monolito modular en **capas**, con las dependencias verificadas automáticamente por `import-linter` en el CI:

```
api  →  services  →  engine | clients | repositories
```

| Capa | Rol | Carpeta |
|---|---|---|
| `api` | Rutas HTTP, validación, autenticación, errores | [app/api/](app/api/) |
| `services` | Lógica de negocio y orquestación | [app/services/](app/services/) |
| `engine` | Motor de detección y puntaje: código puro, solo biblioteca estándar | [app/engine/](app/engine/) |
| `clients` | Adaptadores a APIs externas (Web Risk, VirusTotal, Resend, Google) | [app/clients/](app/clients/) |
| `repositories` | Acceso a datos: MongoDB y Redis | [app/repositories/](app/repositories/) |
| `core` | Configuración, seguridad, excepciones y logs | [app/core/](app/core/) |

La raíz de composición está en [app/container.py](app/container.py).

**Tecnología:** Python 3.14, FastAPI (asíncrono), MongoDB (replica set, transacciones ACID), Redis, Argon2id, JWT, Docker y Caddy.
**Datos:** MongoDB guarda lo duradero (usuarios, análisis, métricas, catálogo de reglas). Redis guarda lo efímero (códigos de verificación, sesiones, límites de tasa, caché de reputación, cuotas).

## Endpoints principales

| Área | Rutas (`/api/v1`) |
|---|---|
| Autenticación | `POST /auth/register`, `/auth/verify-email`, `/auth/resend-code`, `/auth/login`, `/auth/google`, `/auth/refresh`, `/auth/logout`, `/auth/password/forgot`, `/auth/password/reset`; `DELETE /auth/me` |
| Análisis | `POST /analysis`; `GET /analysis` (historial paginado); `GET` y `DELETE /analysis/{id}` |
| Métricas | `GET /metrics/me` |
| Salud | `GET /health` (en la raíz) |

Todos los errores usan el formato `{"code": "...", "detail": ...}`. Con la API en modo desarrollo, la documentación interactiva está en `/docs`.

## Cómo ejecutarlo en local

Requisitos: Python 3.14, Docker.

```bash
python -m venv venv && source venv/bin/activate        # en Windows: venv\Scripts\activate
pip install -r requirements-dev.txt

cp .env.example .env        # y rellena los valores (ver comentarios del archivo)
docker compose up -d        # MongoDB (replica set), usuarios de mínimo privilegio y Redis
python -m app.repositories.mongo.init_db                # esquema, índices y catálogo inicial
uvicorn app.main:app --reload
```

`.env.example` explica cada variable. Los secretos (`HMAC_PEPPER`, `JWT_SECRET`, `JWT_REFRESH_SECRET`, `REDIS_PASSWORD`) deben generarse aleatorios, por ejemplo con `openssl rand -hex 32`. Las claves de Web Risk, VirusTotal y Resend son opcionales para arrancar: sin ellas, esas fuentes se omiten.

## Pruebas y calidad

```bash
python -m pytest tests/unit -q          # más de 200 pruebas, sin red ni servicios
python -m pytest tests/integration -q   # con Docker: Redis y MongoDB reales
ruff check . && ruff format --check . && mypy app && lint-imports
```

El CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) ejecuta lint, formato, tipos, reglas de capas, pruebas unitarias, escaneo de secretos (gitleaks), auditoría de dependencias (pip-audit) y la construcción de la imagen Docker.

## Seguridad

Entre otras medidas: contraseñas con Argon2id fuera del event loop, JWT con rotación y revocación de refresh tokens, límites de tasa por IP y por cuenta, protección contra enumeración por tiempo de respuesta, cabeceras de seguridad, límite de tamaño de petición, usuarios de base de datos de mínimo privilegio, Redis con contraseña y dependencias fijadas y auditadas. Si encuentras una vulnerabilidad, repórtala de forma privada al autor en lugar de abrir un issue público.

## Despliegue

Hay una guía completa en [deploy/README.md](deploy/README.md): API, Redis y Caddy (HTTPS automático) en un servidor, con MongoDB Atlas.

## Estructura del repositorio

```
app/          Código de la aplicación (capas descritas arriba)
tests/        Pruebas unitarias e integración
deploy/       Compose de producción, Caddyfile y guía de despliegue
docker/       Soporte de Mongo para desarrollo local
.github/      CI y Dependabot
Dockerfile    Imagen de producción de la API
```

## Licencia

Copyright 2026 Nadia Guerra Cuessy. Distribuido bajo la [Apache License 2.0](LICENSE); consulta también el archivo [NOTICE](NOTICE).
