# Despliegue en producción (un servidor AWS + MongoDB Atlas)

Arquitectura: **Caddy** (HTTPS automático) → **API** (FastAPI) → **Redis** (contenedor interno con clave) y **MongoDB Atlas** (gestionado).
Solo Caddy publica puertos (80/443). La API y Redis viven en una red interna de Docker.

## 1. MongoDB Atlas
1. Crea un cluster en la **misma región de AWS** que el servidor. Para empezar sirve el plan gratuito (M0); para producción real conviene uno de pago con respaldos. Comprueba que el plan admite transacciones (la app exige replica set).
2. Crea dos usuarios de base de datos (autenticación por contraseña, claves largas y aleatorias):
   - `antfish_app`: rol **readWrite** sobre `antfish_db` (lo usa la API).
   - `antfish_migrator`: **readWrite + dbAdmin** sobre `antfish_db` (solo para `init_db`).
3. *Network Access*: añade **solo la IP elástica del servidor** (paso 2). No uses `0.0.0.0/0`.
4. Copia la cadena `mongodb+srv://...` para `MONGODB_URL` y `MONGODB_MIGRATION_URL`.

## 2. Servidor (EC2 o Lightsail)
1. Instancia Linux pequeña (p. ej. Ubuntu 24.04, 1-2 GB de RAM; revisa en tu cuenta qué cubre el plan gratuito o los créditos de AWS). Asigna una **IP elástica** (en Lightsail, IP estática).
2. Firewall / grupo de seguridad: entrada **80 y 443** abiertas al mundo; **22 (SSH) solo desde tu IP**. Nada más.
3. DNS: registro **A** de tu dominio (`api.tu-dominio.com`) hacia esa IP. Caddy necesita que resuelva antes de arrancar para obtener el certificado.
4. Instala Docker y el plugin Compose (guía oficial de Docker para tu distribución) y clona el repositorio (`develop` o `main`).

## 3. Configuración
```bash
cd deploy
cp env.production.example .env.production
chmod 600 .env.production
# genera cada secreto con: openssl rand -hex 32   (usa hex, sin caracteres especiales)
nano .env.production
```
Rellena `DOMAIN`, `ACME_EMAIL`, las URLs de Atlas, `REDIS_PASSWORD`, `HMAC_PEPPER`, `JWT_SECRET`, `JWT_REFRESH_SECRET` (≥32 caracteres y **distintos entre sí**; la app no arranca con valores débiles o de ejemplo), y las claves de Resend, Web Risk, VirusTotal y `GOOGLE_CLIENT_ID`.
`.env.production` está ignorado por git: **nunca lo subas**. Guarda una copia de los secretos en un gestor (AWS Secrets Manager, Bitwarden, etc.).

## 4. Primer arranque
```bash
cd deploy
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
# Migraciones e índices + siembra del catálogo (una vez, y tras cada cambio de esquema):
docker compose --env-file .env.production -f docker-compose.prod.yml exec api \
  python -m app.repositories.mongo.init_db
```
`init_db` usa `MONGODB_MIGRATION_URL` (usuario `antfish_migrator`); la API en ejecución usa el usuario `antfish_app`, sin permisos de esquema.

Verifica:
```bash
curl -i https://api.tu-dominio.com/health      # 200 {"status":"ok"}
docker compose --env-file .env.production -f docker-compose.prod.yml ps
```
Con `ENVIRONMENT=production` `/docs` y `/openapi.json` responden 404 y se activan HSTS y CSP.

## 5. Actualizar a una versión nueva
```bash
git pull
cd deploy
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
# si hubo cambios de esquema: repetir init_db
```

## 6. Operación
- **Logs:** `docker compose ... logs -f api` (una línea JSON por registro; nunca llevan SMS ni secretos).
- **Redis** guarda sesiones (refresh tokens), contadores de tasa y códigos. Tiene persistencia AOF y política `noeviction`; reiniciar el servidor no cierra sesiones. Si se pierde el volumen, los usuarios deberán iniciar sesión de nuevo.
- **Respaldos:** los de Mongo los gestiona Atlas (según plan). Redis no requiere respaldo.
- **Rotar secretos:** cambiar `JWT_SECRET`/`JWT_REFRESH_SECRET` cierra todas las sesiones; cambiar `HMAC_PEPPER` invalida los hashes de mensajes ya guardados y los códigos pendientes.
- **Parches del sistema:** actualiza el SO del servidor periódicamente y reconstruye la imagen (`up -d --build`) para recibir actualizaciones de la imagen base.

## Qué NO cubre esta guía
Balanceo/alta disponibilidad (un solo servidor), TLS interno entre contenedores (la red es privada del host) y autoescalado. Si necesitas eso, el mismo `Dockerfile` sirve para ECS Fargate, con Redis en ElastiCache.
