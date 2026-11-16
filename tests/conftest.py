"""Configuración global de pruebas: secretos aleatorios por ejecución (nunca fijos en el repo)."""

import os
import secrets

# Deben definirse antes de importar app.core.config (los secretos son obligatorios).
for _name in ("HMAC_PEPPER", "JWT_SECRET", "JWT_REFRESH_SECRET"):
    os.environ[_name] = secrets.token_urlsafe(48)
