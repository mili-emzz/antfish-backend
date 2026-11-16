from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SECRET_LENGTH = 32
_PLACEHOLDER_MARKERS = ("change", "cambia", "default", "changeme", "example", "secret_key")


class Settings(BaseSettings):
    PROJECT_NAME: str = "AntFish API"
    ENVIRONMENT: Literal["development", "production"] = "development"
    MONGODB_URL: str = "mongodb://localhost:27017"
    # Usuario con privilegios de esquema (collMod, índices); solo para init_db (no la API).
    MONGODB_MIGRATION_URL: str = ""
    DATABASE_NAME: str = "antfish_db"
    REDIS_URL: str = "redis://localhost:6379"
    RESEND_API_KEY: str = ""
    EMAIL_FROM: str = "no-reply@antfish.xyz"
    # Client ID (OAuth web) con el que Google emite el ID token (aud). Vacío = POST /auth/google responde 503.
    GOOGLE_CLIENT_ID: str = ""

    # Secretos obligatorios, sin valor por defecto (RNF-03, RNF-05): la app no arranca sin ellos.
    HMAC_PEPPER: str
    JWT_SECRET: str
    JWT_REFRESH_SECRET: str

    # JWT Settings (RF-06.8, RNF-03)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # Credenciales de APIs externas de inteligencia de amenazas (RF-02.2)
    GOOGLE_WEB_RISK_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    PHISHTANK_API_KEY: str = ""
    # PhishTank deshabilitado por defecto: su API devuelve 403 (Cloudflare) y no emite claves nuevas.
    # Con False no se consulta ni cuenta como fallo; el código del cliente se conserva.
    PHISHTANK_ENABLED: bool = False
    REPUTATION_CLIENT_TIMEOUT: float = 1.5
    # TTL del caché de reputación rep:{url_normalizada} (RF-04.1).
    REPUTATION_CACHE_TTL_SECONDS: int = 3600

    # Cuota dual por API externa: por minuto y diaria (P5). Ajustar al plan contratado.
    QUOTA_GOOGLE_WEB_RISK_PM: int = 60
    QUOTA_GOOGLE_WEB_RISK_DAILY: int = 5000
    QUOTA_VIRUSTOTAL_PM: int = 4
    QUOTA_VIRUSTOTAL_DAILY: int = 500
    QUOTA_PHISHTANK_PM: int = 20
    QUOTA_PHISHTANK_DAILY: int = 2000

    # Catálogo de reglas y marcas en memoria (CU-11): TTL y reintento tras un fallo de carga.
    RULES_CACHE_TTL_SECONDS: int = 3600
    RULES_RETRY_SECONDS: int = 30

    # Rate limiting de endpoints (DP-04): ventana fija de 60 s.
    RATE_LIMIT_AUTH_PER_MIN: int = 5
    RATE_LIMIT_ANALYSIS_PER_MIN: int = 20
    RATE_LIMIT_RESEND_PER_HOUR: int = 3

    def quota_limits(self) -> dict[str, tuple[int, int]]:
        """Devuelve {api: (limite_por_minuto, limite_diario)}."""
        return {
            "google_web_risk": (self.QUOTA_GOOGLE_WEB_RISK_PM, self.QUOTA_GOOGLE_WEB_RISK_DAILY),
            "virustotal": (self.QUOTA_VIRUSTOTAL_PM, self.QUOTA_VIRUSTOTAL_DAILY),
            "phishtank": (self.QUOTA_PHISHTANK_PM, self.QUOTA_PHISHTANK_DAILY),
        }

    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", hide_input_in_errors=True
    )

    @field_validator("HMAC_PEPPER", "JWT_SECRET", "JWT_REFRESH_SECRET")
    @classmethod
    def _validate_secret_strength(cls, value: str, info) -> str:  # type: ignore[no-untyped-def]
        """Rechaza secretos cortos o que parezcan placeholders (sin mostrar su valor)."""
        if len(value) < MIN_SECRET_LENGTH:
            raise ValueError(
                f"{info.field_name} debe tener al menos {MIN_SECRET_LENGTH} caracteres"
            )
        if any(marker in value.lower() for marker in _PLACEHOLDER_MARKERS):
            raise ValueError(f"{info.field_name} parece un valor de ejemplo; genere uno aleatorio")
        return value

    @model_validator(mode="after")
    def _validate_distinct_jwt_secrets(self) -> "Settings":
        if self.JWT_SECRET == self.JWT_REFRESH_SECRET:
            raise ValueError("JWT_SECRET y JWT_REFRESH_SECRET deben ser distintos")
        return self


settings = Settings()  # type: ignore[call-arg]
