import os

# Archivos exactos mapeados por el agente
archivos = [
    "app/api/schemas/analysis.py", "app/api/v1/analysis.py", "app/engine/url_extractor.py",
    "app/clients/base.py", "app/clients/google_web_risk.py", "app/clients/virustotal.py",
    "app/clients/phishtank.py", "app/services/analysis_service.py", "app/engine/url_heuristics.py",
    "app/engine/public_suffixes.py", "app/engine/text_heuristics.py", "app/engine/scoring.py",
    "app/engine/models.py", "app/engine/risk_levels.py", "app/engine/recommendations.py",
    "app/repositories/redis/reputation_cache.py", "app/repositories/redis/quota_repository.py",
    "app/repositories/mongo/unit_of_work.py", "app/repositories/mongo/analysis_repository.py",
    "app/repositories/mongo/metrics_repository.py", "app/services/metrics_service.py",
    "app/api/v1/metrics.py", "app/api/schemas/metrics.py", "app/core/security.py",
    "app/repositories/mongo/user_repository.py", "app/services/auth_service.py",
    "app/api/v1/auth.py", "app/api/schemas/auth.py", "app/repositories/redis/verification_repository.py",
    "app/clients/resend_email.py", "app/services/verification_service.py", "app/clients/google_identity.py",
    "app/api/deps.py", "app/repositories/mongo/init_db.py", "tests/performance/locustfile.py",
    "app/core/logging.py", "app/core/exceptions.py", "app/api/errors.py",
    "app/repositories/redis/rate_limit_repository.py", "app/services/rate_limiter.py",
    "app/repositories/mongo/rules_repository.py", "app/services/rules_provider.py",
    "app/repositories/mongo/initial_data.json", "app/api/v1/health.py", "app/main.py",
    "app/container.py", "app/core/config.py"
]

for ruta in archivos:
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    if not os.path.exists(ruta):
        with open(ruta, 'w') as f:
            pass
            
print("Estructura base creada con éxito.")