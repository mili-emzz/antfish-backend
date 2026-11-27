"""Generador de recomendaciones de seguridad (1 a 3 recomendaciones).

Basado en el nivel de riesgo y los hallazgos específicos detectados.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.engine.models import Finding, RiskLevel


def generate_recommendations(
    risk_level: RiskLevel,
    findings: Sequence[Finding],
) -> list[str]:
    """Genera de 1 a 3 recomendaciones de acción directas para el usuario."""
    finding_codes = {f.regla_codigo for f in findings}
    recs: list[str] = []

    if risk_level == RiskLevel.CRITICO:
        recs.append("No accedas al enlace bajo ninguna circunstancia.")
        if "TXT_SOLICITUD_DATOS" in finding_codes or "URL_SUBDOMINIO_ENGANOSO" in finding_codes:
            recs.append("No compartas contraseñas, PIN, NIP ni información bancaria confidencial.")
        else:
            recs.append("No descargues archivos ni autorices ningún permiso en el sitio.")
        recs.append(
            "Si dudas de la autenticidad, contacta a la institución exclusivamente por sus canales oficiales."
        )

    elif risk_level == RiskLevel.ALTO:
        recs.append(
            "Evita ingresar al enlace; presenta múltiples indicadores de riesgo o suplantación."
        )
        if "TXT_LENGUAJE_URGENCIA" in finding_codes:
            recs.append(
                "Los atacantes suelen usar urgencia falsa para apresurar decisiones; tómate un momento para verificar."
            )
        else:
            recs.append(
                "Verifica la autenticidad del remitente a través de su aplicación oficial o teléfono oficial."
            )
        recs.append("Nunca proporciones códigos de verificación recibidos por SMS o aplicaciones.")

    elif risk_level == RiskLevel.MEDIO:
        recs.append(
            "Procede con precaución: el mensaje contiene patrones sospechosos o enlaces acortados."
        )
        recs.append(
            "Revisa minuciosamente la barra de direcciones del navegador antes de interactuar."
        )
        if "URL_ACORTADOR" in finding_codes:
            recs.append(
                "El enlace está acortado y oculta su destino real; no abras la página si no esperabas este mensaje."
            )

    else:  # BAJO
        recs.append("No se detectaron indicadores evidentes de fraude en el enlace o mensaje.")
        recs.append(
            "Mantén siempre precaución ante solicitudes no solicitadas de información personal."
        )

    # Retornar como máximo 3 recomendaciones
    return recs[:3]
