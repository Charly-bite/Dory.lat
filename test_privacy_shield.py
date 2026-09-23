#!/usr/bin/env python3
"""
test_privacy_shield.py - Pruebas Unitarias del Escudo de Privacidad PII
"""

import sys
import os

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from privacy_shield import PrivacyShield, luhn_checksum
from app_hf import predict_phishing_hf

def test_privacy_shield_comprehensive():
    print("=" * 70)
    print("EJECUTANDO PRUEBAS DEL ESCUDO DE PRIVACIDAD (PII SANITIZER)")
    print("=" * 70)

    # 1. Prueba de Luhn Checksum
    assert luhn_checksum("4532015112830366") is True, "Visa válida debe pasar Luhn"
    assert luhn_checksum("1234567890123456") is False, "Número aleatorio no debe pasar Luhn"
    print("✅ [PASS] Algoritmo de Luhn para tarjetas de crédito/débito validado.")

    # 2. Prueba de Enmascaramiento Integral
    sample_text = """
    Estimado Juan Perez Gonzalez:
    Le informamos que su RFC ACCC891024XX1 y CURP ACCC891024HDFRRL09 presentan un saldo vencido.
    Su tarjeta Visa 4532-0151-1283-0366 y cuenta CLABE 012180004567890123 han sido pausadas.
    Para reactivar su acceso, ingrese su contraseña temporal: password=TemporalPass2026!
    Puede comunicarse a nuestro whatsapp: +52 33 1234 5678 o al correo carlos.aceves@quimicaboss.com.mx.
    Enlace de desbloqueo: https://sat-consultas-falso.online/login?session=abc123xyz
    """

    res = PrivacyShield.anonymize_text(sample_text)
    sanitized = res['sanitized_text']
    
    print("\n--- TEXTO SANITIZADO GENERADO ---")
    print(sanitized.strip())
    print("-" * 70)

    # Verificaciones de anonimización
    assert "4532-0151-1283-0366" not in sanitized, "La tarjeta real no debe existir en el texto"
    assert "[TARJETA_PROTEGIDA]" in sanitized, "Debe contener el token [TARJETA_PROTEGIDA]"

    assert "ACCC891024XX1" not in sanitized, "El RFC no debe existir"
    assert "[RFC_PROTEGIDO]" in sanitized, "Debe contener el token [RFC_PROTEGIDO]"

    assert "ACCC891024HDFRRL09" not in sanitized, "El CURP no debe existir"
    assert "[CURP_PROTEGIDO]" in sanitized, "Debe contener el token [CURP_PROTEGIDO]"

    assert "012180004567890123" not in sanitized, "La CLABE no debe existir"
    assert "[CLABE_PROTEGIDA]" in sanitized, "Debe contener el token [CLABE_PROTEGIDA]"

    assert "TemporalPass2026!" not in sanitized, "El password no debe existir"
    assert "[PASSWORD_PROTEGIDO]" in sanitized, "Debe contener el token [PASSWORD_PROTEGIDO]"

    assert "carlos.aceves@quimicaboss.com.mx" not in sanitized, "El correo corporativo no debe existir"
    assert "[CORREO_EMPLEADO_PROTEGIDO]" in sanitized, "Debe contener el token de correo"

    assert "Juan Perez" not in sanitized, "El nombre de la persona debe estar protegido"

    # Verificación crítica: EL ENLACE MALICIOSO DEBE PERMANECER INTACTO
    assert "https://sat-consultas-falso.online/login?session=abc123xyz" in sanitized, \
        "El enlace malicioso debe mantenerse íntegro para análisis forense"

    print(f"✅ [PASS] Entidades anonimizadas detectadas: {len(res['redacted_entities'])}")
    for ent in res['redacted_entities']:
        print(f"   - {ent['category']}: {ent['preview']} -> {ent['token']}")

    # 3. Verificación de Preservación de Señal de Phishing con Dory AI
    print("\n--- EVALUANDO DETECCIÓN DE PHISHING CON TEXTO SANITIZADO ---")
    prediction = predict_phishing_hf(sanitized)
    print(f"Dictamen: {'PHISHING' if prediction['is_phishing'] else 'LEGÍTIMO'} | Score: {prediction['risk_score']}/100")
    print(f"Amenazas detectadas: {prediction.get('threats', [])}")
    
    assert prediction['is_phishing'] is True, "El correo debe seguir siendo clasificado como PHISHING"
    assert prediction['risk_score'] >= 80, "La puntuación de riesgo debe ser alta (> 80)"
    print("✅ [PASS] El motor de IA detecta el phishing con máxima precisión sobre el texto anonimizado.")

    print("\n" + "=" * 70)
    print("¡TODAS LAS PRUEBAS DEL ESCUDO DE PRIVACIDAD COMPLETADAS CON ÉXITO!")
    print("=" * 70)

if __name__ == '__main__':
    test_privacy_shield_comprehensive()
