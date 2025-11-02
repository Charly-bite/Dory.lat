"""
Script para subir tu modelo actual de phishing a HuggingFace.
Esto te permite usar el modelo exacto que ya entrenaste, pero alojado en HF.

Instrucciones:
1. Instalar: pip install huggingface_hub
2. Obtener token de: https://huggingface.co/settings/tokens
3. Ejecutar: python upload_model_to_hf.py
"""

import os
import json
from pathlib import Path

try:
    from huggingface_hub import HfApi, create_repo, upload_file
except ImportError:
    print("❌ Error: huggingface_hub no está instalado")
    print("   Instala con: pip install huggingface_hub")
    exit(1)

# --- Configuración ---
HF_USERNAME = "Charly-bite"  # Cambia por tu username de HuggingFace
MODEL_NAME = "phishing-detector-hybrid"
REPO_ID = f"{HF_USERNAME}/{MODEL_NAME}"

# Rutas locales de tus modelos
MODEL_DIR = Path("saved_data/models")
FILES_TO_UPLOAD = {
    "HybridNN.keras": "model.keras",
    "numeric_preprocessor.pkl": "preprocessor.pkl", 
    "numeric_cols_info.json": "numeric_cols_info.json",
    "embedding_model_info.json": "embedding_model_info.json"
}

def create_model_card():
    """Crear README.md para tu modelo en HuggingFace."""
    return """---
language: en
tags:
- phishing
- email-security
- text-classification
- keras
- sentence-transformers
license: mit
---

# Phishing Email Detector - Hybrid Neural Network

Este modelo detecta emails de phishing usando un enfoque híbrido que combina:
- **Embeddings de texto** (sentence-transformers)
- **Features numéricas** (longitud, URLs, mayúsculas, etc.)
- **Red neuronal Keras** para clasificación

## Uso

```python
import requests

API_URL = "https://api-inference.huggingface.co/models/Charly-bite/phishing-detector-hybrid"
headers = {"Authorization": f"Bearer {API_TOKEN}"}

def query(payload):
    response = requests.post(API_URL, headers=headers, json=payload)
    return response.json()

output = query({
    "inputs": "URGENT: Verify your account immediately by clicking here!"
})
```

## Métricas

- **Accuracy**: ~95% (ajusta con tus métricas reales)
- **Precision**: ~93%
- **Recall**: ~94%
- **F1-Score**: ~93.5%

## Training Data

Entrenado con dataset de emails legítimos y phishing.

## Autores

Desarrollado por Charly-bite para www.dory.lat

## Licencia

MIT License
"""

def upload_to_huggingface(token):
    """Subir modelo y archivos a HuggingFace."""
    
    print(f"\n🚀 Subiendo modelo a HuggingFace...")
    print(f"   Repositorio: {REPO_ID}")
    print(f"   Directorio local: {MODEL_DIR.absolute()}\n")
    
    # Verificar que existen los archivos
    missing_files = []
    for local_file in FILES_TO_UPLOAD.keys():
        if not (MODEL_DIR / local_file).exists():
            missing_files.append(local_file)
    
    if missing_files:
        print(f"❌ Error: No se encontraron estos archivos:")
        for f in missing_files:
            print(f"   - {MODEL_DIR / f}")
        return False
    
    try:
        # Crear API
        api = HfApi(token=token)
        
        # 1. Crear repositorio (si no existe)
        print("📁 Creando repositorio...")
        try:
            create_repo(
                repo_id=REPO_ID,
                token=token,
                private=False,  # Hazlo público o privado
                exist_ok=True
            )
            print(f"   ✅ Repositorio creado/verificado: https://huggingface.co/{REPO_ID}")
        except Exception as e:
            print(f"   ⚠️  Repositorio ya existe o error: {e}")
        
        # 2. Subir README
        print("\n📝 Creando README.md...")
        readme_path = MODEL_DIR / "README.md"
        readme_path.write_text(create_model_card())
        
        api.upload_file(
            path_or_fileobj=str(readme_path),
            path_in_repo="README.md",
            repo_id=REPO_ID,
            token=token
        )
        print("   ✅ README.md subido")
        readme_path.unlink()  # Limpiar
        
        # 3. Subir archivos del modelo
        print("\n📦 Subiendo archivos del modelo...")
        for local_name, remote_name in FILES_TO_UPLOAD.items():
            local_path = MODEL_DIR / local_name
            print(f"   Subiendo {local_name} → {remote_name}...")
            
            api.upload_file(
                path_or_fileobj=str(local_path),
                path_in_repo=remote_name,
                repo_id=REPO_ID,
                token=token
            )
            print(f"   ✅ {local_name} subido correctamente")
        
        print(f"\n🎉 ¡Modelo subido exitosamente!")
        print(f"\n📍 Ver tu modelo en: https://huggingface.co/{REPO_ID}")
        print(f"\n🔗 API URL: https://api-inference.huggingface.co/models/{REPO_ID}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error durante la subida: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("  Subir Modelo de Phishing a HuggingFace")
    print("=" * 60)
    
    # Solicitar token
    print("\n🔑 Necesitas un token de HuggingFace:")
    print("   1. Ve a: https://huggingface.co/settings/tokens")
    print("   2. Click en 'New token'")
    print("   3. Nombre: dory-upload (o cualquier nombre)")
    print("   4. Tipo: 'Write' (necesario para subir)")
    print("   5. Copia el token\n")
    
    token = input("📋 Pega tu token aquí (o presiona Enter para usar variable HF_TOKEN): ").strip()
    
    if not token:
        token = os.environ.get("HF_TOKEN")
        if not token:
            print("❌ No se encontró token. Configura HF_TOKEN o ingresa uno.")
            return
    
    # Verificar token
    if not token.startswith("hf_"):
        print("⚠️  Advertencia: El token debería empezar con 'hf_'")
        confirm = input("   ¿Continuar de todos modos? (y/N): ").strip().lower()
        if confirm != 'y':
            print("Cancelado.")
            return
    
    # Confirmar
    print(f"\n📊 Resumen:")
    print(f"   Usuario HF: {HF_USERNAME}")
    print(f"   Nombre modelo: {MODEL_NAME}")
    print(f"   Repositorio: {REPO_ID}")
    print(f"   Archivos a subir: {len(FILES_TO_UPLOAD)}")
    
    confirm = input("\n¿Proceder con la subida? (y/N): ").strip().lower()
    if confirm != 'y':
        print("Cancelado.")
        return
    
    # Subir
    success = upload_to_huggingface(token)
    
    if success:
        print("\n" + "=" * 60)
        print("  SIGUIENTE PASO")
        print("=" * 60)
        print("\n1. Ve a Render dashboard: https://dashboard.render.com")
        print("2. Agrega variable de entorno:")
        print(f"   Key: HF_API_TOKEN")
        print(f"   Value: {token[:10]}... (tu token)")
        print("\n3. Actualiza app_hf.py:")
        print(f"   YOUR_MODEL = '{REPO_ID}'")
        print("\n4. Deploy:")
        print("   git add .")
        print("   git commit -m 'Use HuggingFace hosted model'")
        print("   git push")
        print("\n✅ Tu app estará lista en 2-3 minutos!")

if __name__ == "__main__":
    main()
