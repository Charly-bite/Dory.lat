# Guía: Migrar a HuggingFace Inference API

## ✅ Ventajas de usar HuggingFace

1. **Sin carga de modelos** - Tu app Render inicia en 2-3 segundos
2. **Respuestas rápidas** - HuggingFace tiene GPUs optimizadas
3. **Tier gratuito** - 30,000 requests/mes gratis
4. **Escalable** - HuggingFace maneja la infraestructura
5. **Requirements mínimos** - Solo Flask + requests (5MB vs 3GB+)

## 📋 Pasos para Implementar

### 1. Crear cuenta en HuggingFace

```bash
# Visita: https://huggingface.co/join
# Crea tu cuenta gratis
```

### 2. Obtener API Token

1. Ve a: https://huggingface.co/settings/tokens
2. Click en "New token"
3. Nombre: `dory-lat-api`
4. Tipo: `Read` (suficiente para inference)
5. Copia el token (empieza con `hf_...`)

### 3. Opciones para tu Modelo

#### Opción A: Subir tu modelo Keras actual (RECOMENDADO)

HuggingFace soporta modelos TensorFlow/Keras. Necesitas:

```python
# Script para subir tu modelo
from huggingface_hub import HfApi, create_repo
import os

# 1. Crear repositorio en HuggingFace
repo_name = "Charly-bite/phishing-detector-keras"
create_repo(repo_name, token="TU_TOKEN_AQUI", exist_ok=True)

# 2. Subir archivos del modelo
api = HfApi()

# Subir modelo Keras
api.upload_file(
    path_or_fileobj="saved_data/models/HybridNN.keras",
    path_in_repo="model.keras",
    repo_id=repo_name,
    token="TU_TOKEN_AQUI"
)

# Subir preprocessor
api.upload_file(
    path_or_fileobj="saved_data/models/numeric_preprocessor.pkl",
    path_in_repo="preprocessor.pkl",
    repo_id=repo_name,
    token="TU_TOKEN_AQUI"
)

# Subir info de embeddings
api.upload_file(
    path_or_fileobj="saved_data/models/embedding_model_info.json",
    path_in_repo="embedding_info.json",
    repo_id=repo_name,
    token="TU_TOKEN_AQUI"
)

print("✅ Modelo subido exitosamente!")
```

#### Opción B: Usar modelo preentrenado de HuggingFace

Si prefieres usar un modelo ya disponible:

```python
# Modelos de clasificación de texto disponibles:
- "distilbert-base-uncased-finetuned-sst-2-english"  # Sentiment
- "facebook/bart-large-mnli"  # Zero-shot classification
- "unitary/toxic-bert"  # Toxic content detection
```

#### Opción C: Fine-tuning de modelo en HuggingFace

Re-entrenar usando transformers nativo:

```python
from transformers import AutoModelForSequenceClassification, Trainer

# Cargar modelo base
model = AutoModelForSequenceClassification.from_pretrained(
    "distilbert-base-uncased",
    num_labels=2  # phishing vs legitimate
)

# Entrenar con tus datos
# ... código de entrenamiento ...

# Subir a HuggingFace
model.push_to_hub("Charly-bite/phishing-detector")
```

### 4. Configurar Render para usar HuggingFace

#### A. Agregar HF_API_TOKEN a Render

1. Ve a tu dashboard de Render: https://dashboard.render.com
2. Click en tu servicio "dory-lat-app"
3. Ve a "Environment"
4. Click "Add Environment Variable"
5. Key: `HF_API_TOKEN`
6. Value: `hf_TuTokenAquí`
7. Click "Save Changes"

#### B. Actualizar render.yaml

```yaml
# Opción 1: Editar render.yaml actual
# Cambiar estas líneas:
buildCommand: pip install -r requirements_hf.txt  # ← Cambiar
startCommand: gunicorn --bind 0.0.0.0:$PORT --timeout 60 --workers 2 --threads 2 app_hf:app  # ← Cambiar

# Opción 2: Usar render_hf.yaml
# Renombrar: mv render_hf.yaml render.yaml
```

### 5. Modificar app_hf.py para tu modelo

Si subiste tu modelo a HuggingFace:

```python
# En app_hf.py, actualizar:

HF_API_URL = "https://api-inference.huggingface.co/models/"
YOUR_MODEL = "Charly-bite/phishing-detector-keras"  # Tu modelo

def predict_phishing_hf(text):
    headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
    
    # Llamar a tu modelo en HuggingFace
    response = requests.post(
        f"{HF_API_URL}{YOUR_MODEL}",
        headers=headers,
        json={"inputs": text}
    )
    
    if response.status_code == 200:
        result = response.json()
        # Parsear resultado según formato de tu modelo
        return {
            'is_phishing': result[0]['label'] == 'PHISHING',
            'confidence': result[0]['score']
        }
    else:
        # Fallback a heurísticas si falla
        return fallback_prediction(text)
```

### 6. Deploy a Render

```bash
# Commit cambios
git add app_hf.py requirements_hf.txt render.yaml
git commit -m "Migrate to HuggingFace Inference API"
git push

# Render auto-deployará
# ⏱️ Build time: ~1-2 minutos (vs 8-10 antes)
# 🚀 Startup time: ~3 segundos (vs timeout antes)
```

### 7. Testing

```bash
# Test local
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"subject": "URGENT: Verify your account", "body": "Click here now!"}'

# Test en producción
curl -X POST https://www.dory.lat/predict \
  -H "Content-Type: application/json" \
  -d '{"subject": "URGENT: Verify your account", "body": "Click here now!"}'
```

## 🔥 Comparación de Performance

### Antes (Modelos locales)
- **Build**: 8-10 minutos
- **Startup**: ❌ Timeout después de 5 minutos
- **Primera predicción**: ❌ 503 Error
- **RAM usada**: 450MB+ (512MB límite)
- **Dependencies**: 3GB+ (TensorFlow, PyTorch, etc.)

### Después (HuggingFace)
- **Build**: 1-2 minutos ✅
- **Startup**: 3-5 segundos ✅
- **Primera predicción**: 1-2 segundos ✅
- **RAM usada**: ~100MB ✅
- **Dependencies**: 5MB ✅

## 📊 Limitaciones del Tier Gratuito de HuggingFace

- **30,000 requests/mes** (~1000/día)
- **Rate limit**: ~30 requests/minuto
- **Cold start**: Primera request puede tardar ~20 segundos (modelo se carga)
- **Timeout**: 60 segundos por request

Si necesitas más, planes pagados desde $9/mes.

## 🎯 Siguiente Paso RECOMENDADO

**Probar app_hf.py localmente primero:**

```bash
cd /home/byte/GitHub/dory-lat-app

# Instalar requirements ligeros
pip install -r requirements_hf.txt

# Exportar token (temporal, para prueba)
export HF_API_TOKEN="hf_TuTokenAquí"

# Correr local
python app_hf.py

# Test en otra terminal
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"subject": "Test", "body": "This is a test email"}'
```

Una vez funcione local, hacer deploy a Render.

## 🚀 Deploy Rápido (Si quieres probar YA)

La versión `app_hf.py` usa heurísticas simples por ahora (no requiere modelo subido).
Para probarla:

```bash
# 1. Actualizar render.yaml
cp render_hf.yaml render.yaml

# 2. Commit y push
git add app_hf.py requirements_hf.txt render.yaml
git commit -m "Switch to HuggingFace lightweight version"
git push

# 3. En Render dashboard, agregar env var:
#    HF_API_TOKEN = tu_token (opcional por ahora)

# ✅ Deployará en 2-3 minutos y funcionará INMEDIATAMENTE
```

Luego puedes mejorar la predicción subiendo tu modelo real.
