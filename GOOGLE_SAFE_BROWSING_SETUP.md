# 🔐 Configurar Google Safe Browsing API

## 📋 Resumen

Google Safe Browsing API permite verificar URLs contra una base de datos de millones de sitios maliciosos conocidos. Es **gratuito** hasta 10,000 requests por día.

---

## 🚀 Pasos para Obtener API Key

### 1. Crear Proyecto en Google Cloud

1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Inicia sesión con tu cuenta de Google
3. Haz clic en **"Select a project"** → **"New Project"**
4. Nombre del proyecto: `dory-phishing-detector` (o el que prefieras)
5. Haz clic en **"Create"**

### 2. Habilitar Safe Browsing API

1. En el menú lateral, ve a **"APIs & Services"** → **"Library"**
2. Busca: **"Safe Browsing API"**
3. Haz clic en **"Safe Browsing API"**
4. Haz clic en **"Enable"**

### 3. Crear API Key

1. Ve a **"APIs & Services"** → **"Credentials"**
2. Haz clic en **"+ CREATE CREDENTIALS"**
3. Selecciona **"API Key"**
4. Copia la API key generada (guárdala en un lugar seguro)

### 4. Restricciones de Seguridad (Recomendado)

Para proteger tu API key:

1. Haz clic en el ícono de edición (✏️) junto a tu API key
2. En **"API restrictions"**:
   - Selecciona **"Restrict key"**
   - Marca solo **"Safe Browsing API"**
3. En **"Application restrictions"** (opcional):
   - Selecciona **"HTTP referrers"**
   - Agrega: `www.dory.lat/*`
4. Haz clic en **"Save"**

---

## 🔧 Configurar en Render

### Opción 1: Dashboard de Render

1. Ve a [Render Dashboard](https://dashboard.render.com/)
2. Selecciona tu servicio `dory-lat-app`
3. Ve a **"Environment"**
4. Haz clic en **"Add Environment Variable"**
5. Agrega:
   - **Key:** `GOOGLE_SAFE_BROWSING_API_KEY`
   - **Value:** Tu API key de Google
6. Haz clic en **"Save Changes"**
7. Render redesplegará automáticamente

### Opción 2: Archivo render.yaml

Edita `render.yaml` y agrega:

```yaml
services:
  - type: web
    name: dory-lat-app
    env: python
    region: oregon
    plan: free
    buildCommand: pip install -r requirements_hf.txt
    startCommand: gunicorn --bind 0.0.0.0:$PORT --timeout 60 --workers 2 --threads 2 app_hf:app
    envVars:
      - key: HF_API_TOKEN
        sync: false
      - key: GOOGLE_SAFE_BROWSING_API_KEY
        sync: false
```

Luego establece el valor en el dashboard de Render.

---

## ✅ Verificar Instalación

### Test 1: Health Check

```bash
curl https://www.dory.lat/health | jq
```

**Respuesta esperada:**
```json
{
  "status": "healthy",
  "service": "dory-phishing-detector-hf",
  "version": "2.2-google-safe-browsing",
  "features": {
    "enhanced_heuristics": true,
    "google_safe_browsing": true,  ← Debe ser true
    "bilingual_support": true
  }
}
```

### Test 2: URL Maliciosa Conocida

```bash
curl -X POST https://www.dory.lat/predict \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email_text=Click here: http://testsafebrowsing.appspot.com/s/malware.html' \
  | jq '.google_safe_browsing'
```

**Respuesta esperada:**
```json
{
  "checked": true,
  "is_safe": false,
  "malicious_urls": ["http://testsafebrowsing.appspot.com/s/malware.html"],
  "threats_found": ["Malware"]
}
```

### Test 3: URL Legítima

```bash
curl -X POST https://www.dory.lat/predict \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email_text=Visit us at https://www.google.com' \
  | jq '.google_safe_browsing'
```

**Respuesta esperada:**
```json
{
  "checked": true,
  "is_safe": true,
  "malicious_urls": [],
  "threats_found": []
}
```

---

## 📊 Límites y Cuotas

| Límite | Valor | Costo |
|--------|-------|-------|
| **Requests por día** | 10,000 | Gratis |
| **Requests adicionales** | Por 1,000 | $0.25 USD |
| **Lookup API (recomendado)** | Ilimitado | $1.00/1,000 usuarios |

**Para este proyecto:** 10,000 requests/día son más que suficientes.

---

## 🔐 Seguridad de la API Key

### ✅ HACER:
- ✅ Almacenar en variables de entorno
- ✅ Usar restricciones de API (solo Safe Browsing)
- ✅ Restringir por dominio (www.dory.lat)
- ✅ Rotar la key periódicamente (cada 6 meses)

### ❌ NO HACER:
- ❌ Hardcodear en el código
- ❌ Commitear al repositorio Git
- ❌ Compartir públicamente
- ❌ Usar sin restricciones

---

## 🐛 Troubleshooting

### Problema: `google_safe_browsing.checked = false`

**Causa:** API key no configurada

**Solución:**
1. Verifica que `GOOGLE_SAFE_BROWSING_API_KEY` esté en variables de entorno
2. Reinicia el servicio en Render
3. Verifica con `curl https://www.dory.lat/health`

### Problema: Error 403 "API key not valid"

**Causa:** API key incorrecta o restricciones muy estrictas

**Solución:**
1. Verifica que copiaste la key completa
2. Revisa las restricciones de la API en Google Cloud
3. Asegúrate de que Safe Browsing API esté habilitada

### Problema: Error 429 "Quota exceeded"

**Causa:** Superaste el límite de 10,000 requests/día

**Solución:**
1. Espera hasta el siguiente día (reset a medianoche PST)
2. O habilita facturación en Google Cloud para requests adicionales
3. Implementa caché de resultados para reducir llamadas

### Problema: Timeout en la API

**Causa:** Google Safe Browsing no responde a tiempo

**Solución:**
- La app ya maneja esto con un timeout de 5 segundos
- Si falla, continúa con heurísticas normales
- No afecta la funcionalidad principal

---

## 📈 Monitoreo de Uso

### Ver Estadísticas en Google Cloud

1. Ve a **"APIs & Services"** → **"Dashboard"**
2. Selecciona **"Safe Browsing API"**
3. Verás gráficos de:
   - Requests por día
   - Errores
   - Latencia

### Logs en Render

```bash
# Ver logs en tiempo real
render logs --service dory-lat-app --tail
```

Busca líneas como:
```
Google Safe Browsing API error: 403
Google Safe Browsing API timeout
```

---

## 🎯 Beneficios de Google Safe Browsing

### ✅ Ventajas

1. **Base de datos masiva:** Millones de URLs maliciosas conocidas
2. **Actualización constante:** Google actualiza la DB continuamente
3. **Alta precisión:** Usado por Chrome, Firefox, Safari
4. **Múltiples amenazas:** Malware, phishing, software no deseado
5. **Gratis hasta 10k/día:** Ideal para proyectos pequeños-medianos
6. **Baja latencia:** Respuestas en <1 segundo
7. **Respaldo confiable:** Infraestructura de Google

### 📊 Tipos de Amenazas Detectadas

- **MALWARE:** Sitios que distribuyen malware
- **SOCIAL_ENGINEERING:** Sitios de phishing
- **UNWANTED_SOFTWARE:** Software potencialmente no deseado
- **POTENTIALLY_HARMFUL_APPLICATION:** Apps móviles dañinas

---

## 🔄 Alternativas (Si no quieres usar Google)

### 1. PhishTank API
- **Gratis:** Sí
- **Límite:** Ilimitado (descarga diaria de DB)
- **Precisión:** Media (depende de reportes de usuarios)

### 2. VirusTotal API
- **Gratis:** 4 requests/minuto
- **Límite:** Muy bajo para producción
- **Precisión:** Alta (agrega múltiples servicios)

### 3. URLScan.io
- **Gratis:** Sí (con límites)
- **Límite:** 10,000/mes
- **Precisión:** Alta

**Recomendación:** Google Safe Browsing es la mejor opción para este proyecto.

---

## 📝 Checklist de Configuración

- [ ] Crear proyecto en Google Cloud
- [ ] Habilitar Safe Browsing API
- [ ] Generar API key
- [ ] Aplicar restricciones de seguridad
- [ ] Agregar variable de entorno en Render
- [ ] Verificar health check (`google_safe_browsing: true`)
- [ ] Probar con URL maliciosa de test
- [ ] Probar con URL legítima
- [ ] Verificar que aparezca en lista de amenazas
- [ ] Documentar la API key en lugar seguro

---

## 🎓 URLs de Test de Google

Google proporciona URLs de test que **siempre** devuelven positivo:

```
http://testsafebrowsing.appspot.com/s/malware.html        → MALWARE
http://testsafebrowsing.appspot.com/s/phishing.html       → SOCIAL_ENGINEERING
http://testsafebrowsing.appspot.com/s/unwanted.html       → UNWANTED_SOFTWARE
```

**Úsalas para probar** que la integración funciona correctamente.

---

**¿Listo para configurar?** Sigue los pasos y en 10 minutos tendrás Google Safe Browsing funcionando! 🚀
