# Imagen del motor Dory (app_hf + dory_engine + clasificador ML v4)
# Antes: Python 3.9 + requirements.txt (TensorFlow) + app:app legado, distinto de lo que corre en producción.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NAME=Dory-Lat

WORKDIR /app

COPY requirements_hf.txt .
RUN pip install --no-cache-dir -r requirements_hf.txt

COPY . .

# Usuario sin privilegios
RUN useradd --create-home --uid 10001 dory && chown -R dory /app
USER dory

EXPOSE 5000

# Pocos workers + hilos: el modelo se carga una vez por proceso (~2 s) y la inferencia es ligera
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "60", "app_hf:app"]
