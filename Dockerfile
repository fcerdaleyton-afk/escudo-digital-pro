FROM python:3.11-alpine

# Evitar archivos temporales y asegurar logs en tiempo real
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Actualización de seguridad y dependencias de compilación
RUN apk update && apk upgrade && \
    apk add --no-cache --virtual .build-deps build-base libffi-dev

# Instalación de requerimientos
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

# Copiar el código y asegurar permisos
COPY . .
RUN adduser -D maryuser && \
    chown -R maryuser:maryuser /app
USER maryuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
