# 1. Imagen base ultra-ligera (Cero vulnerabilidades según Snyk)
FROM python:3.11-alpine

# 2. Directorio de trabajo
WORKDIR /app

# 3. Instalamos dependencias de compilación (Necesarias en Alpine)
# Se eliminan automáticamente al terminar para no dejar rastro
RUN apk add --no-cache --virtual .build-deps build-base libffi-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

# 4. Copiamos los requerimientos primero (para aprovechar el caché)
COPY requirements.txt .

# 5. Copiamos el resto del código de Mary V5
COPY . .

# 6. Seguridad de Élite: Usuario sin privilegios (Comando específico de Alpine)
RUN adduser -D maryuser
USER maryuser

# 7. Configuración de ejecución
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
