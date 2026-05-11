# Usamos una imagen ultra-ligera y segura
FROM python:3.11-slim

# Directorio de trabajo
WORKDIR /app

# Instalamos dependencias del sistema mínimas
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copiamos y blindamos requerimientos
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos el código
COPY . .

# No corremos como root (Seguridad Élite)
RUN useradd -m maryuser
USER maryuser

# Puerto
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
