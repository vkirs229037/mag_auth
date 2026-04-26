FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
# Если нужен конфиг из deploy-config – он уже скопирован в build-context
# COPY nginx.conf /etc/something...
EXPOSE 5000
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]