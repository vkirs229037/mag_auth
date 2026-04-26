# auth-service/Dockerfile
FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./app.py
# Конфигурационный файл будет монтироваться или подкладываться при старте,
# здесь не копируем (образ универсален)
EXPOSE 5000
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]
