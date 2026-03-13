FROM python:3.11-slim
WORKDIR /app
COPY apps/ai-service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
WORKDIR /app/apps/ai-service
COPY apps/ai-service/app ./app
COPY apps/ai-service/scripts ./scripts
COPY apps/ai-service/README.md ./README.md
COPY apps/ai-service/models ./models
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
