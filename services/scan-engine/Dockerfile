FROM python:3.11-slim
WORKDIR /app
COPY services/scan-engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY aegisml/ /app/aegisml/
COPY services/scan-engine/ /app/services/scan-engine/
EXPOSE 8000
CMD cd /app/services/scan-engine && uvicorn main:app --host 0.0.0.0 --port $PORT
