FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY requirements.lock.txt ./
RUN pip install --no-cache-dir -r requirements.lock.txt && useradd --uid 10001 --create-home guard
COPY backend ./backend
COPY adapters ./adapters
COPY assets/tokenizer ./assets/tokenizer
COPY --from=frontend /build/dist ./frontend/dist
RUN mkdir -p /app/data && chown -R guard:guard /app
USER guard
ENV GUARD_DATA_DIR=/app/data PYTHONUNBUFFERED=1
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=2)"
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8765"]
