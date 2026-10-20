# DataShield Support Workbench: React UI (built here) served by a FastAPI backend.
FROM node:22-alpine AS ui
WORKDIR /ui
COPY workbench/frontend/package.json workbench/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY workbench/frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 WB_STATIC=/srv/static
COPY workbench/backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY workbench/backend/app /srv/app
COPY --from=ui /ui/dist /srv/static
WORKDIR /srv
EXPOSE 9443
HEALTHCHECK --interval=15s --timeout=5s --retries=3 CMD python3 -c "import ssl,urllib.request as u; u.urlopen('https://localhost:9443/api/health', context=ssl.create_default_context(cafile='/lab-certs/ca-chain.pem'), timeout=4)"
# Runs as root only because the Docker socket requires it; all Linux capabilities are dropped in compose.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9443", "--ssl-keyfile", "/lab-certs/server.key", "--ssl-certfile", "/lab-certs/server.crt", "--no-server-header", "--log-level", "warning"]
