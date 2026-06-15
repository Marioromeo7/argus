# ── Stage 1: Build React ──────────────────────────────────────────────────────
FROM node:20-alpine AS ui-builder
WORKDIR /ui
COPY ui/package*.json ./
RUN npm install
COPY ui/ ./
RUN npm run build
# Output: /ui/dist

# ── Stage 2: FastAPI ──────────────────────────────────────────────────────────
FROM python:3.11-slim
WORKDIR /app

COPY api/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/
COPY --from=ui-builder /ui/dist ./ui/dist

EXPOSE 3000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "3000"]
