# ── Stage 1: build ─────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --frozen-lockfile

COPY . .

ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=${VITE_API_URL}

RUN npm run build

# ── Stage 2: serve with nginx (unprivileged — runs as uid 101) ──────────────
FROM nginxinc/nginx-unprivileged:1.27-alpine

LABEL org.opencontainers.image.title="CyberTwin SOC Frontend"
LABEL org.opencontainers.image.description="React/Vite frontend served via nginx"
LABEL org.opencontainers.image.version="3.1.0"

# Remove default nginx config
USER root
RUN rm -f /etc/nginx/conf.d/default.conf
USER nginx

# Copy our SPA nginx config
COPY nginx.conf /etc/nginx/conf.d/cybertwin.conf

# Copy built assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# nginx-unprivileged listens on 8080 by default
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
