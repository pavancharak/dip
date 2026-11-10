# syntax=docker/dockerfile:1
# Multi-stage build for the DIP API. Secrets are never copied into the image:
# keys and API keys are mounted at runtime (see docker-compose.yml and docs/deployment).

FROM node:22-bookworm-slim AS build
# CI=true lets pnpm prune without a TTY; Docker builds have none.
ENV CI=true
RUN corepack enable
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile \
 && pnpm -r run build \
 && pnpm --config.inject-workspace-packages=true --filter @dip/api deploy --prod /out

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    DIP_CONFIG=/run/secrets/dip-config.json \
    PORT=3000 \
    NODE_EXTRA_CA_CERTS=/app/rds-global-bundle.pem
WORKDIR /app
# Self-contained API: its built files, production dependencies and internal packages.
COPY --from=build --chown=node:node /out ./
RUN mkdir -p /var/lib/dip && chown node:node /var/lib/dip
VOLUME ["/var/lib/dip"]
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# AWS RDS CA bundle (public), so the server can verify its PostgreSQL connection.
COPY --chown=node:node deployment/aws/rds-global-bundle.pem /app/rds-global-bundle.pem
# Writes ECS-injected secrets to memory-backed files, then runs the command.
COPY --chown=node:node deployment/aws/entrypoint.sh /usr/local/bin/dip-entrypoint.sh
ENTRYPOINT ["sh", "/usr/local/bin/dip-entrypoint.sh"]
CMD ["node", "dist/server.js"]
