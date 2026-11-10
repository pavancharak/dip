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
 && pnpm prune --prod

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    DIP_CONFIG=/run/secrets/dip-config.json \
    PORT=3000
WORKDIR /app
COPY --from=build --chown=node:node /app/package.json ./package.json
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/packages ./packages
COPY --from=build --chown=node:node /app/apps ./apps
RUN mkdir -p /var/lib/dip && chown node:node /var/lib/dip
VOLUME ["/var/lib/dip"]
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# Writes ECS-injected secrets to memory-backed files, then runs the command.
COPY --chown=node:node deployment/aws/entrypoint.sh /usr/local/bin/dip-entrypoint.sh
ENTRYPOINT ["sh", "/usr/local/bin/dip-entrypoint.sh"]
CMD ["node", "apps/api/dist/server.js"]
