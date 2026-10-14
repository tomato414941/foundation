FROM public.ecr.aws/docker/library/node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY vendor ./vendor
RUN npm ci --include=dev --no-audit --no-fund
COPY . .
RUN npm run build
RUN npm prune --omit=dev --offline --ignore-scripts --no-audit --no-fund

FROM public.ecr.aws/docker/library/node:24-bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
ARG FOUNDATION_RELEASE_COMMIT=
ENV FOUNDATION_RELEASE_COMMIT=$FOUNDATION_RELEASE_COMMIT
ENV NODE_ENV=production FOUNDATION_HOST=0.0.0.0 FOUNDATION_PORT=3417 FOUNDATION_DATA=/var/lib/foundation
WORKDIR /app
COPY --from=build --chown=node:node /app/package.json ./package.json
COPY --from=build --chown=node:node /app/compose.yaml ./compose.yaml
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/cli/dist/cli.mjs ./release/cli.mjs
COPY --from=build --chown=node:node /app/cli/dist/agent.mjs ./release/agent.mjs
COPY --from=build --chown=node:node /app/deploy/release ./deploy/release
RUN mkdir -p /var/lib/foundation && chown node:node /var/lib/foundation
USER node
EXPOSE 3417
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD node -e "fetch('http://127.0.0.1:3417/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "dist/server/main.js"]
