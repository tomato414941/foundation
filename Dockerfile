FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --include=dev --no-audit --no-fund
COPY . .
RUN npm run build
RUN npm prune --omit=dev --offline --ignore-scripts --no-audit --no-fund

FROM node:24-bookworm-slim AS runtime
ARG FOUNDATION_COMMIT=
ENV NODE_ENV=production FOUNDATION_HOST=0.0.0.0 FOUNDATION_PORT=3417 FOUNDATION_DATA=/var/lib/foundation FOUNDATION_COMMIT=$FOUNDATION_COMMIT
WORKDIR /app
COPY --from=build --chown=node:node /app/package.json ./package.json
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
RUN mkdir -p /var/lib/foundation && chown node:node /var/lib/foundation
USER node
EXPOSE 3417
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD node -e "fetch('http://127.0.0.1:3417/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "dist/server/main.js"]
