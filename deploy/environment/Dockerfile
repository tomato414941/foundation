FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --include=dev --no-audit --no-fund
COPY cli ./cli
COPY shared ./shared
COPY runtime ./runtime
COPY server ./server
COPY scripts/build-cli.mjs ./scripts/build-cli.mjs
RUN node scripts/build-cli.mjs

FROM node:24-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates docker.io util-linux \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build --chmod=755 /app/cli/dist/cli.mjs /usr/local/bin/foundation
COPY --chmod=755 deploy/environment/entrypoint.sh /usr/local/bin/foundation-agent
WORKDIR /root
CMD ["foundation-agent"]
