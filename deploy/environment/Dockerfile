FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --include=dev --no-audit --no-fund
COPY cli ./cli
COPY shared ./shared
COPY scripts/build-cli.mjs ./scripts/build-cli.mjs
RUN node scripts/build-cli.mjs

FROM node:24-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-pip python3-venv jq unzip openssh-client \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build --chmod=755 /app/cli/dist/cli.mjs /usr/local/bin/foundation
WORKDIR /root
CMD ["sleep", "infinity"]
