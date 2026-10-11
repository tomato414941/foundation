#!/bin/bash
set -euo pipefail

python3 deploy/release/images.py public.ecr.aws/docker/library/postgres:18-alpine
docker run --detach --name foundation-test-postgres \
  --publish 127.0.0.1:5432:5432 \
  --env POSTGRES_USER=foundation --env POSTGRES_PASSWORD=foundation-ci-only \
  --env POSTGRES_DB=foundation_test public.ecr.aws/docker/library/postgres:18-alpine
for attempt in {1..45}; do
  if docker exec foundation-test-postgres pg_isready --host 127.0.0.1 --username foundation --dbname foundation_test; then
    exit 0
  fi
  sleep 1
done
docker logs foundation-test-postgres
exit 1
