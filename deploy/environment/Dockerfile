# The machine a lent environment runs on: a shell, common tools, and the foundation CLI. It sleeps until a command is
# run in it; Foundation destroys it when the environment closes. Build and push it to the runner app's registry:
#   fly deploy --build-only --push --image-label <label> -a <runner app>   (from this directory)
FROM node:24-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-pip jq unzip openssh-client \
 && rm -rf /var/lib/apt/lists/*
RUN npm install -g --ignore-scripts @tomato414941/foundation && npm cache clean --force
ENV HOME=/root
WORKDIR /root
CMD ["sleep", "infinity"]
