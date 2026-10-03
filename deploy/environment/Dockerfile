# The general image a lent environment is made from when its opener names none: a shell and the tools commands most
# often reach for, and nothing of Foundation's, so it never falls behind the server. What a command needs of
# Foundation is handed to that command. Build and push it to the runner app's registry, under a new label each time:
#   docker build -t registry.fly.io/<runner app>:<label> . && docker push registry.fly.io/<runner app>:<label>
FROM node:24-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-pip python3-venv jq unzip openssh-client \
 && rm -rf /var/lib/apt/lists/*
ENV HOME=/root
WORKDIR /root
CMD ["sleep", "infinity"]
