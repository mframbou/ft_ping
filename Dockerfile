FROM debian

# https://github.com/gliderlabs/docker-alpine/issues/24
RUN apt-get update && apt-get -y install build-essential zsh iputils-ping && mkdir -p /mframbou

WORKDIR /mframbou
CMD ["zsh"]