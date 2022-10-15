FROM alpine

# https://github.com/gliderlabs/docker-alpine/issues/24
RUN apk update && apk add alpine-sdk zsh && mkdir -p /ft_nm

WORKDIR /ft_nm
CMD ["zsh"]