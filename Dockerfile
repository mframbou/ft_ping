FROM alpine

# https://github.com/gliderlabs/docker-alpine/issues/24
RUN apk update && apk add --update alpine-sdk && mkdir -p /ft_nm

WORKDIR /ft_nm
CMD ["sh"]