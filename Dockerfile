# docker build -t wolweb .
FROM golang:alpine AS builder

LABEL org.label-schema.vcs-url="https://github.com/vsc55/wolweb" \
      org.label-schema.url="https://github.com/vsc55/wolweb/blob/main/README.md"

RUN mkdir /wolweb
WORKDIR /wolweb

# Install Dependecies
RUN apk update && apk upgrade && \
    apk add --no-cache git && \
    git clone https://github.com/vsc55/wolweb . && \
    go mod init wolweb && \
    go get -d github.com/gorilla/handlers && \
    go get -d github.com/gorilla/mux && \
    go get -d github.com/ilyakaznacheev/cleanenv

# Build Source Files
RUN go build -o wolweb . 

# Create 2nd Stage final image
FROM alpine
WORKDIR /wolweb
COPY --from=builder /wolweb/index.html .
COPY --from=builder /wolweb/wolweb .
COPY --from=builder /wolweb/devices.json .
COPY --from=builder /wolweb/config.json .
COPY --from=builder /wolweb/users.json .
COPY --from=builder /wolweb/static ./static

ARG WOLWEBPORT=8089

CMD ["/wolweb/wolweb"]

EXPOSE ${WOLWEBPORT}
