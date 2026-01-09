FROM golang:alpine AS builder

WORKDIR /usr/src/app

COPY . .
RUN apk add make openssh
RUN make build


FROM alpine

RUN apk add --no-cache openssh tzdata && \
      ssh-keygen -t rsa -C "chatkey" -f /root/.ssh/id_rsa

WORKDIR /usr/local/bin

COPY --from=builder /usr/src/app/ssh-chat .
RUN chmod +x ssh-chat
CMD ["/usr/local/bin/ssh-chat"]
