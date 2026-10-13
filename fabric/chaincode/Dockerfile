FROM golang:1.20 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY agenttrust_cc.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/agenttrust-cc .

FROM debian:bookworm-slim
COPY --from=builder /out/agenttrust-cc /usr/local/bin/agenttrust-cc

EXPOSE 9999
ENTRYPOINT ["/usr/local/bin/agenttrust-cc"]