FROM golang:1.27.1 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/fabric-gateway-bridge .

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /out/fabric-gateway-bridge /fabric-gateway-bridge

USER 65532:65532

EXPOSE 8090

ENTRYPOINT ["/fabric-gateway-bridge"]
