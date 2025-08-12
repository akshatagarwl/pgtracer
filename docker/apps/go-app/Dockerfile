FROM golang:1.24-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o app-go main.go

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/app-go /app-go
CMD ["/app-go"]
