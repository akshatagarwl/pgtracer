FROM golang:1.24-alpine AS builder
RUN apk add --no-cache clang llvm
WORKDIR /build
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go generate ./internal/bpf/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -o pgtracer cmd/pgtracer/main.go

FROM alpine:3.22
RUN apk add --no-cache ca-certificates bpftool
COPY --from=builder /build/pgtracer /app/pgtracer
ENTRYPOINT ["/app/pgtracer"]