FROM gcc:13-bookworm AS builder
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y libpq-dev
WORKDIR /build
COPY main.c ./
RUN --mount=type=cache,target=/root/.cache/gcc \
    gcc -Wall -I/usr/include/postgresql -o app-c main.c -lpq

FROM debian:bookworm-slim
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y libpq5
COPY --from=builder /build/app-c /app-c
CMD ["/app-c"]
