FROM gcc:13-bookworm AS builder
RUN apt-get update && apt-get install -y libpq-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY main.c ./
RUN gcc -Wall -I/usr/include/postgresql -o app-c main.c -lpq

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libpq5 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/app-c /app-c
CMD ["/app-c"]
