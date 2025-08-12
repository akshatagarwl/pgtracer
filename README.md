# pgtracer
eBPF-based PostgreSQL query tracer for Linux that captures SQL queries across multiple programming languages and environments.

## Build

```bash
# ensure clang and llvm-strip are in PATH
go generate ./internal/bpf/
GOOS=linux GOARCH=amd64 go build -o pgtracer cmd/pgtracer/main.go
GOOS=linux GOARCH=arm64 go build -o pgtracer cmd/pgtracer/main.go
```

## Run

```bash
sudo ./pgtracer
```

## Docker Demo

### Setup

```bash
cd docker
docker-compose up --build -d
docker-compose logs -f pgtracer
```

### Test with Different Clients

#### 1. Go Application (lib/pq)

```bash
docker build -t test-go-app docker/apps/go-app/
docker run --rm --network docker_pgtracer-net \
  -e PGHOST=postgres \
  -e PGPORT=5432 \
  -e PGUSER=testuser \
  -e PGPASSWORD=testpass \
  -e PGDATABASE=testdb \
  test-go-app
```

#### 2. Python Application (psycopg2)

```bash
docker build -t test-python-app docker/apps/python-app/
docker run --rm --network docker_pgtracer-net \
  -e PGHOST=postgres \
  -e PGPORT=5432 \
  -e PGUSER=testuser \
  -e PGPASSWORD=testpass \
  -e PGDATABASE=testdb \
  test-python-app
```

#### 3. C Application (libpq)

```bash
docker build -t test-c-app docker/apps/c-app/
docker run --rm --network docker_pgtracer-net \
  -e PGHOST=postgres \
  -e PGPORT=5432 \
  -e PGUSER=testuser \
  -e PGPASSWORD=testpass \
  -e PGDATABASE=testdb \
  test-c-app
```

#### 4. psql

```bash
docker run -it --rm --network docker_pgtracer-net \
  -e PGPASSWORD=testpass \
  postgres:16 \
  psql -h postgres -U testuser -d testdb
```

## Supported Libraries

- **Go**: github.com/lib/pq (including stripped binaries)
- **C**: libpq (dynamically linked)
- **Python**: psycopg2 (uses libpq)

## Features

- Automatically chooses between `BPF_MAP_TYPE_PERF_EVENT_ARRAY` and `BPF_MAP_TYPE_RINGBUF` for older kernel versions.
- Works in container environments by attaching uprobes to procfs libraries instead of static paths.
- Uses `cilium/ebpf` for statically linked zero dependency binaries that work with `CGO_ENABLED=0`

## Requirements
- Linux kernel with BTF support
- clang and llvm-strip for building
