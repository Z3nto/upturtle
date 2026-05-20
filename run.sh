#!/usr/bin/env sh
set -eu

APP_NAME="upturtle"
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BIN_DIR="$ROOT_DIR/bin"
BIN_PATH="$BIN_DIR/$APP_NAME"
DATA_DIR="$ROOT_DIR/data"

usage() {
  cat <<EOF
Usage: ./run.sh [option]

Options:
  --build, -b        Build only
  --build-run, -r    Build and start
  --help, -h         Show help

With no option, the application is started only.
EOF
}

build_app() {
  mkdir -p "$BIN_DIR"
  echo "Building $APP_NAME to $BIN_PATH ..."
  CGO_ENABLED=1 go build -ldflags "-s -w" -o "$BIN_PATH" ./cmd/upturtle
}

start_app() {
  if [ ! -x "$BIN_PATH" ]; then
    echo "Binary not found: $BIN_PATH" >&2
    echo "Run './run.sh --build' or './run.sh --build-run' first." >&2
    exit 1
  fi

  mkdir -p "$DATA_DIR/conf" "$DATA_DIR/db"

  if [ -z "${UPTURTLE_CONFIG_PATH:-}" ]; then
    export UPTURTLE_CONFIG_PATH="$DATA_DIR/conf/config.json"
  fi

  echo "Starting $APP_NAME ..."
  echo "Configuration: $UPTURTLE_CONFIG_PATH"
  echo "Address: ${LISTEN_ADDR:-:8080}"
  exec "$BIN_PATH"
}

case "${1:-}" in
  "")
    start_app
    ;;
  --build|-b)
    build_app
    ;;
  --build-run|--build-and-run|-r)
    build_app
    start_app
    ;;
  --help|-h)
    usage
    ;;
  *)
    echo "Unknown option: $1" >&2
    usage >&2
    exit 2
    ;;
esac
