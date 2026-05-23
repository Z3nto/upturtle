#!/bin/sh
set -eu

mkdir -p /data/conf /data/db
chown -R appuser:appuser /data

docker_socket="/var/run/docker.sock"
case "${DOCKER_HOST:-}" in
  unix://*)
    docker_socket="${DOCKER_HOST#unix://}"
    ;;
esac

if [ -S "$docker_socket" ]; then
  docker_gid="$(stat -c '%g' "$docker_socket" 2>/dev/null || true)"
  if [ -n "$docker_gid" ]; then
    if ! getent group "$docker_gid" >/dev/null 2>&1; then
      groupadd -g "$docker_gid" dockerhost
    fi

    docker_group="$(getent group "$docker_gid" | cut -d: -f1)"
    if [ -n "$docker_group" ]; then
      usermod -aG "$docker_group" appuser
    fi
  fi
fi

exec su -s /bin/sh appuser -c 'exec /app/upturtle'
