#!/bin/sh
# Container entrypoint for ECS. ECS injects three secrets as environment variables.
# This writes them to memory-backed files, points the server at them, clears the
# variables, then starts the command given to the container.
#
#   DIP_CONFIG_JSON   the full server config; its /run/secrets/ paths are rewritten
#   DIP_PG_URL        PostgreSQL connection string
#   DIP_OPERATOR_KEY  operator API key (at least 32 characters)
#
# /dev/shm is memory-backed, so the secrets never reach the container's disk.
set -eu

DIR=/dev/shm/dip-secrets
umask 077
mkdir -p "$DIR"

: "${DIP_CONFIG_JSON:?DIP_CONFIG_JSON is required}"
: "${DIP_PG_URL:?DIP_PG_URL is required}"
: "${DIP_OPERATOR_KEY:?DIP_OPERATOR_KEY is required}"

printf '%s' "$DIP_PG_URL" > "$DIR/pg-url"
printf '%s' "$DIP_OPERATOR_KEY" > "$DIR/operator.key"
printf '%s' "$DIP_CONFIG_JSON" | sed "s#/run/secrets/#$DIR/#g" > "$DIR/dip-config.json"

unset DIP_CONFIG_JSON DIP_PG_URL DIP_OPERATOR_KEY
export DIP_CONFIG="$DIR/dip-config.json"

exec "$@"
