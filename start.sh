#!/usr/bin/env sh
set -eu
mkdir -p data output
docker compose up -d --build
