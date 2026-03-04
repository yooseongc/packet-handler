#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME=${IMAGE_NAME:-packet_handler:build}
EXPORTER_NAME=${EXPORTER_NAME:-packet_handler:exporter}

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

echo "[build] building musl binary in docker..."
docker build -t "$IMAGE_NAME" .

echo "[build] building exporter image..."
docker build --target exporter -t "$EXPORTER_NAME" .

echo "[build] extracting musl binary via dist volume mount..."
mkdir -p ./dist
docker run --rm -v "$ROOT_DIR/dist:/dist" "$EXPORTER_NAME"

echo "[build] done"
echo "- runtime image: $IMAGE_NAME"
echo "- exporter image: $EXPORTER_NAME"
echo "- extracted binary: ./dist/packet_handler"
