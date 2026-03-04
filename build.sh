#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME=${IMAGE_NAME:-packet_handler:build}
ARTIFACT_NAME=${ARTIFACT_NAME:-packet_handler:artifact}

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

echo "[build] building musl binary in docker..."
docker build -t "$IMAGE_NAME" .

echo "[build] exporting artifact image..."
docker build --target artifact -t "$ARTIFACT_NAME" .

echo "[build] done"
echo "- runtime image: $IMAGE_NAME"
echo "- artifact image: $ARTIFACT_NAME"
