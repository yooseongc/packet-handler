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

echo "[build] extracting musl binary from artifact image..."
CID=$(docker create "$ARTIFACT_NAME")
mkdir -p ./dist
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT
docker cp "$CID":/packet_handler ./dist/packet_handler
chmod +x ./dist/packet_handler

echo "[build] done"
echo "- runtime image: $IMAGE_NAME"
echo "- artifact image: $ARTIFACT_NAME"
echo "- extracted binary: ./dist/packet_handler"
