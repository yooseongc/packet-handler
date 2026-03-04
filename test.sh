#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

BIN="${BIN:-$ROOT_DIR/target/debug/packet_handler}"

echo "[test] cargo check"
~/.cargo/bin/cargo check >/dev/null

echo "[test] cargo test"
~/.cargo/bin/cargo test >/dev/null

echo "[test] build debug binary"
~/.cargo/bin/cargo build >/dev/null

if [[ ! -x "$BIN" ]]; then
  echo "[FAIL] binary not found: $BIN"
  exit 1
fi

echo "[test] cli negative tests"

# 1) no args -> should fail
if "$BIN" >/dev/null 2>&1; then
  echo "[FAIL] expected failure without required args"
  exit 1
fi

# 2) missing input should fail
if "$BIN" substitute_ip --from 1.1.1.1 --to 2.2.2.2 >/dev/null 2>&1; then
  echo "[FAIL] expected failure when --input is missing"
  exit 1
fi

# 3) substitute_ip missing --to should fail
if "$BIN" --input ./nonexistent.pcap substitute_ip --from 1.1.1.1 >/dev/null 2>&1; then
  echo "[FAIL] expected failure when --to is missing"
  exit 1
fi

# 4) snaplen missing N should fail
if "$BIN" --input ./nonexistent.pcap snaplen >/dev/null 2>&1; then
  echo "[FAIL] expected failure when snaplen argument is missing"
  exit 1
fi

echo "[test] sample packet file tests"
SAMPLE="./test/ndlp1.pcap"
if [[ -f "$SAMPLE" ]]; then
  "$BIN" --input "$SAMPLE" --output ./test/out_substitute.pcap --overwrite substitute_ip --from 10.10.10.5 --to 192.168.0.100 >/dev/null
  "$BIN" --input "$SAMPLE" --output ./test/out_snaplen.pcap --overwrite snaplen 64 >/dev/null
  echo "[OK] sample packet test passed ($SAMPLE)"
else
  echo "[WARN] sample packet not found, skipping packet processing test: $SAMPLE"
fi

echo "[OK] basic cli tests passed"
