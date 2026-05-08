#!/usr/bin/env bash
# Run the full demo. Usage: ./run.sh
set -e
cd "$(dirname "$0")"

# First-time setup: generate the orchestrator key and capture pubkey.
if [ ! -f keys/orchestrator.pub ]; then
  echo "First run — generating orchestrator key..."
  python orchestrator.py >/dev/null 2>&1 || true
fi
export ROOT_PUBKEY=$(python -c "from pathlib import Path; print(Path('keys/orchestrator.pub').read_bytes().hex())")
echo "root pubkey: $ROOT_PUBKEY"

# Start writer + researcher in background; orchestrator runs in foreground.
python writer.py &
WRITER_PID=$!
sleep 1
python researcher.py &
RESEARCHER_PID=$!
sleep 1
trap "kill $WRITER_PID $RESEARCHER_PID 2>/dev/null || true" EXIT

python orchestrator.py
