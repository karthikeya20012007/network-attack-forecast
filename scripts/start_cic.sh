#!/bin/bash
# scripts/start_cic.sh
# Start CICFlowMeter live capture with timestamped CSV rotation.
#
# Usage:
#   sudo ./scripts/start_cic.sh          # capture from eth0 (default)
#   sudo ./scripts/start_cic.sh lo       # capture from loopback

set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BASE_DIR="$(dirname "$DIR")"

# Load env variables if they exist
if [ -f "$BASE_DIR/.env" ]; then
    set -a
    source "$BASE_DIR/.env"
    set +a
fi

DEFAULT_IFACE=$(ip route 2>/dev/null | awk '/^default/ {print $5}' | head -n 1)
DEFAULT_IFACE="${DEFAULT_IFACE:-eth0}"
INTERFACE="${1:-${NETWORK_INTERFACE:-$DEFAULT_IFACE}}"
CIC_FLOW_DIR="${CIC_FLOW_DIR:-$BASE_DIR/data/cic/flows}"
CIC_ROTATION="${CIC_ROTATION_MINUTES:-1}"

# Ensure output directory exists
mkdir -p "$CIC_FLOW_DIR"

# Resolve venv Python and our CIC wrapper script.
# The wrapper works around a positional-argument bug in cicflowmeter
# 0.5.0's main() — see src/collector/cic_wrapper.py for details.
VENV_PYTHON="$BASE_DIR/.venv/bin/python-capture"
if [ ! -x "$VENV_PYTHON" ]; then
    VENV_PYTHON="$BASE_DIR/.venv/bin/python3"
fi
CIC_WRAPPER="$BASE_DIR/src/collector/cic_wrapper.py"

if [ ! -x "$VENV_PYTHON" ]; then
    echo "Error: venv Python not found."
    echo "  Checked: $BASE_DIR/.venv/bin/python"
    echo "  Create with: python3 -m venv $BASE_DIR/.venv"
    exit 1
fi
if [ ! -f "$CIC_WRAPPER" ]; then
    echo "Error: CIC wrapper script not found at $CIC_WRAPPER"
    exit 1
fi

echo "==================================="
echo " CICFlowMeter Live Capture"
echo "==================================="
echo " Python:     $VENV_PYTHON"
echo " Wrapper:    $CIC_WRAPPER"
echo " Interface:  $INTERFACE"
echo " Output dir: $CIC_FLOW_DIR"
echo " Rotation:   every ${CIC_ROTATION} minute(s)"
echo "==================================="
echo ""

# Generate the first output filename
generate_filename() {
    date +"flows_%Y-%m-%d_%H-%M.csv"
}

CAPTURE_PID=""

cleanup() {
    echo ""
    echo "Stopping CICFlowMeter..."
    if [ -n "$CAPTURE_PID" ] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
        echo "  Waiting for flows to flush..."
        for i in {1..10}; do
            if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        
        if kill -0 "$CAPTURE_PID" 2>/dev/null; then
            echo "  Process did not exit. Forcing termination..."
            kill -9 "$CAPTURE_PID" 2>/dev/null || true
        fi
    fi
    rm -f "$DIR/.cic.pid"
    echo "CICFlowMeter stopped."
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "Starting capture... (Press Ctrl+C to stop)"
echo ""

while true; do
    OUTFILE="$CIC_FLOW_DIR/$(generate_filename)"
    echo "[$(date +%H:%M:%S)] Capturing → $OUTFILE"

    "$VENV_PYTHON" "$CIC_WRAPPER" -i "$INTERFACE" -c "$OUTFILE" &
    CAPTURE_PID=$!
    echo "$CAPTURE_PID" > "$DIR/.cic.pid"

    # Wait for the rotation interval
    SECONDS_TO_WAIT=$(( CIC_ROTATION * 60 ))
    sleep "$SECONDS_TO_WAIT" &
    SLEEP_PID=$!
    wait "$SLEEP_PID" 2>/dev/null || true

    # Stop current capture
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
    fi

    if [ -f "$OUTFILE" ]; then
        SIZE=$(stat -c%s "$OUTFILE" 2>/dev/null || echo "?")
        LINES=$(wc -l < "$OUTFILE" 2>/dev/null || echo "?")
        echo "       Wrote $LINES lines ($SIZE bytes)"
    fi
done
