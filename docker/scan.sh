#!/bin/bash
set -euo pipefail

# Configuration via environment variables
SCAN_RATE="${SCAN_RATE:-50000}"
SCAN_PORTS="${SCAN_PORTS:-3128,8080,1080,8888,9050,8443,3129,80,443,1081}"
EXCLUDE_FILE="${EXCLUDE_FILE:-/config/exclude.conf}"
OUTPUT_FILE="${OUTPUT_FILE:-/data/candidates.json}"

echo "=== Proxy Scanner ==="
echo "Rate:     ${SCAN_RATE} pps"
echo "Ports:    ${SCAN_PORTS}"
echo "Exclude:  ${EXCLUDE_FILE}"
echo "Output:   ${OUTPUT_FILE}"
echo "Started:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "====================="

# Remove previous scan results
rm -f "${OUTPUT_FILE}"

# Run masscan
# --banners is omitted to keep it fast — we only need open port discovery
masscan 0.0.0.0/0 \
    -p"${SCAN_PORTS}" \
    --excludefile "${EXCLUDE_FILE}" \
    --rate "${SCAN_RATE}" \
    --open \
    -oJ "${OUTPUT_FILE}" \
    --source-port 40000-56383

echo "=== Scan Complete ==="
echo "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Count results
if [ -f "${OUTPUT_FILE}" ]; then
    # Masscan JSON has one record per line (roughly)
    COUNT=$(wc -l < "${OUTPUT_FILE}")
    echo "Candidates: ~${COUNT} lines"
else
    echo "ERROR: No output file generated"
    exit 1
fi
