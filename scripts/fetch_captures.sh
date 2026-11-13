#!/bin/bash
set -euo pipefail

[ $# -eq 0 ] || { echo "Usage: $0 (no arguments; syncs every capture)" >&2; exit 1; }
LOCAL_DIR="captures/"
PROFILE="${AWS_PROFILE:?set AWS_PROFILE to the profile for the capture bucket account}"
REGION="us-east-1"

# Get bucket from env var or local file
if [[ -n "${CORESIGMA_CAPTURE_BUCKET:-}" ]]; then
  BUCKET="$CORESIGMA_CAPTURE_BUCKET"
else
  # Try to load from local file
  LOCAL_FILE="$(dirname "$0")/../tests/private_strings.local.json"
  if [[ -f "$LOCAL_FILE" ]]; then
    BUCKET=$(python3 -c "import json; print(json.load(open('$LOCAL_FILE'))['capture_bucket'])")
  else
    echo "Error: CORESIGMA_CAPTURE_BUCKET not set and tests/private_strings.local.json not found" >&2
    echo "Set CORESIGMA_CAPTURE_BUCKET or copy tests/private_strings.local.json.example and fill with real values" >&2
    exit 1
  fi
fi

echo "Fetching all captures..."

aws s3 sync "$BUCKET" "$LOCAL_DIR" \
  --profile "$PROFILE" \
  --region "$REGION"

echo "Captures synced to $LOCAL_DIR"
