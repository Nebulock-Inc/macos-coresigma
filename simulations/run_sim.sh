#!/bin/bash
# Usage: run_sim.sh <atomic-name> <test-index>
# Runs a simulation atomic on the coreSigma EC2 Mac test host, records timing in reports/sim_windows.json
set -euo pipefail

# Configuration: set these in the environment or in simulations/sim.env (gitignored).
# CORESIGMA_TEST_INSTANCE  - EC2 Mac instance ID to run on
# CORESIGMA_TEST_ACCOUNT   - AWS account ID that must own it (checked before anything is sent)
# AWS_PROFILE / AWS_REGION - credentials for that account
SIM_ENV="$(cd "$(dirname "$0")" && pwd)/sim.env"
[ -f "$SIM_ENV" ] && { set -a; . "$SIM_ENV"; set +a; }  # export, so aws sees AWS_PROFILE
INSTANCE_ID="${CORESIGMA_TEST_INSTANCE:?set CORESIGMA_TEST_INSTANCE (or simulations/sim.env)}"
EXPECTED_ACCOUNT="${CORESIGMA_TEST_ACCOUNT:?set CORESIGMA_TEST_ACCOUNT (or simulations/sim.env)}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ATOMICS_DIR="$REPO_ROOT/simulations/atomics"
REPORTS_FILE="$REPO_ROOT/reports/sim_windows.json"

# Parse arguments
if [ $# -ne 2 ]; then
  echo "Usage: $0 <atomic-name> <test-index>" >&2
  echo "Example: $0 T1059.002-paste-to-stealer 0" >&2
  exit 1
fi

ATOMIC_NAME="$1"
TEST_INDEX="$2"
ATOMIC_FILE="$ATOMICS_DIR/${ATOMIC_NAME}.yaml"

# Dry-run mode check
DRY_RUN="${DRY_RUN:-false}"

# How long the host waits for the atomic, in seconds: 120 unless SIM_TIMEOUT says more (a hands-on recording window).
# At most 540, so the cleanup still runs inside SSM's 600 s executionTimeout.
SIM_TIMEOUT="${SIM_TIMEOUT:-120}"
if ! [[ "$SIM_TIMEOUT" =~ ^[0-9]+$ ]] || [ "$SIM_TIMEOUT" -gt 540 ]; then
  echo "ERROR: SIM_TIMEOUT must be a whole number of seconds, at most 540" >&2
  exit 1
fi

# Validate atomic file exists
if [ ! -f "$ATOMIC_FILE" ]; then
  echo "ERROR: Atomic file not found: $ATOMIC_FILE" >&2
  exit 1
fi

# Safety check: verify AWS account
if [ "$DRY_RUN" != "true" ]; then
  ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
  if [ "$ACCOUNT" != "$EXPECTED_ACCOUNT" ]; then
    echo "ERROR: Wrong AWS account ($ACCOUNT). Expected $EXPECTED_ACCOUNT." >&2
    exit 1
  fi
  echo "✓ Verified AWS account $EXPECTED_ACCOUNT" >&2
fi

# Extract command and cleanup from YAML
# Simple extraction: find command: line, then capture until cleanup_command:
echo "Parsing atomic file: $ATOMIC_FILE" >&2
COMMAND=$(awk '
  /^      command: \|$/ { in_cmd=1; next }
  in_cmd && /^      cleanup_command:/ { in_cmd=0 }
  in_cmd && /^        / { sub(/^        /, ""); print }
' "$ATOMIC_FILE")

CLEANUP=$(awk '
  /^      cleanup_command: \|$/ { in_cleanup=1; next }
  in_cleanup && /^[^ ]/ { in_cleanup=0 }
  in_cleanup && /^        / { sub(/^        /, ""); print }
' "$ATOMIC_FILE")

if [ -z "$COMMAND" ]; then
  echo "ERROR: Could not extract command from atomic file" >&2
  exit 1
fi

if [ -z "$CLEANUP" ]; then
  echo "ERROR: Could not extract cleanup_command from atomic file" >&2
  exit 1
fi

# Get test name for reporting
TEST_NAME=$(awk '/^  - name:/ { $1=$2=""; sub(/^ +/, ""); print; exit }' "$ATOMIC_FILE")
if [ -z "$TEST_NAME" ]; then
  TEST_NAME="$ATOMIC_NAME test $TEST_INDEX"
fi

echo "Running simulation: $TEST_NAME" >&2

# Start time on this machine: only a fallback, the window comes from the host's clock (CS_SIM_START/CS_SIM_END)
START_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [ "$DRY_RUN" = "true" ]; then
  echo "=== DRY RUN MODE ===" >&2
  echo "Would run on instance: $INSTANCE_ID" >&2
  echo "" >&2
  echo "Command file to generate (/tmp/cs_sim.command):" >&2
  echo "#!/bin/bash" >&2
  echo "trap 'echo \$? > /tmp/cs_sim.done' EXIT" >&2
  echo "$COMMAND" >&2
  echo "" >&2
  echo "Execution flow:" >&2
  echo "  1. Remove /tmp/cs_sim.done from previous run" >&2
  echo "  2. Write command to /tmp/cs_sim.command (with EXIT trap for marker)" >&2
  echo "  3. Print the window start (host clock), launch in Terminal window via launchctl asuser" >&2
  echo "  4. Poll for /tmp/cs_sim.done (${SIM_TIMEOUT}s timeout, 2s intervals)" >&2
  echo "  5. Read exit status from marker file" >&2
  echo "  6. Print the window end (host clock, rounded up a second) after marker appears (or timeout)" >&2
  echo "  7. Run cleanup" >&2
  echo "" >&2
  echo "Cleanup to execute:" >&2
  echo "$CLEANUP" >&2
  echo "" >&2
  echo "Would write to $REPORTS_FILE:" >&2
  END_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "{\"name\": \"$TEST_NAME\", \"start\": \"$START_TIME\", \"end\": \"$END_TIME\", \"status\": \"success\"} (on success)" >&2
  echo "{\"name\": \"$TEST_NAME\", \"start\": \"$START_TIME\", \"end\": \"$END_TIME\", \"status\": \"error\"} (on atomic failure)" >&2
  echo "{\"name\": \"$TEST_NAME\", \"start\": \"$START_TIME\", \"end\": \"$END_TIME\", \"status\": \"timeout\"} (on timeout)" >&2
  exit 0
fi

# Build the execution script for SSM
# This script will:
# 1. Remove done marker from previous run
# 2. Write the command to /tmp/cs_sim.command (with EXIT trap to write marker + status)
# 3. Print the window start (CS_SIM_START=...) and run it in a Terminal window as ec2-user
# 4. Poll for done marker with timeout
# 5. Print the window end (CS_SIM_END=...) once the marker appears, before the cleanup
# 6. Read exit status from marker
# 7. Run the cleanup
EXEC_SCRIPT=$(cat <<'SCRIPT_EOF'
set -e

# Remove done marker from any previous run
rm -f /tmp/cs_sim.done

# Write command to file (with EXIT trap to guarantee marker on any exit)
cat > /tmp/cs_sim.command << 'COMMAND_EOF'
#!/bin/bash
trap 'echo $? > /tmp/cs_sim.done' EXIT
COMMAND_CONTENT_PLACEHOLDER
COMMAND_EOF
chmod +x /tmp/cs_sim.command

# Run in Terminal window as ec2-user. The window starts here, on the host's clock; run_sim.sh reads this line.
USER_ID=$(id -u ec2-user)
echo "CS_SIM_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
launchctl asuser "$USER_ID" open -a Terminal /tmp/cs_sim.command

# Poll for completion marker
TIMEOUT=SIM_TIMEOUT_PLACEHOLDER
ELAPSED=0
while [ ! -f /tmp/cs_sim.done ] && [ $ELAPSED -lt $TIMEOUT ]; do
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done
# The window ends here, before the cleanup below; run_sim.sh reads this line. Rounded up a second (BSD date -v):
# rule_matrix counts @timestamp <= end, and the last events can be later in this second than its whole-second time.
echo "CS_SIM_END=$(date -u -v+1S +%Y-%m-%dT%H:%M:%SZ)"
sleep 1  # so the cleanup below starts after that rounded-up end, outside the window

# Determine result status
if [ ! -f /tmp/cs_sim.done ]; then
  echo "WARNING: Simulation timed out after ${TIMEOUT}s" >&2
  STATUS="timeout"
  EXIT_STATUS=2
else
  ATOMIC_EXIT=$(cat /tmp/cs_sim.done)
  if [ "$ATOMIC_EXIT" -eq 0 ]; then
    echo "Simulation completed successfully in ${ELAPSED}s"
    STATUS="success"
    EXIT_STATUS=0
  else
    echo "WARNING: Simulation failed with exit code $ATOMIC_EXIT after ${ELAPSED}s" >&2
    STATUS="error"
    EXIT_STATUS=1
  fi
fi

# Run cleanup
cat > /tmp/cs_sim_cleanup.sh << 'CLEANUP_EOF'
#!/bin/bash
CLEANUP_CONTENT_PLACEHOLDER
CLEANUP_EOF
chmod +x /tmp/cs_sim_cleanup.sh
chmod 755 /tmp/cs_sim_cleanup.sh
# Cleanup paths use ~, so run as the user the simulation ran as (SSM runs as root, ~ would be /var/root).
sudo -u ec2-user -H /bin/bash /tmp/cs_sim_cleanup.sh

# Remove temporary files
rm -f /tmp/cs_sim.command /tmp/cs_sim_cleanup.sh /tmp/cs_sim.done

echo "Simulation and cleanup complete (status: $STATUS)"
exit $EXIT_STATUS
SCRIPT_EOF
)

# Replace placeholders with actual command and cleanup content.
# Quoted replacement: bash 5.2+ (patsub_replacement) turns an unquoted & into the match, breaking 2>&1 and &&.
# No outer quotes: bash 3.2 keeps the inner quotes literally inside "${...}".
EXEC_SCRIPT=${EXEC_SCRIPT/COMMAND_CONTENT_PLACEHOLDER/"$COMMAND"}
EXEC_SCRIPT=${EXEC_SCRIPT/CLEANUP_CONTENT_PLACEHOLDER/"$CLEANUP"}
EXEC_SCRIPT=${EXEC_SCRIPT/SIM_TIMEOUT_PLACEHOLDER/"$SIM_TIMEOUT"}

# Base64 encode the script for transmission
# Hex, not base64: the host-side `base64 -D` matched the ClickFix rule's paste-base64 selector and polluted sim windows.
HEX_SCRIPT=$(printf '%s\n' "$EXEC_SCRIPT" | xxd -p | tr -d '\n')

# Build SSM parameters JSON
PARAMS=$(jq -cn \
  --arg cmd "echo '$HEX_SCRIPT' | xxd -r -p > /tmp/cs_ssm_exec.sh && /bin/bash /tmp/cs_ssm_exec.sh; rc=\$?; rm -f /tmp/cs_ssm_exec.sh; exit \$rc" \
  --arg timeout "600" \
  '{commands:[$cmd], executionTimeout:[$timeout]}')

# Send command via SSM
echo "Sending command to instance $INSTANCE_ID..." >&2
COMMAND_ID=$(aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name AWS-RunShellScript \
  --comment "coresigma-sim-$ATOMIC_NAME" \
  --parameters "$PARAMS" \
  --query Command.CommandId \
  --output text)

echo "Command ID: $COMMAND_ID" >&2

# Poll for completion
echo "Waiting for completion..." >&2
while true; do
  STATUS=$(aws ssm get-command-invocation \
    --command-id "$COMMAND_ID" \
    --instance-id "$INSTANCE_ID" \
    --query Status \
    --output text 2>/dev/null || echo "Pending")

  case "$STATUS" in
    Pending|InProgress|Delayed)
      sleep 10
      ;;
    *)
      break
      ;;
  esac
done

# Get results and exit code
echo "Command finished with status: $STATUS" >&2
INVOCATION=$(aws ssm get-command-invocation \
  --command-id "$COMMAND_ID" \
  --instance-id "$INSTANCE_ID" \
  --output json)

EXIT_CODE=$(echo "$INVOCATION" | jq -r '.ResponseCode // 0')
STDOUT=$(echo "$INVOCATION" | jq -r '.StandardOutputContent // ""')
STDERR=$(echo "$INVOCATION" | jq -r '.StandardErrorContent // ""')

echo "Exit code: $EXIT_CODE"
echo "$STDOUT"
if [ -n "$STDERR" ]; then
  echo "$STDERR" >&2
fi

# The window on the host's clock: from just before the launch to the completion marker (before cleanup).
# If the host printed only one end, or none, both come from this machine's clock (never one from each), and a
# clean run is recorded as clock_fallback, which rule_matrix leaves out like any status but success.
HOST_START=$(printf '%s\n' "$STDOUT" | sed -n 's/^CS_SIM_START=//p')
HOST_END=$(printf '%s\n' "$STDOUT" | sed -n 's/^CS_SIM_END=//p')
SUCCESS_STATUS=success
if [ -n "$HOST_START" ] && [ -n "$HOST_END" ]; then
  START_TIME=$HOST_START
  END_TIME=$HOST_END
else
  END_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  SUCCESS_STATUS=clock_fallback
  echo "WARNING: the host didn't print CS_SIM_START and CS_SIM_END; window from this machine's clock" >&2
fi

# Ensure reports directory exists
mkdir -p "$(dirname "$REPORTS_FILE")"

# Append to reports file (maintain valid JSON array)
if [ ! -f "$REPORTS_FILE" ]; then
  echo "[]" > "$REPORTS_FILE"
fi

# Build JSON entry based on exit code (0=success, 1=error, 2=timeout)
case "$EXIT_CODE" in
  0)
    NEW_ENTRY=$(jq -cn \
      --arg name "$TEST_NAME" \
      --arg start "$START_TIME" \
      --arg end "$END_TIME" \
      --arg status "$SUCCESS_STATUS" \
      '{name:$name, start:$start, end:$end, status:$status}')
    ;;
  1)
    NEW_ENTRY=$(jq -cn \
      --arg name "$TEST_NAME" \
      --arg start "$START_TIME" \
      --arg end "$END_TIME" \
      '{name:$name, start:$start, end:$end, status:"error"}')
    echo "WARNING: Atomic failed, window marked as error" >&2
    ;;
  2)
    NEW_ENTRY=$(jq -cn \
      --arg name "$TEST_NAME" \
      --arg start "$START_TIME" \
      --arg end "$END_TIME" \
      '{name:$name, start:$start, end:$end, status:"timeout"}')
    echo "WARNING: Simulation timed out, window marked as timeout" >&2
    ;;
  *)
    NEW_ENTRY=$(jq -cn \
      --arg name "$TEST_NAME" \
      --arg start "$START_TIME" \
      --arg end "$END_TIME" \
      --argjson code "$EXIT_CODE" \
      '{name:$name, start:$start, end:$end, status:"unknown", exit_code:$code}')
    echo "WARNING: Unexpected exit code $EXIT_CODE" >&2
    ;;
esac

# Add entry to array
jq --argjson entry "$NEW_ENTRY" '. += [$entry]' "$REPORTS_FILE" > "$REPORTS_FILE.tmp"
mv "$REPORTS_FILE.tmp" "$REPORTS_FILE"

echo "Recorded simulation window in $REPORTS_FILE" >&2

# Exit with the simulation's exit code
exit "$EXIT_CODE"
