#!/usr/bin/env bash
# Skill Auditor - Sandbox Behavioral Analysis v0.2.1
# Runs skill in isolated Docker container with honeypot traps
# Monitors network, file access, and credential theft attempts

set -uo pipefail

# === ERROR HANDLING ===
error_exit() {
    local msg="$1"
    local code="${2:-1}"
    echo "❌ Error: $msg" >&2
    exit "$code"
}

warn() {
    echo "⚠️  Warning: $1" >&2
}

cleanup() {
    local exit_code=$?
    if [ -n "${CONTAINER_NAME:-}" ]; then
        docker stop "$CONTAINER_NAME" > /dev/null 2>&1 || true
        docker rm "$CONTAINER_NAME" > /dev/null 2>&1 || true
    fi
    if [ -n "${TEMP_DIR:-}" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi
    exit $exit_code
}

trap cleanup EXIT INT TERM

# === RESOLVE SCRIPT LOCATION ===
SOURCE="$0"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
SANDBOX_DIR="$SCRIPT_DIR/sandbox"
CONTAINER_NAME="skill-audit-$$-$(date +%s)"
TIMEOUT_SECONDS=30

# === INPUT VALIDATION ===
SKILL_FILE="${1:-}"

if [ -z "$SKILL_FILE" ]; then
    cat >&2 << 'USAGE'
Usage: sandbox_audit.sh <skill_file>

Runs skill in isolated Docker container with honeypot credentials.
Monitors for credential theft and malicious behavior.

Requires: Docker
USAGE
    exit 1
fi

# Sanitize path
SKILL_FILE_CLEAN=$(echo "$SKILL_FILE" | sed 's/[;&|`$]//g')
if [ "$SKILL_FILE" != "$SKILL_FILE_CLEAN" ]; then
    error_exit "Invalid characters in file path" 2
fi

if [ ! -f "$SKILL_FILE" ]; then
    error_exit "File not found: $SKILL_FILE" 3
fi

if [ ! -r "$SKILL_FILE" ]; then
    error_exit "File not readable: $SKILL_FILE" 4
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    warn "Docker not available - skipping sandbox analysis"
    echo "   Install Docker for dynamic behavioral analysis"
    exit 0
fi

# Check Docker is running
if ! docker info > /dev/null 2>&1; then
    warn "Docker daemon not running - skipping sandbox analysis"
    exit 0
fi

# Check Dockerfile exists
if [ ! -f "$SANDBOX_DIR/Dockerfile" ]; then
    error_exit "Sandbox Dockerfile not found at $SANDBOX_DIR/Dockerfile" 5
fi

SKILL_BASENAME=$(basename "$SKILL_FILE")
HASH=$(shasum -a 256 "$SKILL_FILE" | cut -d' ' -f1)

echo "========================================"
echo "   SANDBOX BEHAVIORAL ANALYSIS v0.2"
echo "========================================"
echo "Skill: $SKILL_FILE"
echo "Hash: $HASH"
echo "Container: $CONTAINER_NAME"
echo "Timeout: ${TIMEOUT_SECONDS}s"
echo "========================================"
echo ""

# Build sandbox image
echo "=== Building Sandbox ==="
if ! docker build -q -t skill-audit-sandbox "$SANDBOX_DIR" > /dev/null 2>&1; then
    echo "⚠️  Failed to build sandbox image"
    exit 1
fi
echo "✅ Sandbox image ready"
echo ""

# Create temp workspace
TEMP_DIR=$(mktemp -d) || error_exit "Failed to create temp directory"

cp "$SKILL_FILE" "$TEMP_DIR/skill.md"

# Create analysis script
cat > "$TEMP_DIR/analyze.sh" << 'ANALYSIS'
#!/bin/bash
set -e

HONEYPOT_ACCESSED=()
CODE_EXECUTED=()
NETWORK_ATTEMPTS=()
FILES_MODIFIED=()

echo "=== SKILL ANALYSIS LOG ==="
echo "Started: $(date)"
echo ""

# Track original honeypot hashes
ORIG_ENV_HASH=$(sha256sum /home/agent/.clawdbot/.env 2>/dev/null | cut -d' ' -f1)
ORIG_SOUL_HASH=$(sha256sum /home/agent/SOUL.md 2>/dev/null | cut -d' ' -f1)
ORIG_AGENTS_HASH=$(sha256sum /home/agent/AGENTS.md 2>/dev/null | cut -d' ' -f1)

# Extract code blocks from skill
echo "=== EXTRACTING CODE BLOCKS ==="

# Extract bash
grep -A 50 '```bash' /skill/skill.md 2>/dev/null | sed '/```$/q' | grep -v '```' > /tmp/bash_code.sh 2>/dev/null || true
# Extract sh  
grep -A 50 '```sh' /skill/skill.md 2>/dev/null | sed '/```$/q' | grep -v '```' >> /tmp/bash_code.sh 2>/dev/null || true
# Extract python
grep -A 50 '```python' /skill/skill.md 2>/dev/null | sed '/```$/q' | grep -v '```' > /tmp/python_code.py 2>/dev/null || true
# Extract javascript
grep -A 50 '```javascript' /skill/skill.md 2>/dev/null | sed '/```$/q' | grep -v '```' > /tmp/js_code.js 2>/dev/null || true

echo "Bash code: $(wc -l < /tmp/bash_code.sh 2>/dev/null || echo 0) lines"
echo "Python code: $(wc -l < /tmp/python_code.py 2>/dev/null || echo 0) lines"
echo "JavaScript code: $(wc -l < /tmp/js_code.js 2>/dev/null || echo 0) lines"
echo ""

# Execute extracted code (sandboxed, no network)
echo "=== EXECUTION TRACE ==="

if [ -s /tmp/bash_code.sh ]; then
    echo "--- Bash Execution ---"
    timeout 5 strace -f -e trace=open,openat,read,write,connect,sendto 2>&1 bash /tmp/bash_code.sh 2>&1 | head -50 || echo "(completed/timeout)"
    echo ""
fi

if [ -s /tmp/python_code.py ]; then
    echo "--- Python Execution ---"
    timeout 5 python3 /tmp/python_code.py 2>&1 | head -30 || echo "(completed/timeout)"
    echo ""
fi

echo ""
echo "=== HONEYPOT CHECK ==="

# Check credential file access
echo "Checking for honeypot access..."
NEW_ENV_HASH=$(sha256sum /home/agent/.clawdbot/.env 2>/dev/null | cut -d' ' -f1)
NEW_SOUL_HASH=$(sha256sum /home/agent/SOUL.md 2>/dev/null | cut -d' ' -f1)
NEW_AGENTS_HASH=$(sha256sum /home/agent/AGENTS.md 2>/dev/null | cut -d' ' -f1)

if [ "$ORIG_ENV_HASH" != "$NEW_ENV_HASH" ]; then
    echo "⛔ ALERT: .env file was modified!"
fi

if [ "$ORIG_SOUL_HASH" != "$NEW_SOUL_HASH" ]; then
    echo "⛔ ALERT: SOUL.md was modified!"
    echo "New content:"
    cat /home/agent/SOUL.md
fi

if [ "$ORIG_AGENTS_HASH" != "$NEW_AGENTS_HASH" ]; then
    echo "⛔ ALERT: AGENTS.md was modified!"
fi

# Check if honeypot values appear in output or temp files
if grep -r "HONEYPOT" /tmp/ 2>/dev/null | grep -v analyze.sh; then
    echo "⛔ ALERT: Honeypot values found in temp files!"
fi

echo ""
echo "=== NETWORK TEST ==="
echo "Container has --network none, testing..."
if curl --connect-timeout 2 http://example.com 2>&1 | grep -q "Could not resolve"; then
    echo "✅ Network correctly isolated"
else
    echo "⚠️  Network may not be fully isolated"
fi

echo ""
echo "=== FILE SYSTEM SCAN ==="
echo "Checking /tmp for suspicious files..."
ls -la /tmp/ 2>/dev/null | grep -v "analyze\|code\|bash\|python\|js" || echo "(clean)"

echo ""
echo "=== ANALYSIS COMPLETE ==="
echo "Finished: $(date)"
ANALYSIS
chmod +x "$TEMP_DIR/analyze.sh"

# Run container
echo "=== Starting Sandbox Container ==="
docker run -d \
    --name "$CONTAINER_NAME" \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,size=50m \
    --memory=256m \
    --cpus=0.5 \
    --pids-limit=50 \
    --security-opt=no-new-privileges \
    -v "$TEMP_DIR:/skill:ro" \
    skill-audit-sandbox \
    sleep 120 > /dev/null

echo "✅ Container started (isolated, read-only, no network)"
echo ""

echo "=== Running Behavioral Analysis ==="
docker exec "$CONTAINER_NAME" bash /skill/analyze.sh 2>&1

echo ""
echo "=== Sandbox Cleanup ==="
docker stop "$CONTAINER_NAME" > /dev/null 2>&1 || true
docker rm "$CONTAINER_NAME" > /dev/null 2>&1 || true
echo "✅ Container destroyed"

echo ""
echo "========================================"
echo "   SANDBOX ANALYSIS COMPLETE"
echo "========================================"
