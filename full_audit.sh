#!/usr/bin/env bash
# Skill Auditor - Full Analysis (Static + Sandbox) v0.2.1
# Combines static YARA/pattern analysis with dynamic Docker sandbox

set -uo pipefail

# === ERROR HANDLING ===
error_exit() {
    local msg="$1"
    local code="${2:-1}"
    echo "❌ Error: $msg" >&2
    exit "$code"
}

# Resolve symlinks to find actual script directory (macOS compatible)
SOURCE="$0"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

# === INPUT VALIDATION ===
SKILL_FILE="${1:-}"

if [ -z "$SKILL_FILE" ]; then
    cat >&2 << 'USAGE'
Usage: skill-audit-full <skill_file>

Runs comprehensive security audit:
  Phase 1: Static analysis (YARA rules + pattern matching)
  Phase 2: Dynamic analysis (Docker sandbox with honeypots)

Exit codes:
  0 - Analysis complete
  1 - Usage error
  2 - Invalid input
  3 - File not found
  4 - Static analysis failed
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
    error_exit "File not readable: $SKILL_FILE" 3
fi

# Verify audit script exists
if [ ! -x "$SCRIPT_DIR/audit.sh" ]; then
    error_exit "audit.sh not found or not executable" 4
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           SKILL AUDITOR - FULL SECURITY ANALYSIS             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Run static analysis
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ PHASE 1: STATIC ANALYSIS                                       │"
echo "└────────────────────────────────────────────────────────────────┘"
"$SCRIPT_DIR/audit.sh" "$SKILL_FILE"

# Capture risk from static analysis
STATIC_RESULT=$("$SCRIPT_DIR/audit.sh" "$SKILL_FILE" json 2>/dev/null)
STATIC_SCORE=$(echo "$STATIC_RESULT" | grep -o '"score": [0-9]*' | grep -o '[0-9]*')
STATIC_RISK=$(echo "$STATIC_RESULT" | grep -o '"risk_level": "[^"]*"' | cut -d'"' -f4)

echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ PHASE 2: DYNAMIC SANDBOX ANALYSIS                              │"
echo "└────────────────────────────────────────────────────────────────┘"

if command -v docker &> /dev/null; then
    "$SCRIPT_DIR/sandbox_audit.sh" "$SKILL_FILE"
else
    echo "⚠️  Docker not available - skipping sandbox analysis"
    echo "   Install Docker for behavioral analysis with honeypots"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    FINAL ASSESSMENT                          ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Static Analysis Score: $(printf '%-34s' "$STATIC_SCORE") ║"
echo "║  Static Risk Level: $(printf '%-38s' "$STATIC_RISK") ║"
echo "╠══════════════════════════════════════════════════════════════╣"

case "$STATIC_RISK" in
    LOW)
        echo "║  🟢 VERDICT: LIKELY SAFE                                     ║"
        echo "║  Recommendation: Safe for manual review and installation     ║"
        ;;
    MEDIUM)
        echo "║  🟠 VERDICT: REVIEW REQUIRED                                 ║"
        echo "║  Recommendation: Inspect flagged patterns before installing  ║"
        ;;
    HIGH)
        echo "║  🔴 VERDICT: NOT RECOMMENDED                                 ║"
        echo "║  Recommendation: Do not install without expert review        ║"
        ;;
    CRITICAL)
        echo "║  ⛔ VERDICT: REJECT                                          ║"
        echo "║  Recommendation: DO NOT INSTALL - likely malicious           ║"
        ;;
esac

echo "╚══════════════════════════════════════════════════════════════╝"
