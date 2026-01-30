#!/usr/bin/env bash
# Skill Auditor v0.2.1 - JarvisYVR
# Static analysis of skill files for malicious patterns
# Weighted scoring with false positive reduction

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

# === RESOLVE SCRIPT LOCATION ===
SOURCE="$0"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
RULES_DIR="$SCRIPT_DIR/rules"
REPORTS_DIR="$SCRIPT_DIR/reports"

# === INPUT VALIDATION ===
SKILL_FILE="${1:-}"
OUTPUT_FORMAT="${2:-text}"

# Check required argument
if [ -z "$SKILL_FILE" ]; then
    cat >&2 << 'USAGE'
Usage: skill-audit <skill_file> [text|json]

Arguments:
  skill_file    Path to skill file (.md recommended)
  output        Output format: text (default) or json

Examples:
  skill-audit /path/to/SKILL.md
  skill-audit /path/to/SKILL.md json
USAGE
    exit 1
fi

# Validate output format
case "$OUTPUT_FORMAT" in
    text|json) ;;
    *) error_exit "Invalid output format '$OUTPUT_FORMAT'. Use 'text' or 'json'" 2 ;;
esac

# Sanitize and validate file path
# Prevent path traversal and command injection
SKILL_FILE_CLEAN=$(echo "$SKILL_FILE" | sed 's/[;&|`$]//g')
if [ "$SKILL_FILE" != "$SKILL_FILE_CLEAN" ]; then
    error_exit "Invalid characters in file path" 3
fi

# Check file exists
if [ ! -e "$SKILL_FILE" ]; then
    error_exit "File not found: $SKILL_FILE" 4
fi

# Check it's a regular file (not directory, device, etc.)
if [ ! -f "$SKILL_FILE" ]; then
    error_exit "Not a regular file: $SKILL_FILE" 5
fi

# Check file is readable
if [ ! -r "$SKILL_FILE" ]; then
    error_exit "File not readable: $SKILL_FILE" 6
fi

# Check file size (max 10MB to prevent DoS)
MAX_SIZE=$((10 * 1024 * 1024))
FILE_SIZE=$(wc -c < "$SKILL_FILE" 2>/dev/null | tr -d ' ') || FILE_SIZE=0
if [ "$FILE_SIZE" -gt "$MAX_SIZE" ]; then
    error_exit "File too large (${FILE_SIZE} bytes, max ${MAX_SIZE})" 7
fi

# Check file isn't empty
if [ "$FILE_SIZE" -eq 0 ]; then
    error_exit "File is empty: $SKILL_FILE" 8
fi

# Warn if not markdown
if [[ ! "$SKILL_FILE" =~ \.(md|markdown)$ ]]; then
    warn "File doesn't have .md extension - may not be a skill file"
fi

# Check for binary content (skills should be text)
if file "$SKILL_FILE" 2>/dev/null | grep -qE 'executable|binary|data'; then
    error_exit "File appears to be binary, not a text skill file" 9
fi

# Create reports directory with error handling
if ! mkdir -p "$REPORTS_DIR" 2>/dev/null; then
    warn "Could not create reports directory, continuing without saving"
fi

BASENAME=$(basename "$SKILL_FILE" .md) || error_exit "Failed to get basename"
TIMESTAMP=$(date +%Y%m%d_%H%M%S) || TIMESTAMP="unknown"
HASH=$(shasum -a 256 "$SKILL_FILE" 2>/dev/null | cut -d' ' -f1) || HASH="unavailable"
FILESIZE="$FILE_SIZE"  # Already validated above

TOTAL_SCORE=0
FINDING_COUNT=0
FINDINGS_TEXT=""

add_finding() {
    local category="$1"
    local severity="$2"
    local description="$3"
    local evidence="$4"
    
    # Weight by category
    local weight=50
    case "$category" in
        credential_theft)   weight=100 ;;
        data_exfiltration)  weight=100 ;;
        identity_tampering) weight=90 ;;
        prompt_injection)   weight=70 ;;
        obfuscation)        weight=60 ;;
        filesystem_abuse)   weight=50 ;;
        suspicious_network) weight=40 ;;
    esac
    
    # Multiplier by severity
    local multiplier=50
    case "$severity" in
        critical) multiplier=100 ;;
        high)     multiplier=70 ;;
        medium)   multiplier=40 ;;
        low)      multiplier=20 ;;
    esac
    
    local score=$((weight * multiplier / 100))
    TOTAL_SCORE=$((TOTAL_SCORE + score))
    FINDING_COUNT=$((FINDING_COUNT + 1))
    
    local sev_icon="⚪"
    case "$severity" in
        critical) sev_icon="⛔" ;;
        high)     sev_icon="🔴" ;;
        medium)   sev_icon="🟠" ;;
        low)      sev_icon="🟡" ;;
    esac
    
    FINDINGS_TEXT="${FINDINGS_TEXT}${sev_icon} [${severity}] ${category}
   ${description}
   Evidence: ${evidence}
   Score: +${score}

"
}

check_credential_patterns() {
    # Critical: Honeypot/sensitive paths in executable context
    local sensitive_paths=".clawdbot/.env .config/moltbook .aws/credentials .ssh/id_rsa .ssh/id_ed25519"
    for path in $sensitive_paths; do
        if grep -F "$path" "$SKILL_FILE" > /dev/null 2>&1; then
            if grep -B2 -A2 "$path" "$SKILL_FILE" | grep -qE '^```|cat |read |load|open' 2>/dev/null; then
                add_finding "credential_theft" "high" "Access to sensitive path: $path" \
                    "$(grep -n "$path" "$SKILL_FILE" | head -1)"
                return
            fi
        fi
    done
    
    # High: Credential file access with exfiltration
    if grep -qiE '(cat|read|load|open).*\.(env|credentials|aws)' "$SKILL_FILE" 2>/dev/null; then
        if grep -qiE '(curl|post|send|webhook)' "$SKILL_FILE" 2>/dev/null; then
            add_finding "credential_theft" "critical" "Credential access with exfiltration" \
                "$(grep -inE '(cat|read).*\.env' "$SKILL_FILE" | head -1)"
        fi
    fi
    
    # Medium: API key export/echo
    if grep -qE '^\s*(export|echo|cat|curl).*API_KEY' "$SKILL_FILE" 2>/dev/null; then
        add_finding "credential_theft" "medium" "API key in executable context" \
            "$(grep -nE '(export|echo).*API_KEY' "$SKILL_FILE" | head -1)"
    fi
}

check_exfiltration_patterns() {
    # Critical: Known exfiltration endpoints
    local bad_domains="webhook.site ngrok.io requestbin pipedream hookbin beeceptor burpcollaborator"
    for domain in $bad_domains; do
        if grep -qi "$domain" "$SKILL_FILE" 2>/dev/null; then
            add_finding "data_exfiltration" "critical" "Known exfiltration endpoint: $domain" \
                "$(grep -in "$domain" "$SKILL_FILE" | head -1)"
            return
        fi
    done
    
    # High: POST to unknown endpoints
    if grep -qiE 'curl.*-X\s*POST|requests\.post' "$SKILL_FILE" 2>/dev/null; then
        local safe_apis="api.openai.com api.anthropic.com api.github.com api.open-meteo.com wttr.in googleapis.com"
        local is_safe=false
        for api in $safe_apis; do
            if grep -qi "$api" "$SKILL_FILE" 2>/dev/null; then
                is_safe=true
                break
            fi
        done
        if [ "$is_safe" = false ]; then
            add_finding "data_exfiltration" "high" "POST to unknown endpoint" \
                "$(grep -inE 'curl.*POST|requests\.post' "$SKILL_FILE" | head -1)"
        fi
    fi
}

check_identity_tampering() {
    local identity_files="SOUL.md AGENTS.md IDENTITY.md USER.md MEMORY.md HEARTBEAT.md"
    
    for ifile in $identity_files; do
        if grep -qi "$ifile" "$SKILL_FILE" 2>/dev/null; then
            # Check for write operations targeting identity files
            if grep -qi "$ifile" "$SKILL_FILE" | grep -qiE '(echo.*>>|write|append|modify|overwrite)' 2>/dev/null; then
                add_finding "identity_tampering" "critical" "Write operation targeting $ifile" \
                    "$(grep -in "$ifile" "$SKILL_FILE" | head -1)"
                return
            fi
            # Check for sneaky context
            if grep -iB5 -iA5 "$ifile" "$SKILL_FILE" 2>/dev/null | grep -qiE '(secretly|without.*asking|silently|automatic)' 2>/dev/null; then
                add_finding "identity_tampering" "high" "Suspicious reference to $ifile" \
                    "$(grep -in "$ifile" "$SKILL_FILE" | head -1)"
                return
            fi
        fi
    done
}

check_prompt_injection() {
    # Critical: Direct override attempts
    if grep -qiE 'ignore.*all.*previous|disregard.*instructions|forget.*instructions|override.*instructions' "$SKILL_FILE" 2>/dev/null; then
        add_finding "prompt_injection" "critical" "Instruction override attempt" \
            "$(grep -inE 'ignore.*previous|disregard|forget.*instruction' "$SKILL_FILE" | head -1)"
        return
    fi
    
    # High: Jailbreak patterns
    if grep -qiE 'jailbreak|DAN|do.anything.now|no.*restrictions' "$SKILL_FILE" 2>/dev/null; then
        add_finding "prompt_injection" "high" "Jailbreak pattern" \
            "$(grep -inE 'jailbreak|DAN' "$SKILL_FILE" | head -1)"
        return
    fi
    
    # Medium: Identity manipulation with privilege context
    if grep -qiE 'you are now|pretend to be' "$SKILL_FILE" 2>/dev/null; then
        if grep -iB3 -iA3 'you are now' "$SKILL_FILE" 2>/dev/null | grep -qiE '(admin|root|unrestricted|no.limits)' 2>/dev/null; then
            add_finding "prompt_injection" "medium" "Identity manipulation" \
                "$(grep -inE 'you are now' "$SKILL_FILE" | head -1)"
        fi
    fi
}

check_obfuscation() {
    # Critical: eval/exec with decoding
    if grep -qE '(eval|exec)\s*\(' "$SKILL_FILE" 2>/dev/null; then
        if grep -qiE '(base64|decode|atob)' "$SKILL_FILE" 2>/dev/null; then
            add_finding "obfuscation" "critical" "Code execution with decoding" \
                "$(grep -nE '(eval|exec)' "$SKILL_FILE" | head -1)"
            return
        else
            add_finding "obfuscation" "high" "Dynamic code execution" \
                "$(grep -nE '(eval|exec)' "$SKILL_FILE" | head -1)"
            return
        fi
    fi
    
    # High: Large base64 blobs
    if grep -qoE '[A-Za-z0-9+/]{50,}={0,2}' "$SKILL_FILE" 2>/dev/null; then
        add_finding "obfuscation" "high" "Large base64 content" \
            "$(grep -oE '[A-Za-z0-9+/]{50,}' "$SKILL_FILE" | head -1 | cut -c1-30)..."
    fi
    
    # Medium: Hex escapes
    local hex_count
    hex_count=$(grep -oE '\\x[0-9a-fA-F]{2}' "$SKILL_FILE" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$hex_count" -gt 5 ]; then
        add_finding "obfuscation" "medium" "Hex escape sequences ($hex_count found)" \
            "Multiple \\x## patterns"
    fi
}

check_filesystem_abuse() {
    # Critical: Recursive delete from root
    if grep -qE 'rm\s+-rf\s+/' "$SKILL_FILE" 2>/dev/null; then
        add_finding "filesystem_abuse" "critical" "Recursive delete from root" \
            "$(grep -nE 'rm\s+-rf' "$SKILL_FILE" | head -1)"
        return
    fi
    
    # High: System file access
    local system_paths="/etc/passwd /etc/shadow /etc/sudoers"
    for spath in $system_paths; do
        if grep -qF "$spath" "$SKILL_FILE" 2>/dev/null; then
            add_finding "filesystem_abuse" "high" "System file access: $spath" \
                "$(grep -n "$spath" "$SKILL_FILE" | head -1)"
            return
        fi
    done
    
    # Medium: Overly permissive chmod
    if grep -qE 'chmod\s+777' "$SKILL_FILE" 2>/dev/null; then
        add_finding "filesystem_abuse" "medium" "Overly permissive chmod" \
            "$(grep -nE 'chmod.*777' "$SKILL_FILE" | head -1)"
    fi
}

check_suspicious_network() {
    # Critical: Shell patterns
    if grep -qiE 'reverse.shell|bind.shell|nc\s+-[el]|netcat.*-[el]' "$SKILL_FILE" 2>/dev/null; then
        add_finding "suspicious_network" "critical" "Shell/backdoor pattern" \
            "$(grep -inE 'reverse.shell|nc\s+-' "$SKILL_FILE" | head -1)"
        return
    fi
    
    # Medium: Raw sockets
    if grep -qiE 'socket\.socket|SOCK_STREAM|SOCK_RAW' "$SKILL_FILE" 2>/dev/null; then
        add_finding "suspicious_network" "medium" "Low-level socket ops" \
            "$(grep -inE 'socket' "$SKILL_FILE" | head -1)"
    fi
}

run_yara_scan() {
    if command -v yara &> /dev/null && [ -f "$RULES_DIR/malicious_skill.yar" ]; then
        echo "=== YARA SCAN ==="
        local yara_out
        yara_out=$(yara -s "$RULES_DIR/malicious_skill.yar" "$SKILL_FILE" 2>/dev/null || true)
        if [ -n "$yara_out" ]; then
            echo "$yara_out" | head -20
            local yara_matches
            yara_matches=$(echo "$yara_out" | grep -c "^[A-Za-z]" 2>/dev/null || echo "0")
            TOTAL_SCORE=$((TOTAL_SCORE + yara_matches * 15))
        else
            echo "✅ No YARA matches"
        fi
        echo ""
    fi
}

extract_urls() {
    echo "=== EXTRACTED URLs ==="
    local urls
    urls=$(grep -oE 'https?://[^ )"<>]+' "$SKILL_FILE" 2>/dev/null | sort -u || echo "")
    if [ -n "$urls" ]; then
        echo "$urls"
    else
        echo "(none)"
    fi
    echo ""
}

calculate_risk() {
    if [ "$TOTAL_SCORE" -eq 0 ]; then
        RISK_LEVEL="LOW"
        RISK_EMOJI="🟢"
        RECOMMENDATION="Safe for manual review"
    elif [ "$TOTAL_SCORE" -lt 50 ]; then
        RISK_LEVEL="LOW"
        RISK_EMOJI="🟢"
        RECOMMENDATION="Minor concerns, review flagged items"
    elif [ "$TOTAL_SCORE" -lt 100 ]; then
        RISK_LEVEL="MEDIUM"
        RISK_EMOJI="🟠"
        RECOMMENDATION="Review carefully before installing"
    elif [ "$TOTAL_SCORE" -lt 150 ]; then
        RISK_LEVEL="HIGH"
        RISK_EMOJI="🔴"
        RECOMMENDATION="Do not install without analysis"
    else
        RISK_LEVEL="CRITICAL"
        RISK_EMOJI="⛔"
        RECOMMENDATION="REJECT - Multiple severe threats"
    fi
}

output_report() {
    echo "========================================"
    echo "   SKILL AUDITOR v0.2.1"
    echo "========================================"
    echo "File: $SKILL_FILE"
    echo "Size: $FILESIZE bytes"
    echo "SHA256: $HASH"
    echo "Scanned: $(date)"
    echo "========================================"
    echo ""
    
    run_yara_scan
    
    echo "=== THREAT ANALYSIS ==="
    if [ -z "$FINDINGS_TEXT" ]; then
        echo "✅ No threats detected"
    else
        echo "$FINDINGS_TEXT"
    fi
    
    extract_urls
    
    calculate_risk
    
    echo "========================================"
    echo "   RISK ASSESSMENT"
    echo "========================================"
    echo "$RISK_EMOJI Risk Level: $RISK_LEVEL"
    echo "   Threat Score: $TOTAL_SCORE"
    echo "   Findings: $FINDING_COUNT"
    echo ""
    echo "   $RECOMMENDATION"
    echo "========================================"
}

output_json() {
    calculate_risk
    cat << EOF
{
  "file": "$SKILL_FILE",
  "hash": "$HASH",
  "size": $FILESIZE,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "score": $TOTAL_SCORE,
  "risk_level": "$RISK_LEVEL",
  "finding_count": $FINDING_COUNT,
  "recommendation": "$RECOMMENDATION"
}
EOF
}

# Run all checks
check_credential_patterns
check_exfiltration_patterns  
check_identity_tampering
check_prompt_injection
check_obfuscation
check_filesystem_abuse
check_suspicious_network

if [ "$OUTPUT_FORMAT" = "json" ]; then
    output_json
else
    output_report
fi
