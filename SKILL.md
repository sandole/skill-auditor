# Skill Auditor

Security auditing for Clawdbot skills. Analyzes skills for malicious patterns before installation.

## Quick Use

Audit a skill before installing:
```bash
skill-audit /path/to/SKILL.md
```

JSON output for automation:
```bash
skill-audit /path/to/SKILL.md json
```

Full analysis with Docker sandbox:
```bash
skill-audit-full /path/to/SKILL.md
```

## What It Detects

| Category | Severity | Examples |
|----------|----------|----------|
| **Credential Theft** | Critical | `.env` access, API key exfiltration, SSH key theft |
| **Data Exfiltration** | Critical | webhook.site, ngrok tunnels, suspicious POSTs |
| **Identity Tampering** | Critical | Modifying SOUL.md, AGENTS.md, USER.md |
| **Prompt Injection** | High | "ignore previous instructions", jailbreaks |
| **Code Obfuscation** | High | base64 payloads, eval(), exec() |
| **Filesystem Abuse** | Medium | rm -rf, /etc/passwd access |
| **Suspicious Network** | Medium | Reverse shells, raw sockets |

## Risk Levels

- 🟢 **LOW** (0-49): Safe for manual review
- 🟠 **MEDIUM** (50-99): Review carefully
- 🔴 **HIGH** (100-149): Do not install without deep analysis
- ⛔ **CRITICAL** (150+): REJECT - multiple severe threats

## Sandbox Analysis

If Docker is available, `skill-audit-full` runs the skill in an isolated container:
- No network access
- Read-only filesystem
- Honeypot credentials planted
- Behavioral monitoring via strace

Any credential access or identity tampering triggers alerts.

## Integration

### Before Installing Skills
```bash
# Download skill but don't install
curl -o /tmp/new_skill.md https://clawdhub.com/skills/example/SKILL.md

# Audit it
skill-audit /tmp/new_skill.md

# If safe, install
cp /tmp/new_skill.md ~/.clawdbot/skills/example/SKILL.md
```

### CI/CD Pipeline
```bash
skill-audit skill.md json | jq '.risk_level'
# Returns: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
```

### Batch Audit
```bash
for skill in skills/*/SKILL.md; do
    echo "=== $skill ==="
    skill-audit "$skill" json | jq -r '"\(.risk_level): score \(.score)"'
done
```

## Files

- `audit.sh` - Static analysis (YARA + pattern matching)
- `sandbox_audit.sh` - Dynamic analysis (Docker sandbox)
- `rules/malicious_skill.yar` - YARA detection rules

## Requirements

- **Required**: bash, grep, sed
- **Optional**: yara (enhanced detection)
- **Optional**: Docker (sandbox analysis)

Install YARA on macOS:
```bash
brew install yara
```

## Limitations

- Static analysis can't catch all obfuscation techniques
- Sandbox analysis requires Docker
- Some legitimate skills may trigger false positives (e.g., API integrations)
- Not a substitute for manual code review

## Contributing

Found a bypass? Report it or submit a PR with a new detection rule.
