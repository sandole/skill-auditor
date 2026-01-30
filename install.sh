#!/usr/bin/env bash
# Skill Auditor Installer
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${HOME}/.local/bin"

echo "Installing Skill Auditor..."

# Create bin directory
mkdir -p "$BIN_DIR"

# Make scripts executable
chmod +x "$SCRIPT_DIR/audit.sh"
chmod +x "$SCRIPT_DIR/sandbox_audit.sh"
chmod +x "$SCRIPT_DIR/full_audit.sh" 2>/dev/null || true

# Create symlinks
ln -sf "$SCRIPT_DIR/audit.sh" "$BIN_DIR/skill-audit"
ln -sf "$SCRIPT_DIR/full_audit.sh" "$BIN_DIR/skill-audit-full"

# Check if bin is in PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo ""
    echo "⚠️  Add to your shell profile:"
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
fi

# Check optional dependencies
echo ""
echo "=== Dependencies ==="
if command -v yara &> /dev/null; then
    echo "✅ YARA installed (enhanced detection)"
else
    echo "⚪ YARA not found (optional - brew install yara)"
fi

if command -v docker &> /dev/null; then
    echo "✅ Docker installed (sandbox analysis available)"
else
    echo "⚪ Docker not found (optional - for sandbox analysis)"
fi

echo ""
echo "✅ Skill Auditor installed!"
echo ""
echo "Usage:"
echo "  skill-audit <skill.md>       # Static analysis"
echo "  skill-audit <skill.md> json  # JSON output"
echo "  skill-audit-full <skill.md>  # Static + sandbox"
