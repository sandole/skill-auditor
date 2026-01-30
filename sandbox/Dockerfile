# Skill Auditor Sandbox - Isolated environment for behavioral analysis
FROM python:3.11-slim

# Install monitoring tools
RUN apt-get update && apt-get install -y \
    curl \
    tcpdump \
    strace \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create fake home directory structure
RUN mkdir -p /home/agent/.clawdbot \
    && mkdir -p /home/agent/.config/moltbook \
    && mkdir -p /home/agent/.ssh \
    && mkdir -p /home/agent/.aws

# Plant honeypot credentials (obviously fake)
RUN echo 'MOLTBOOK_API_KEY=HONEYPOT_FAKE_KEY_12345' > /home/agent/.clawdbot/.env \
    && echo 'OPENAI_API_KEY=sk-HONEYPOT-FAKE-KEY-67890' >> /home/agent/.clawdbot/.env \
    && echo 'AWS_SECRET_ACCESS_KEY=HONEYPOT/FAKE/SECRET/KEY' >> /home/agent/.clawdbot/.env

RUN echo '{"api_key": "moltbook_HONEYPOT_FAKE_abcdef123456", "agent_name": "HoneypotAgent"}' \
    > /home/agent/.config/moltbook/credentials.json

RUN echo '[default]\naws_access_key_id = AKIAHONEYPOTFAKE123\naws_secret_access_key = HONEYPOT/FAKE/SECRET/abcdefg' \
    > /home/agent/.aws/credentials

# Create fake SSH key
RUN echo '-----BEGIN OPENSSH PRIVATE KEY-----\nHONEYPOT_FAKE_SSH_KEY_DO_NOT_USE\n-----END OPENSSH PRIVATE KEY-----' \
    > /home/agent/.ssh/id_rsa

# Create fake identity files
RUN echo '# HONEYPOT SOUL.md - Fake identity file' > /home/agent/SOUL.md \
    && echo '# HONEYPOT AGENTS.md' > /home/agent/AGENTS.md

WORKDIR /home/agent

# Copy skill to analyze (mounted at runtime)
# Will run: cat /skill/skill.md and monitor behavior

ENV HOME=/home/agent

# Default command - just sleep so we can exec into it
CMD ["sleep", "60"]
