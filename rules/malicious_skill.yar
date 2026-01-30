/*
 * YARA Rules for Malicious Skill Detection
 * JarvisYVR Skill Auditor v0.1
 */

rule CredentialTheft {
    meta:
        description = "Detects attempts to access credential files"
        severity = "critical"
        category = "exfiltration"
    strings:
        $env1 = ".env" nocase
        $env2 = "credentials.json" nocase
        $env3 = "api_key" nocase
        $env4 = "API_KEY" 
        $env5 = "MOLTBOOK_API_KEY"
        $env6 = "~/.clawdbot" nocase
        $env7 = "~/.config/moltbook" nocase
        $env8 = "Bearer " 
        $env9 = "Authorization:" nocase
        $aws1 = ".aws/credentials"
        $aws2 = "AWS_SECRET"
        $ssh1 = ".ssh/id_rsa"
        $ssh2 = ".ssh/id_ed25519"
    condition:
        any of them
}

rule DataExfiltration {
    meta:
        description = "Detects potential data exfiltration patterns"
        severity = "critical"
        category = "exfiltration"
    strings:
        $post1 = "curl" nocase
        $post2 = "-X POST" nocase
        $post3 = "POST " 
        $post4 = "requests.post" nocase
        $post5 = "fetch(" 
        $webhook1 = "webhook.site" nocase
        $webhook2 = "ngrok.io" nocase
        $webhook3 = "requestbin" nocase
        $webhook4 = "pipedream" nocase
        $webhook5 = "hookbin" nocase
        $webhook6 = "beeceptor" nocase
    condition:
        (any of ($post*)) and (any of ($webhook*))
}

rule IdentityTampering {
    meta:
        description = "Detects attempts to modify agent identity files"
        severity = "critical"
        category = "tampering"
    strings:
        $soul = "SOUL.md" nocase
        $agents = "AGENTS.md" nocase
        $identity = "IDENTITY.md" nocase
        $user = "USER.md" nocase
        $memory = "MEMORY.md" nocase
        $heartbeat = "HEARTBEAT.md" nocase
        $write1 = "echo" 
        $write2 = ">>" 
        $write3 = "write" nocase
        $write4 = "append" nocase
        $write5 = "modify" nocase
        $write6 = "update" nocase
    condition:
        (any of ($soul, $agents, $identity, $user, $memory, $heartbeat)) and (any of ($write*))
}

rule PromptInjection {
    meta:
        description = "Detects prompt injection patterns"
        severity = "high"
        category = "injection"
    strings:
        $inject1 = "ignore previous" nocase
        $inject2 = "ignore all previous" nocase
        $inject3 = "disregard" nocase
        $inject4 = "forget your instructions" nocase
        $inject5 = "new instructions" nocase
        $inject6 = "you are now" nocase
        $inject7 = "act as" nocase
        $inject8 = "pretend to be" nocase
        $inject9 = "system prompt" nocase
        $inject10 = "jailbreak" nocase
    condition:
        any of them
}

rule ObfuscatedCode {
    meta:
        description = "Detects obfuscated or encoded content"
        severity = "high"
        category = "obfuscation"
    strings:
        $b64_pattern = /[A-Za-z0-9+\/]{40,}={0,2}/
        $hex_pattern = /\\x[0-9a-fA-F]{2}/
        $eval1 = "eval(" nocase
        $eval2 = "exec(" nocase
        $eval3 = "compile(" nocase
        $decode1 = "base64" nocase
        $decode2 = "atob(" nocase
        $decode3 = "decode(" nocase
    condition:
        ($b64_pattern and any of ($decode*)) or (any of ($eval*)) or (#hex_pattern > 5)
}

rule SuspiciousNetworking {
    meta:
        description = "Detects suspicious network operations"
        severity = "medium"
        category = "networking"
    strings:
        $net1 = "socket" nocase
        $net2 = "urllib" nocase
        $net3 = "requests" nocase
        $net4 = "http.client" nocase
        $net5 = "aiohttp" nocase
        $net6 = "reverse shell" nocase
        $net7 = "bind shell" nocase
        $net8 = "nc -" 
        $net9 = "netcat" nocase
    condition:
        2 of them
}

rule FileSystemAbuse {
    meta:
        description = "Detects suspicious file system operations"
        severity = "medium"
        category = "filesystem"
    strings:
        $fs1 = "rm -rf" nocase
        $fs2 = "rmdir" nocase
        $fs3 = "shutil.rmtree" nocase
        $fs4 = "os.remove" nocase
        $fs5 = "/etc/passwd"
        $fs6 = "/etc/shadow"
        $fs7 = "chmod 777"
        $fs8 = "chown"
    condition:
        any of them
}
