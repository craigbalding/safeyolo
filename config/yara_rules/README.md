# YARA Rules

This directory contains YARA rules for threat detection in the extended build.

## Default Rules

`default.yar` includes basic rules for:
- AWS access keys
- GitHub tokens
- Private key material
- Common jailbreak phrases
- LLM instruction markers

## Custom Rules

Add your own `.yar` files here, then load them:

```bash
# Edit docker-compose.yml or start-safeyolo.sh
--set yara_rules=/app/config/yara_rules/custom.yar
```

## Rule Format

```yara
rule Rule_Name {
    meta:
        description = "What this detects"
        severity = 5  // 1-5, 5 = critical
        category = "credential|jailbreak|injection|pii"
    strings:
        $pattern = /regex/ ascii
        $literal = "exact match" nocase
    condition:
        any of them
}
```

## Testing Rules

```bash
# In dev build
docker exec -it safeyolo bash
cd /app
yara config/yara_rules/default.yar test_file.txt
```

## Resources

- YARA documentation: https://yara.readthedocs.io/
- Rule examples: https://github.com/Yara-Rules/rules
