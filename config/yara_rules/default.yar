/*
 * SafeYolo Default YARA Rules
 *
 * These rules scan for common credential patterns and security threats.
 * Add custom rules here or load them via --set yara_rules=/path/to/custom.yar
 */

rule AWS_Access_Key {
    meta:
        description = "AWS Access Key ID"
        severity = 5
        category = "credential"
    strings:
        $key = /AKIA[0-9A-Z]{16}/ ascii
    condition:
        $key
}

rule GitHub_Token {
    meta:
        description = "GitHub Personal Access Token"
        severity = 5
        category = "credential"
    strings:
        $ghp = /ghp_[a-zA-Z0-9]{36}/ ascii
        $gho = /gho_[a-zA-Z0-9]{36}/ ascii
        $ghs = /ghs_[a-zA-Z0-9]{36}/ ascii
    condition:
        any of them
}

rule Private_Key {
    meta:
        description = "Private key material"
        severity = 5
        category = "credential"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
        $ec = "-----BEGIN EC PRIVATE KEY-----" ascii
        $private = "-----BEGIN PRIVATE KEY-----" ascii
    condition:
        any of them
}

rule Jailbreak_Patterns {
    meta:
        description = "Common LLM jailbreak phrases"
        severity = 3
        category = "jailbreak"
    strings:
        $ignore = "ignore previous instructions" nocase ascii
        $dan = "you are now DAN" nocase ascii
        $developer = "developer mode enabled" nocase ascii
        $system = "system: you are" nocase ascii
    condition:
        any of them
}

rule LLM_Instruction_Markers {
    meta:
        description = "LLM instruction delimiters that shouldn't appear in user input"
        severity = 2
        category = "injection"
    strings:
        $inst = "[INST]" ascii
        $sys = "<<SYS>>" ascii
        $im_start = "<|im_start|>" ascii
        $im_end = "<|im_end|>" ascii
    condition:
        any of them
}
