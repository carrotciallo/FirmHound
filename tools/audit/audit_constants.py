"""Shared constants for static audit and the bounded agent loop."""

from __future__ import annotations

# Sink imports worth recovering an actual call site for (ARM32 disassembly).
CHAIN_SINKS = frozenset(
    {
        "doSystemCmd",
        "system",
        "popen",
        "execve",
        "sprintf",
        "vsprintf",
        "strcpy",
        "strncpy",
        "memcpy",
        "strcat",
        "snprintf",
    }
)

# API name -> verifier-recognised validation kind.
KIND_BY_API = {
    "strlen": "length_check",
    "strncmp": "whitelist",
    "strcmp": "whitelist",
    "atoi": "type_limit",
    "strtol": "type_limit",
    "strtoul": "type_limit",
    "strtok": "blacklist",
    "isalpha": "charset_check",
    "isdigit": "charset_check",
}
