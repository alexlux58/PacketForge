from __future__ import annotations

import shlex
from dataclasses import dataclass

APPROVED_COMMANDS = {
    "arp",
    "dig",
    "ifconfig",
    "ip",
    "netstat",
    "ping",
    "ping6",
    "route",
    "ss",
    "traceroute",
    "traceroute6",
}


@dataclass(frozen=True)
class CommandValidation:
    ok: bool
    message: str
    argv: list[str]


def validate_command(command: str) -> CommandValidation:
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        return CommandValidation(False, str(exc), [])
    if not argv:
        return CommandValidation(False, "Enter a command.", [])
    if argv[0] not in APPROVED_COMMANDS:
        return CommandValidation(False, f"'{argv[0]}' is not in the approved command list.", argv)
    dangerous_tokens = {";", "&&", "||", "|", ">", ">>", "<", "$(", "`"}
    if any(token in command for token in dangerous_tokens):
        return CommandValidation(
            False, "shell operators and command substitution are not allowed.", argv
        )
    return CommandValidation(True, "Command is approved.", argv)
