import re
from typing import Any


_DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)


def validate_regex(domain: str) -> dict[str, Any]:
    """Validate an ASCII DNS hostname against RFC 1034/1123 hostname rules."""
    valid = isinstance(domain, str) and bool(_DOMAIN_PATTERN.fullmatch(domain))
    reason = None
    if not valid:
        reason = "Domain must be 1–253 characters with 1–63 character labels, valid hyphens, and an alphabetic TLD."
    return {"is_valid": valid, "error_reason": reason}


def validate_dfa(domain: str) -> dict[str, Any]:
    """Validate a domain using an explicit character-by-character DFA trace."""
    transitions: list[dict[str, str]] = []
    state = "START"
    error_index = None
    error_reason = None
    label_length = 0
    has_dot = False

    def move(char: str, next_state: str, index: int) -> None:
        nonlocal state, error_index, error_reason
        transitions.append(
            {"char": char, "from_state": state, "to_state": next_state}
        )
        state = next_state
        if next_state == "REJECT" and error_index is None:
            error_index = index

    if not isinstance(domain, str) or not domain:
        return {
            "is_valid": False,
            "transitions": [],
            "error_index": 0,
            "error_reason": "Domain must not be empty.",
        }
    for index, char in enumerate(domain):
        if char == ".":
            if state not in ("LABEL_START", "LABEL_BODY"):
                move(char, "REJECT", index)
                error_reason = "A label cannot be empty or end with a hyphen."
                break
            move(char, "DOT", index)
            label_length = 0
            has_dot = True
            if index == len(domain) - 1:
                move("", "REJECT", index)
                error_reason = "Domain cannot end with a dot."
                break
            continue

        if char == "-":
            if state in ("LABEL_START", "LABEL_BODY") and label_length < 63:
                move(char, "HYPHEN", index)
            elif state == "HYPHEN" and label_length < 63:
                move(char, "HYPHEN", index)
            else:
                move(char, "REJECT", index)
                error_reason = "Hyphens cannot begin a label or exceed the label limit."
                break
            label_length += 1
            continue

        if char.isascii() and char.isalnum():
            if label_length >= 63:
                move(char, "REJECT", index)
                error_reason = "A label cannot exceed 63 characters."
                break
            if state in ("START", "DOT"):
                move(char, "LABEL_START", index)
            elif state == "LABEL_START":
                move(char, "LABEL_BODY", index)
            elif state in ("LABEL_BODY", "HYPHEN"):
                move(char, "LABEL_BODY", index)
            else:
                move(char, "REJECT", index)
                error_reason = "Unexpected character in domain."
                break
            label_length += 1
            continue

        move(char, "REJECT", index)
        error_reason = "Only ASCII letters, digits, hyphens, and dots are allowed."
        break

    if state != "REJECT":
        labels = domain.split(".")
        if len(domain) > 253:
            move("", "REJECT", 253)
            error_reason = "Domain exceeds the 253-character maximum."
        elif not has_dot:
            move("", "REJECT", len(domain) - 1)
            error_reason = "Domain must contain a top-level domain."
        elif not labels[-1][0].isalpha():
            move("", "REJECT", len(domain) - 1)
            error_reason = "Top-level domain must start with an alphabetic character."
        elif state == "HYPHEN":
            move("", "REJECT", len(domain) - 1)
            error_reason = "A label cannot end with a hyphen."
        elif state in ("LABEL_START", "LABEL_BODY"):
            transitions.append(
                {"char": "", "from_state": state, "to_state": "ACCEPT"}
            )
            state = "ACCEPT"
        else:
            move("", "REJECT", len(domain) - 1)
            error_reason = "Domain must end with a complete label."

    return {
        "is_valid": state == "ACCEPT",
        "transitions": transitions,
        "error_index": error_index,
        "error_reason": error_reason,
    }
